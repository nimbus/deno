// Copyright 2018-2026 the Deno authors. MIT license.

use std::borrow::Cow;
use std::cell::RefCell;
use std::rc::Rc;

use brotli::enc::StandardAlloc;
use brotli::enc::encode::BrotliEncoderDestroyInstance;
use brotli::enc::encode::BrotliEncoderOperation;
use brotli::enc::encode::BrotliEncoderParameter;
use brotli::enc::encode::BrotliEncoderStateStruct;
use brotli::ffi;
use deno_core::op2;
use deno_core::v8;
use deno_core::v8_static_strings;
use deno_error::JsErrorBox;
use libc::c_ulong;
use zlib::*;

mod alloc;
pub mod mode;
mod stream;

use mode::Flush;
use mode::Mode;

use self::alloc::brotli_alloc;
use self::alloc::brotli_free;
use self::stream::StreamWrapper;

#[inline]
fn check(condition: bool, msg: &str) -> Result<(), JsErrorBox> {
  if condition {
    Ok(())
  } else {
    Err(JsErrorBox::type_error(msg.to_string()))
  }
}

/// The caller of every `write`/`writeSync` op below controls the offsets and
/// lengths, so the window has to be checked against the real backing store
/// before anything indexes with it; it would otherwise panic and take the
/// process down. Go through these rather than open-coding the check, so a new
/// op cannot be written without one.
fn slice_input(input: &[u8], off: u32, len: u32) -> Result<&[u8], JsErrorBox> {
  (off as usize)
    .checked_add(len as usize)
    .and_then(|end| input.get(off as usize..end))
    .ok_or_else(|| JsErrorBox::type_error("invalid input range"))
}

fn slice_output(
  out: &mut [u8],
  off: u32,
  len: u32,
) -> Result<&mut [u8], JsErrorBox> {
  (off as usize)
    .checked_add(len as usize)
    .and_then(|end| out.get_mut(off as usize..end))
    .ok_or_else(|| JsErrorBox::type_error("invalid output range"))
}

/// Report an engine error to the handle's `onerror(message, errno, code)`,
/// the same arguments that Node's `CompressionStream::CheckError` passes.
fn call_onerror(
  scope: &mut v8::PinScope<'_, '_>,
  this: v8::Local<v8::Object>,
  message: &str,
  errno: i32,
  code: &str,
) {
  v8_static_strings! {
    ONERROR_STR = "onerror",
  }
  let onerror_str = ONERROR_STR.v8_string(scope).unwrap();
  let onerror = this.get(scope, onerror_str.into()).unwrap();
  let cb = v8::Local::<v8::Function>::try_from(onerror).unwrap();
  let message = v8::String::new(scope, message).unwrap();
  let errno = v8::Integer::new(scope, errno);
  let code = v8::String::new(scope, code).unwrap();
  cb.call(
    scope,
    this.into(),
    &[message.into(), errno.into(), code.into()],
  );
}

#[derive(Default)]
struct ZlibInner {
  dictionary: Option<Vec<u8>>,
  err: i32,
  flush: Flush,
  init_done: bool,
  level: i32,
  mem_level: i32,
  mode: Mode,
  strategy: i32,
  window_bits: i32,
  write_in_progress: bool,
  pending_close: bool,
  gzib_id_bytes_read: u32,
  /// When set, a gzip member boundary is not silently followed by the next
  /// member; the remaining input is left for the caller to reject as trailing
  /// junk.
  reject_garbage_after_end: bool,
  callback: Option<v8::Global<v8::Function>>,
  strm: StreamWrapper,
}

const GZIP_HEADER_ID1: u8 = 0x1f;
const GZIP_HEADER_ID2: u8 = 0x8b;

impl ZlibInner {
  #[allow(clippy::too_many_arguments, reason = "TODO: improve this")]
  fn start_write(
    &mut self,
    input: &[u8],
    in_off: u32,
    in_len: u32,
    out: &mut [u8],
    out_off: u32,
    out_len: u32,
    flush: Flush,
  ) -> Result<(), JsErrorBox> {
    check(self.init_done, "write before init")?;
    check(!self.write_in_progress, "write already in progress")?;
    check(!self.pending_close, "close already in progress")?;

    self.write_in_progress = true;

    let next_in = slice_input(input, in_off, in_len)?.as_ptr() as *mut _;
    let next_out = slice_output(out, out_off, out_len)?.as_mut_ptr();

    self.strm.avail_in = in_len;
    self.strm.next_in = next_in;
    self.strm.avail_out = out_len;
    self.strm.next_out = next_out;

    self.flush = flush;
    Ok(())
  }

  fn do_write(&mut self, flush: Flush) -> Result<(), JsErrorBox> {
    self.flush = flush;
    match self.mode {
      Mode::Deflate | Mode::Gzip | Mode::DeflateRaw => {
        self.err = self.strm.deflate(flush);
      }
      // Auto-detect mode.
      Mode::Unzip if self.strm.avail_in > 0 => 'blck: {
        let mut next_expected_header_byte = Some(0);
        // SAFETY: `self.strm.next_in` is valid pointer to the input buffer.
        // `self.strm.avail_in` is the length of the input buffer that is only set by
        // `start_write`.
        let strm = unsafe {
          std::slice::from_raw_parts(
            self.strm.next_in,
            self.strm.avail_in as usize,
          )
        };

        if self.gzib_id_bytes_read == 0 {
          if strm[0] == GZIP_HEADER_ID1 {
            self.gzib_id_bytes_read = 1;
            next_expected_header_byte = Some(1);

            // Not enough.
            if self.strm.avail_in == 1 {
              break 'blck;
            }
          } else {
            self.mode = Mode::Inflate;
            next_expected_header_byte = None;
          }
        }

        if self.gzib_id_bytes_read == 1 {
          let byte = match next_expected_header_byte {
            Some(i) => strm[i],
            None => break 'blck,
          };
          if byte == GZIP_HEADER_ID2 {
            self.gzib_id_bytes_read = 2;
            self.mode = Mode::Gunzip;
          } else {
            self.mode = Mode::Inflate;
          }
        } else if next_expected_header_byte.is_some() {
          return Err(JsErrorBox::type_error(
            "invalid number of gzip magic number bytes read",
          ));
        }
      }
      _ => {}
    }

    match self.mode {
      Mode::Inflate
        | Mode::Gunzip
        | Mode::InflateRaw
        // We're still reading the header.
        | Mode::Unzip => {
        self.err = self.strm.inflate(self.flush);
        // TODO(@littledivy): Use if let chain when it is stable.
        // https://github.com/rust-lang/rust/issues/53667
        //
        // Data was encoded with dictionary
        if let (Z_NEED_DICT, Some(dictionary)) = (self.err, &self.dictionary) {
          self.err = self.strm.inflate_set_dictionary(dictionary);

          if self.err == Z_OK {
            self.err = self.strm.inflate(flush);
          } else if self.err == Z_DATA_ERROR {
            self.err = Z_NEED_DICT;
          }
        }

        while !self.reject_garbage_after_end
          && self.strm.avail_in > 0
          && self.mode == Mode::Gunzip
          && self.err == Z_STREAM_END
          // SAFETY: `strm` is a valid pointer to zlib strm.
          // `strm.next_in` is initialized to the input buffer.
          && unsafe { *self.strm.next_in } != 0x00
        {
          self.err = self.strm.reset(self.mode);
          self.err = self.strm.inflate(flush);
        }
      }
      _ => {}
    }

    let done = self.strm.avail_out != 0 && self.flush == Flush::Finish;
    // We're are not done yet, but output buffer is full
    if self.err == Z_BUF_ERROR && !done {
      // Set to Z_OK to avoid reporting the error in JS.
      self.err = Z_OK;
    }

    self.write_in_progress = false;
    Ok(())
  }

  fn init_stream(&mut self) -> Result<(), JsErrorBox> {
    match self.mode {
      Mode::Gzip | Mode::Gunzip => self.window_bits += 16,
      Mode::Unzip => self.window_bits += 32,
      Mode::DeflateRaw | Mode::InflateRaw => self.window_bits *= -1,
      _ => {}
    }

    self.err = match self.mode {
      Mode::Deflate | Mode::Gzip | Mode::DeflateRaw => self.strm.deflate_init(
        self.level,
        self.window_bits,
        self.mem_level,
        self.strategy,
      ),
      Mode::Inflate | Mode::Gunzip | Mode::InflateRaw | Mode::Unzip => {
        self.strm.inflate_init(self.window_bits)
      }
      Mode::None => return Err(JsErrorBox::type_error("Unknown mode")),
    };

    self.write_in_progress = false;
    self.init_done = true;

    Ok(())
  }

  fn close(&mut self) -> Result<bool, JsErrorBox> {
    if self.write_in_progress {
      self.pending_close = true;
      return Ok(false);
    }

    self.pending_close = false;
    check(self.init_done, "close before init")?;

    self.strm.end(self.mode);
    self.mode = Mode::None;
    Ok(true)
  }

  fn reset_stream(&mut self) {
    self.err = self.strm.reset(self.mode);
  }

  fn get_error_info(&self) -> Option<(i32, String)> {
    let err_str = match self.err {
      Z_OK | Z_BUF_ERROR => {
        if self.strm.avail_out != 0 && self.flush == Flush::Finish {
          "unexpected end of file"
        } else {
          return None;
        }
      }
      Z_STREAM_END => return None,
      Z_NEED_DICT => {
        if self.dictionary.is_none() {
          "Missing dictionary"
        } else {
          "Bad dictionary"
        }
      }
      _ => "Zlib error",
    };

    let msg = self.strm.msg;
    Some((
      self.err,
      if !msg.is_null() {
        // SAFETY: `msg` is a valid pointer to a null-terminated string.
        unsafe { std::ffi::CStr::from_ptr(msg).to_str().unwrap().to_string() }
      } else {
        err_str.to_string()
      },
    ))
  }

  fn check_error(
    error_info: Option<(i32, String)>,
    scope: &mut v8::PinScope<'_, '_>,
    this: &v8::Global<v8::Object>,
  ) -> bool {
    let Some((err, msg)) = error_info else {
      return true; // No error, nothing to report.
    };

    let this = v8::Local::new(scope, this);
    call_onerror(scope, this, &msg, err, zlib_error_code_name(err));

    false
  }
}

/// The error code name that Node's `ZlibStrerror` gives for a zlib error.
fn zlib_error_code_name(err: i32) -> &'static str {
  match err {
    Z_OK => "Z_OK",
    Z_STREAM_END => "Z_STREAM_END",
    Z_NEED_DICT => "Z_NEED_DICT",
    Z_ERRNO => "Z_ERRNO",
    Z_STREAM_ERROR => "Z_STREAM_ERROR",
    Z_DATA_ERROR => "Z_DATA_ERROR",
    Z_MEM_ERROR => "Z_MEM_ERROR",
    Z_BUF_ERROR => "Z_BUF_ERROR",
    Z_VERSION_ERROR => "Z_VERSION_ERROR",
    _ => "Z_UNKNOWN_ERROR",
  }
}

/// The name that Node's `BrotliDecoderErrorString` gives for a Brotli decoder
/// error code. The `brotli-decompressor` crate drops the leading `_` that the
/// C library keeps (and misspells `CL_SPACE`), so mirror the C list that Node
/// vendors in deps/brotli/c/include/brotli/decode.h.
fn brotli_decoder_error_name(code: i32) -> &'static str {
  match code {
    0 => "_NO_ERROR",
    1 => "_SUCCESS",
    2 => "_NEEDS_MORE_INPUT",
    3 => "_NEEDS_MORE_OUTPUT",
    -1 => "_ERROR_FORMAT_EXUBERANT_NIBBLE",
    -2 => "_ERROR_FORMAT_RESERVED",
    -3 => "_ERROR_FORMAT_EXUBERANT_META_NIBBLE",
    -4 => "_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET",
    -5 => "_ERROR_FORMAT_SIMPLE_HUFFMAN_SAME",
    -6 => "_ERROR_FORMAT_CL_SPACE",
    -7 => "_ERROR_FORMAT_HUFFMAN_SPACE",
    -8 => "_ERROR_FORMAT_CONTEXT_MAP_REPEAT",
    -9 => "_ERROR_FORMAT_BLOCK_LENGTH_1",
    -10 => "_ERROR_FORMAT_BLOCK_LENGTH_2",
    -11 => "_ERROR_FORMAT_TRANSFORM",
    -12 => "_ERROR_FORMAT_DICTIONARY",
    -13 => "_ERROR_FORMAT_WINDOW_BITS",
    -14 => "_ERROR_FORMAT_PADDING_1",
    -15 => "_ERROR_FORMAT_PADDING_2",
    -16 => "_ERROR_FORMAT_DISTANCE",
    -18 => "_ERROR_COMPOUND_DICTIONARY",
    -19 => "_ERROR_DICTIONARY_NOT_SET",
    -20 => "_ERROR_INVALID_ARGUMENTS",
    -21 => "_ERROR_ALLOC_CONTEXT_MODES",
    -22 => "_ERROR_ALLOC_TREE_GROUPS",
    -25 => "_ERROR_ALLOC_CONTEXT_MAP",
    -26 => "_ERROR_ALLOC_RING_BUFFER_1",
    -27 => "_ERROR_ALLOC_RING_BUFFER_2",
    -30 => "_ERROR_ALLOC_BLOCK_TYPE_TREES",
    -31 => "_ERROR_UNREACHABLE",
    _ => "INVALID",
  }
}

pub struct Zlib {
  inner: RefCell<Option<ZlibInner>>,
}

// SAFETY: we're sure this can be GCed
unsafe impl deno_core::GarbageCollected for Zlib {
  fn trace(&self, _visitor: &mut deno_core::v8::cppgc::Visitor) {}

  fn get_name(&self) -> &'static std::ffi::CStr {
    c"Zlib"
  }
}

impl deno_core::Resource for Zlib {
  fn name(&self) -> Cow<'_, str> {
    "zlib".into()
  }
}

#[op2]
impl Zlib {
  #[constructor]
  #[cppgc]
  fn new(#[smi] mode: Option<i32>) -> Result<Zlib, mode::ModeError> {
    let mode = mode.unwrap_or(Mode::Deflate as i32);
    let mode = Mode::try_from(mode)?;

    let inner = ZlibInner {
      mode,
      ..Default::default()
    };

    Ok(Zlib {
      inner: RefCell::new(Some(inner)),
    })
  }

  #[fast]
  pub fn close(&self) -> Result<(), ZlibError> {
    let mut resource = self.inner.borrow_mut();
    let zlib = resource.as_mut().ok_or(ZlibError::NotInitialized)?;

    // If there is a pending write, defer the close until the write is done.
    zlib.close()?;

    Ok(())
  }

  #[fast]
  pub fn set_reject_garbage_after_end(
    &self,
    value: bool,
  ) -> Result<(), ZlibError> {
    let mut zlib = self.inner.borrow_mut();
    let zlib = zlib.as_mut().ok_or(ZlibError::NotInitialized)?;

    zlib.reject_garbage_after_end = value;

    Ok(())
  }

  #[fast]
  #[smi]
  pub fn reset(&self) -> Result<i32, ZlibError> {
    let mut zlib = self.inner.borrow_mut();
    let zlib = zlib.as_mut().ok_or(ZlibError::NotInitialized)?;

    zlib.reset_stream();

    Ok(zlib.err)
  }

  #[fast]
  pub fn params(
    &self,
    #[smi] level: i32,
    #[smi] strategy: i32,
  ) -> Result<(), ZlibError> {
    let mut zlib = self.inner.borrow_mut();
    let zlib = zlib.as_mut().ok_or(ZlibError::NotInitialized)?;

    zlib.err = zlib.strm.deflate_params(level, strategy);
    zlib.level = level;
    zlib.strategy = strategy;

    Ok(())
  }

  #[smi]
  pub fn init(
    &self,
    #[smi] window_bits: i32,
    #[smi] level: i32,
    #[smi] mem_level: i32,
    #[smi] strategy: i32,
    #[scoped] callback: v8::Global<v8::Function>,
    #[buffer] dictionary: Option<&[u8]>,
  ) -> Result<i32, ZlibError> {
    let mut zlib = self.inner.borrow_mut();
    let zlib = zlib.as_mut().ok_or(ZlibError::NotInitialized)?;

    if !((window_bits == 0)
      && matches!(zlib.mode, Mode::Inflate | Mode::Gunzip | Mode::Unzip))
    {
      check((8..=15).contains(&window_bits), "invalid windowBits")?;
    }

    check((-1..=9).contains(&level), "invalid level")?;

    check((1..=9).contains(&mem_level), "invalid memLevel")?;

    check(
      strategy == Z_DEFAULT_STRATEGY
        || strategy == Z_FILTERED
        || strategy == Z_HUFFMAN_ONLY
        || strategy == Z_RLE
        || strategy == Z_FIXED,
      "invalid strategy",
    )?;

    zlib.level = level;
    zlib.window_bits = window_bits;
    zlib.mem_level = mem_level;
    zlib.strategy = strategy;

    zlib.flush = Flush::None;
    zlib.err = Z_OK;

    zlib.init_stream()?;

    zlib.dictionary = dictionary.map(|buf| buf.to_vec());

    zlib.callback = Some(callback);

    Ok(zlib.err)
  }

  #[fast]
  #[reentrant]
  pub fn write_sync(
    &self,
    #[this] this: v8::Global<v8::Object>,
    scope: &mut v8::PinScope<'_, '_>,
    #[smi] flush: i32,
    #[buffer] input: &[u8],
    #[smi] in_off: u32,
    #[smi] in_len: u32,
    #[buffer] out: &mut [u8],
    #[smi] out_off: u32,
    #[smi] out_len: u32,
    #[buffer] write_result: &mut [u32],
  ) -> Result<(), ZlibError> {
    let err_info = {
      let mut zlib = self.inner.borrow_mut();
      let zlib = zlib.as_mut().ok_or(ZlibError::NotInitialized)?;

      let flush = Flush::try_from(flush)?;
      zlib.start_write(input, in_off, in_len, out, out_off, out_len, flush)?;
      zlib.do_write(flush)?;

      if write_result.len() >= 2 {
        write_result[0] = zlib.strm.avail_out;
        write_result[1] = zlib.strm.avail_in;
      }
      zlib.get_error_info()
    };

    ZlibInner::check_error(err_info, scope, &this);
    Ok(())
  }

  #[fast]
  #[reentrant]
  fn write(
    &self,
    #[this] this: v8::Global<v8::Object>,
    scope: &mut v8::PinScope<'_, '_>,
    #[smi] flush: i32,
    #[buffer] input: &[u8],
    #[smi] in_off: u32,
    #[smi] in_len: u32,
    #[buffer] out: &mut [u8],
    #[smi] out_off: u32,
    #[smi] out_len: u32,
    #[buffer] write_result: &mut [u32],
  ) -> Result<(), ZlibError> {
    let err_info = {
      let mut zlib = self.inner.borrow_mut();
      let zlib = zlib.as_mut().ok_or(ZlibError::NotInitialized)?;

      let flush = Flush::try_from(flush)?;
      zlib.start_write(input, in_off, in_len, out, out_off, out_len, flush)?;
      zlib.do_write(flush)?;

      if write_result.len() >= 2 {
        write_result[0] = zlib.strm.avail_out;
        write_result[1] = zlib.strm.avail_in;
      }
      zlib.get_error_info()
    };

    // Report errors via onerror callback (which defers destroy via
    // process.nextTick). The processCallback is NOT called here — it is
    // scheduled asynchronously from JavaScript to match Node.js behavior
    // where compression runs on the libuv threadpool.
    ZlibInner::check_error(err_info, scope, &this);

    Ok(())
  }
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum ZlibError {
  #[class(type)]
  #[error("zlib not initialized")]
  NotInitialized,
  #[class(inherit)]
  #[error(transparent)]
  Mode(
    #[from]
    #[inherit]
    mode::ModeError,
  ),
  #[class(inherit)]
  #[error(transparent)]
  Other(
    #[from]
    #[inherit]
    JsErrorBox,
  ),
}

#[op2]
#[string]
pub fn op_zlib_err_msg(
  #[cppgc] resource: &Zlib,
) -> Result<Option<String>, ZlibError> {
  let mut zlib = resource.inner.borrow_mut();
  let zlib = zlib.as_mut().ok_or(ZlibError::NotInitialized)?;

  let msg = zlib.strm.msg;
  if msg.is_null() {
    return Ok(None);
  }

  // SAFETY: `msg` is a valid pointer to a null-terminated string.
  let msg = unsafe {
    std::ffi::CStr::from_ptr(msg)
      .to_str()
      .map_err(|_| JsErrorBox::type_error("invalid error message"))?
      .to_string()
  };

  Ok(Some(msg))
}

#[op2(fast)]
pub fn op_zlib_close_if_pending(
  #[cppgc] resource: &Zlib,
) -> Result<(), ZlibError> {
  let pending_close = {
    let mut zlib = resource.inner.borrow_mut();
    let zlib = zlib.as_mut().ok_or(ZlibError::NotInitialized)?;

    zlib.write_in_progress = false;
    zlib.pending_close
  };
  if pending_close && let Some(mut res) = resource.inner.borrow_mut().take() {
    let _ = res.close();
  }

  Ok(())
}

struct BrotliEncoderCtx {
  inst: BrotliEncoderStateStruct<StandardAlloc>,
  callback: v8::Global<v8::Function>,
}

pub struct BrotliEncoder {
  ctx: Rc<RefCell<Option<BrotliEncoderCtx>>>,
}

// SAFETY: we're sure this can be GCed
unsafe impl deno_core::GarbageCollected for BrotliEncoder {
  fn trace(&self, _visitor: &mut deno_core::v8::cppgc::Visitor) {}

  fn get_name(&self) -> &'static std::ffi::CStr {
    c"BrotliEncoder"
  }
}

fn encoder_param(i: usize) -> Option<BrotliEncoderParameter> {
  use BrotliEncoderParameter::*;

  Some(match i {
    0 => BROTLI_PARAM_MODE,
    1 => BROTLI_PARAM_QUALITY,
    2 => BROTLI_PARAM_LGWIN,
    3 => BROTLI_PARAM_LGBLOCK,
    4 => BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING,
    5 => BROTLI_PARAM_SIZE_HINT,
    6 => BROTLI_PARAM_LARGE_WINDOW,
    150 => BROTLI_PARAM_Q9_5,
    151 => BROTLI_METABLOCK_CALLBACK,
    152 => BROTLI_PARAM_STRIDE_DETECTION_QUALITY,
    153 => BROTLI_PARAM_HIGH_ENTROPY_DETECTION_QUALITY,
    154 => BROTLI_PARAM_LITERAL_BYTE_SCORE,
    155 => BROTLI_PARAM_CDF_ADAPTATION_DETECTION,
    156 => BROTLI_PARAM_PRIOR_BITMASK_DETECTION,
    157 => BROTLI_PARAM_SPEED,
    158 => BROTLI_PARAM_SPEED_MAX,
    159 => BROTLI_PARAM_CM_SPEED,
    160 => BROTLI_PARAM_CM_SPEED_MAX,
    161 => BROTLI_PARAM_SPEED_LOW,
    162 => BROTLI_PARAM_SPEED_LOW_MAX,
    164 => BROTLI_PARAM_CM_SPEED_LOW,
    165 => BROTLI_PARAM_CM_SPEED_LOW_MAX,
    166 => BROTLI_PARAM_AVOID_DISTANCE_PREFIX_SEARCH,
    167 => BROTLI_PARAM_CATABLE,
    168 => BROTLI_PARAM_APPENDABLE,
    169 => BROTLI_PARAM_MAGIC_NUMBER,
    171 => BROTLI_PARAM_FAVOR_EFFICIENCY,
    _ => return None,
  })
}

fn encoder_operation(i: u8) -> Result<BrotliEncoderOperation, JsErrorBox> {
  match i {
    0 => Ok(BrotliEncoderOperation::BROTLI_OPERATION_PROCESS),
    1 => Ok(BrotliEncoderOperation::BROTLI_OPERATION_FLUSH),
    2 => Ok(BrotliEncoderOperation::BROTLI_OPERATION_FINISH),
    3 => Ok(BrotliEncoderOperation::BROTLI_OPERATION_EMIT_METADATA),
    _ => Err(JsErrorBox::type_error("invalid Brotli operation")),
  }
}

#[op2]
impl BrotliEncoder {
  #[constructor]
  #[cppgc]
  fn new(#[smi] _mode: i32) -> BrotliEncoder {
    BrotliEncoder {
      ctx: Rc::new(RefCell::new(None)),
    }
  }

  fn init(
    &self,
    #[buffer] params: &[u32],
    #[scoped] callback: v8::Global<v8::Function>,
  ) -> bool {
    if params.len() > usize::from(u8::MAX) + 1 {
      return false;
    }

    let inst = {
      let mut state = BrotliEncoderStateStruct::new(StandardAlloc::default());

      for (i, &value) in params.iter().enumerate() {
        if value == 0xFFFFFFFF {
          continue; // Skip setting the parameter, same as C API.
        }
        let Some(parameter) = encoder_param(i) else {
          return false;
        };
        if !state.set_parameter(parameter, value) {
          return false;
        }
      }

      state
    };

    self
      .ctx
      .borrow_mut()
      .replace(BrotliEncoderCtx { inst, callback });
    true
  }

  #[fast]
  fn params(&self) {
    // no-op
  }

  #[fast]
  fn reset(&self) {}

  #[fast]
  #[reentrant]
  pub fn write(
    &self,
    #[this] this: v8::Global<v8::Object>,
    scope: &mut v8::PinScope<'_, '_>,
    #[smi] flush: u8,
    #[buffer] input: &[u8],
    #[smi] in_off: u32,
    #[smi] in_len: u32,
    #[buffer] out: &mut [u8],
    #[smi] out_off: u32,
    #[smi] out_len: u32,
    #[buffer] write_result: &mut [u32],
  ) -> Result<(), JsErrorBox> {
    let operation = encoder_operation(flush)?;
    let input_slice = slice_input(input, in_off, in_len)?;
    let output_slice = slice_output(out, out_off, out_len)?;

    let mut avail_in = in_len as usize;
    let mut avail_out = out_len as usize;
    let callback = {
      let mut ctx = self.ctx.borrow_mut();
      let ctx = ctx.as_mut().expect("BrotliEncoder not initialized");

      ctx.inst.compress_stream(
        operation,
        &mut avail_in,
        input_slice,
        &mut 0,
        &mut avail_out,
        output_slice,
        &mut 0,
        &mut None,
        &mut |_, _, _, _| (),
      );

      if write_result.len() >= 2 {
        write_result[0] = avail_out as u32;
        write_result[1] = avail_in as u32;
      }

      v8::Local::new(scope, &ctx.callback)
    };
    let this = v8::Local::new(scope, &this);
    let _ = callback.call(scope, this.into(), &[]);

    Ok(())
  }

  #[fast]
  pub fn write_sync(
    &self,
    #[smi] flush: u8,
    #[buffer] input: &[u8],
    #[smi] in_off: u32,
    #[smi] in_len: u32,
    #[buffer] out: &mut [u8],
    #[smi] out_off: u32,
    #[smi] out_len: u32,
    #[buffer] write_result: &mut [u32],
  ) -> Result<(), JsErrorBox> {
    let operation = encoder_operation(flush)?;
    let input_slice = slice_input(input, in_off, in_len)?;
    let output_slice = slice_output(out, out_off, out_len)?;

    let mut ctx = self.ctx.borrow_mut();
    let ctx = ctx.as_mut().expect("BrotliEncoder not initialized");

    let mut avail_in = in_len as usize;
    let mut avail_out = out_len as usize;
    ctx.inst.compress_stream(
      operation,
      &mut avail_in,
      input_slice,
      &mut 0,
      &mut avail_out,
      output_slice,
      &mut 0,
      &mut None,
      &mut |_, _, _, _| (),
    );

    if write_result.len() >= 2 {
      write_result[0] = avail_out as u32;
      write_result[1] = avail_in as u32;
    }

    Ok(())
  }

  #[fast]
  fn close(&self) {
    let mut ctx = self.ctx.borrow_mut();
    if let Some(mut ctx) = ctx.take() {
      BrotliEncoderDestroyInstance(&mut ctx.inst);
    }
  }
}

struct BrotliDecoderCtx {
  inst: *mut ffi::decompressor::ffi::BrotliDecoderState,
  callback: v8::Global<v8::Function>,
}

pub struct BrotliDecoder {
  ctx: Rc<RefCell<Option<BrotliDecoderCtx>>>,
}

// SAFETY: we're sure this can be GCed
unsafe impl deno_core::GarbageCollected for BrotliDecoder {
  fn trace(&self, _visitor: &mut deno_core::v8::cppgc::Visitor) {}

  fn get_name(&self) -> &'static std::ffi::CStr {
    c"BrotliDecoder"
  }
}

fn decoder_param(
  i: u32,
) -> Option<ffi::decompressor::ffi::interface::BrotliDecoderParameter> {
  const _: () = {
    assert!(
      std::mem::size_of::<
        ffi::decompressor::ffi::interface::BrotliDecoderParameter,
      >()
        == std::mem::size_of::<u32>(),
    );
  };
  match i {
    0 => Some(ffi::decompressor::ffi::interface::BrotliDecoderParameter::BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION),
    1 => Some(ffi::decompressor::ffi::interface::BrotliDecoderParameter::BROTLI_DECODER_PARAM_LARGE_WINDOW),
    _ => None
  }
}

#[op2]
impl BrotliDecoder {
  #[constructor]
  #[cppgc]
  fn new(#[smi] _mode: i32) -> BrotliDecoder {
    BrotliDecoder {
      ctx: Rc::new(RefCell::new(None)),
    }
  }

  fn init(
    &self,
    #[buffer] params: &[u32],
    #[scoped] callback: v8::Global<v8::Function>,
  ) -> bool {
    // SAFETY: creates new brotli decoder instance. `params` is a valid slice of u32 values.
    let inst = unsafe {
      let state = ffi::decompressor::ffi::BrotliDecoderCreateInstance(
        Some(brotli_alloc),
        Some(brotli_free),
        std::ptr::null_mut(),
      );
      for (i, &value) in params.iter().enumerate() {
        if let Some(param) = decoder_param(i as u32) {
          ffi::decompressor::ffi::BrotliDecoderSetParameter(
            state, param, value,
          );
        }
      }

      state
    };

    self
      .ctx
      .borrow_mut()
      .replace(BrotliDecoderCtx { inst, callback });
    true
  }

  #[fast]
  fn params(&self) {
    // no-op
  }

  #[fast]
  fn reset(&self) {}

  #[fast]
  #[reentrant]
  pub fn write(
    &self,
    #[this] this: v8::Global<v8::Object>,
    scope: &mut v8::PinScope<'_, '_>,
    #[smi] _flush: i32,
    #[buffer] input: &[u8],
    #[smi] in_off: u32,
    #[smi] in_len: u32,
    #[buffer] out: &mut [u8],
    #[smi] out_off: u32,
    #[smi] out_len: u32,
    #[buffer] write_result: &mut [u32],
  ) -> Result<(), JsErrorBox> {
    let (error_info, callback) = {
      let ctx = self.ctx.borrow();
      let ctx = ctx.as_ref().expect("BrotliDecoder not initialized");

      let mut next_in = slice_input(input, in_off, in_len)?.as_ptr();
      let mut next_out = slice_output(out, out_off, out_len)?.as_mut_ptr();

      let mut avail_in = in_len as usize;
      let mut avail_out = out_len as usize;

      // SAFETY: `inst`, `next_in`, `next_out`, `avail_in`, and `avail_out` are valid pointers.
      let error_info = unsafe {
        let res = ffi::decompressor::ffi::BrotliDecoderDecompressStream(
          ctx.inst,
          &mut avail_in,
          &mut next_in,
          &mut avail_out,
          &mut next_out,
          std::ptr::null_mut(),
        );

        if write_result.len() >= 2 {
          write_result[0] = avail_out as u32;
          write_result[1] = avail_in as u32;
        }

        if matches!(
          res,
          ffi::decompressor::ffi::interface::BrotliDecoderResult::BROTLI_DECODER_RESULT_ERROR
        ) {
          let error_code =
            ffi::decompressor::ffi::BrotliDecoderGetErrorCode(ctx.inst) as i32;
          // Match Node: a fixed message, and the decoder error name as the
          // code (e.g. `ERR__ERROR_FORMAT_PADDING_2`).
          let code =
            format!("ERR_{}", brotli_decoder_error_name(error_code));
          Some((error_code, code))
        } else {
          None
        }
      };

      (error_info, v8::Local::new(scope, &ctx.callback))
    };

    let this = v8::Local::new(scope, &this);

    if let Some((err, code)) = error_info {
      call_onerror(scope, this, "Decompression failed", err, &code);
    } else {
      let _ = callback.call(scope, this.into(), &[]);
    }

    Ok(())
  }

  #[fast]
  pub fn write_sync(
    &self,
    #[smi] _flush: i32,
    #[buffer] input: &[u8],
    #[smi] in_off: u32,
    #[smi] in_len: u32,
    #[buffer] out: &mut [u8],
    #[smi] out_off: u32,
    #[smi] out_len: u32,
    #[buffer] write_result: &mut [u32],
  ) -> Result<(), JsErrorBox> {
    let mut ctx = self.ctx.borrow_mut();
    let ctx = ctx.as_mut().expect("BrotliDecoder not initialized");

    let mut next_in = slice_input(input, in_off, in_len)?.as_ptr();
    let mut next_out = slice_output(out, out_off, out_len)?.as_mut_ptr();

    let mut avail_in = in_len as usize;
    let mut avail_out = out_len as usize;

    // SAFETY: `ctx.inst` is a valid pointer to a BrotliDecoderState.
    unsafe {
      ffi::decompressor::ffi::BrotliDecoderDecompressStream(
        ctx.inst,
        &mut avail_in,
        &mut next_in,
        &mut avail_out,
        &mut next_out,
        std::ptr::null_mut(),
      );
    }

    if write_result.len() >= 2 {
      write_result[0] = avail_out as u32;
      write_result[1] = avail_in as u32;
    }

    Ok(())
  }

  #[fast]
  fn close(&self) {
    let mut ctx = self.ctx.borrow_mut();
    if let Some(ctx) = ctx.take() {
      // SAFETY: `ctx.inst` is a valid pointer to a BrotliDecoderState.
      unsafe {
        ffi::decompressor::ffi::BrotliDecoderDestroyInstance(ctx.inst);
      }
    }
  }
}

// Zstd Compression/Decompression support
use zstd::stream::raw::Encoder as ZstdRawEncoder;
use zstd::stream::raw::Operation; // Trait for run/flush/finish methods

struct ZstdCompressCtx {
  encoder: ZstdRawEncoder<'static>,
  pledged_src_size: Option<u64>,
  callback: v8::Global<v8::Function>,
}

pub struct ZstdCompress {
  ctx: Rc<RefCell<Option<ZstdCompressCtx>>>,
}

// SAFETY: we're sure this can be GCed
unsafe impl deno_core::GarbageCollected for ZstdCompress {
  fn trace(&self, _visitor: &mut deno_core::v8::cppgc::Visitor) {}

  fn get_name(&self) -> &'static std::ffi::CStr {
    c"ZstdCompress"
  }
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
enum PledgedSrcSizeError {
  #[class(type)]
  #[property("code" = "ERR_INVALID_ARG_TYPE")]
  #[error("pledgedSrcSize must be a number")]
  NotANumber,
  #[class(range)]
  #[property("code" = "ERR_OUT_OF_RANGE")]
  #[error("pledgedSrcSize must be a safe integer")]
  NotSafeInteger,
  #[class(range)]
  #[property("code" = "ERR_OUT_OF_RANGE")]
  #[error("pledgedSrcSize must be non-negative")]
  Negative,
}

/// Validate `pledgedSrcSize` as Node's `ZstdStream::Init` does: `undefined`
/// leaves it unset, and any other value must be a non-negative safe integer.
fn parse_pledged_src_size(
  value: v8::Local<v8::Value>,
) -> Result<Option<u64>, PledgedSrcSizeError> {
  if value.is_undefined() {
    return Ok(None);
  }
  let Ok(number) = v8::Local::<v8::Number>::try_from(value) else {
    return Err(PledgedSrcSizeError::NotANumber);
  };
  let value = number.value();
  const MAX_SAFE_INTEGER: f64 = 9007199254740991.0;
  if !value.is_finite()
    || value.trunc() != value
    || value.abs() > MAX_SAFE_INTEGER
  {
    return Err(PledgedSrcSizeError::NotSafeInteger);
  }
  if value < 0.0 {
    return Err(PledgedSrcSizeError::Negative);
  }
  Ok(Some(value as u64))
}

#[op2]
impl ZstdCompress {
  #[constructor]
  #[cppgc]
  fn new(#[smi] _mode: i32) -> ZstdCompress {
    ZstdCompress {
      ctx: Rc::new(RefCell::new(None)),
    }
  }

  fn init(
    &self,
    #[buffer] params: &[u32],
    #[scoped] callback: v8::Global<v8::Function>,
    pledged_src_size: v8::Local<v8::Value>,
    #[buffer] dictionary: Option<&[u8]>,
  ) -> Result<bool, JsErrorBox> {
    let pledged_src_size =
      parse_pledged_src_size(pledged_src_size).map_err(JsErrorBox::from_err)?;

    // Default compression level is 3
    let mut encoder = match dictionary {
      Some(dictionary) if !dictionary.is_empty() => {
        ZstdRawEncoder::with_dictionary(3, dictionary)
          .map_err(|_| JsErrorBox::from_err(ZstdDictionaryLoadError))?
      }
      _ => {
        let Ok(encoder) = ZstdRawEncoder::new(3) else {
          return Ok(false);
        };
        encoder
      }
    };

    if pledged_src_size.is_some()
      && encoder.set_pledged_src_size(pledged_src_size).is_err()
    {
      return Ok(false);
    }

    // Apply compression parameters
    for (i, &value) in params.iter().enumerate() {
      if value == 0xFFFFFFFF {
        continue; // Skip unset parameters
      }
      // Map parameter index to zstd parameter
      // ZSTD_c_compressionLevel = 100, ZSTD_c_windowLog = 101, etc.
      use zstd::zstd_safe::CParameter;
      use zstd::zstd_safe::Strategy;
      let param = match i {
        100 => CParameter::CompressionLevel(value as i32),
        101 => CParameter::WindowLog(value),
        102 => CParameter::HashLog(value),
        103 => CParameter::ChainLog(value),
        104 => CParameter::SearchLog(value),
        105 => CParameter::MinMatch(value),
        106 => CParameter::TargetLength(value),
        107 => {
          // Strategy: 1=fast, 2=dfast, 3=greedy, 4=lazy, 5=lazy2, 6=btlazy2, 7=btopt, 8=btultra, 9=btultra2
          let strategy = match value {
            1 => Strategy::ZSTD_fast,
            2 => Strategy::ZSTD_dfast,
            3 => Strategy::ZSTD_greedy,
            4 => Strategy::ZSTD_lazy,
            5 => Strategy::ZSTD_lazy2,
            6 => Strategy::ZSTD_btlazy2,
            7 => Strategy::ZSTD_btopt,
            8 => Strategy::ZSTD_btultra,
            9 => Strategy::ZSTD_btultra2,
            _ => return Ok(false), // Invalid strategy value
          };
          CParameter::Strategy(strategy)
        }
        160 => CParameter::EnableLongDistanceMatching(value != 0),
        161 => CParameter::LdmHashLog(value),
        162 => CParameter::LdmMinMatch(value),
        163 => CParameter::LdmBucketSizeLog(value),
        164 => CParameter::LdmHashRateLog(value),
        200 => CParameter::ContentSizeFlag(value != 0),
        201 => CParameter::ChecksumFlag(value != 0),
        202 => CParameter::DictIdFlag(value != 0),
        240 => CParameter::NbWorkers(value),
        241 => CParameter::JobSize(value),
        242 => CParameter::OverlapSizeLog(value),
        _ => continue, // Skip unknown parameters
      };
      if encoder.set_parameter(param).is_err() {
        return Ok(false);
      }
    }

    self.ctx.borrow_mut().replace(ZstdCompressCtx {
      encoder,
      pledged_src_size,
      callback,
    });
    Ok(true)
  }

  #[fast]
  fn params(&self) {
    // no-op
  }

  #[fast]
  fn reset(&self) {
    let mut ctx = self.ctx.borrow_mut();
    if let Some(ctx) = ctx.as_mut() {
      // A session reset keeps the dictionary and parameters but drops the
      // pledged source size, so set it again as Node does.
      let _ = ctx.encoder.reinit();
      let _ = ctx.encoder.set_pledged_src_size(ctx.pledged_src_size);
    }
  }

  #[fast]
  #[reentrant]
  pub fn write(
    &self,
    #[this] this: v8::Global<v8::Object>,
    scope: &mut v8::PinScope<'_, '_>,
    #[smi] flush: u8,
    #[buffer] input: &[u8],
    #[smi] in_off: u32,
    #[smi] in_len: u32,
    #[buffer] out: &mut [u8],
    #[smi] out_off: u32,
    #[smi] out_len: u32,
    #[buffer] write_result: &mut [u32],
  ) -> Result<(), JsErrorBox> {
    use zstd::stream::raw::InBuffer;
    use zstd::stream::raw::OutBuffer;

    let callback = {
      let mut ctx = self.ctx.borrow_mut();
      let ctx = ctx.as_mut().expect("ZstdCompress not initialized");

      let input_slice = slice_input(input, in_off, in_len)?;
      let output_slice = slice_output(out, out_off, out_len)?;

      let mut in_buffer = InBuffer::around(input_slice);
      let mut out_buffer = OutBuffer::around(output_slice);

      // Call the appropriate method based on flush mode
      // 0 = ZSTD_e_continue, 1 = ZSTD_e_flush, 2 = ZSTD_e_end
      match flush {
        0 => {
          ctx
            .encoder
            .run(&mut in_buffer, &mut out_buffer)
            .map_err(|e| {
              JsErrorBox::generic(format!("Zstd compress error: {}", e))
            })?;
        }
        1 => {
          ctx
            .encoder
            .run(&mut in_buffer, &mut out_buffer)
            .map_err(|e| {
              JsErrorBox::generic(format!("Zstd compress error: {}", e))
            })?;
          ctx.encoder.flush(&mut out_buffer).map_err(|e| {
            JsErrorBox::generic(format!("Zstd flush error: {}", e))
          })?;
        }
        2 => {
          ctx
            .encoder
            .run(&mut in_buffer, &mut out_buffer)
            .map_err(|e| {
              JsErrorBox::generic(format!("Zstd compress error: {}", e))
            })?;
          ctx.encoder.finish(&mut out_buffer, true).map_err(|e| {
            JsErrorBox::generic(format!("Zstd finish error: {}", e))
          })?;
        }
        _ => {
          ctx
            .encoder
            .run(&mut in_buffer, &mut out_buffer)
            .map_err(|e| {
              JsErrorBox::generic(format!("Zstd compress error: {}", e))
            })?;
        }
      }

      let avail_in = in_len as usize - in_buffer.pos();
      let avail_out = out_len as usize - out_buffer.pos();

      if write_result.len() >= 2 {
        write_result[0] = avail_out as u32;
        write_result[1] = avail_in as u32;
      }

      v8::Local::new(scope, &ctx.callback)
    };

    let this = v8::Local::new(scope, &this);
    let _ = callback.call(scope, this.into(), &[]);

    Ok(())
  }

  #[fast]
  pub fn write_sync(
    &self,
    #[smi] flush: u8,
    #[buffer] input: &[u8],
    #[smi] in_off: u32,
    #[smi] in_len: u32,
    #[buffer] out: &mut [u8],
    #[smi] out_off: u32,
    #[smi] out_len: u32,
    #[buffer] write_result: &mut [u32],
  ) -> Result<(), JsErrorBox> {
    use zstd::stream::raw::InBuffer;
    use zstd::stream::raw::OutBuffer;

    let mut ctx = self.ctx.borrow_mut();
    let ctx = ctx.as_mut().expect("ZstdCompress not initialized");

    let input_slice = slice_input(input, in_off, in_len)?;
    let output_slice = slice_output(out, out_off, out_len)?;

    let mut in_buffer = InBuffer::around(input_slice);
    let mut out_buffer = OutBuffer::around(output_slice);

    // Call the appropriate method based on flush mode
    // 0 = ZSTD_e_continue, 1 = ZSTD_e_flush, 2 = ZSTD_e_end
    match flush {
      0 => {
        ctx
          .encoder
          .run(&mut in_buffer, &mut out_buffer)
          .map_err(|e| {
            JsErrorBox::generic(format!("Zstd compress error: {}", e))
          })?;
      }
      1 => {
        ctx
          .encoder
          .run(&mut in_buffer, &mut out_buffer)
          .map_err(|e| {
            JsErrorBox::generic(format!("Zstd compress error: {}", e))
          })?;
        ctx.encoder.flush(&mut out_buffer).map_err(|e| {
          JsErrorBox::generic(format!("Zstd flush error: {}", e))
        })?;
      }
      2 => {
        ctx
          .encoder
          .run(&mut in_buffer, &mut out_buffer)
          .map_err(|e| {
            JsErrorBox::generic(format!("Zstd compress error: {}", e))
          })?;
        ctx.encoder.finish(&mut out_buffer, true).map_err(|e| {
          JsErrorBox::generic(format!("Zstd finish error: {}", e))
        })?;
      }
      _ => {
        ctx
          .encoder
          .run(&mut in_buffer, &mut out_buffer)
          .map_err(|e| {
            JsErrorBox::generic(format!("Zstd compress error: {}", e))
          })?;
      }
    }

    let avail_in = in_len as usize - in_buffer.pos();
    let avail_out = out_len as usize - out_buffer.pos();

    if write_result.len() >= 2 {
      write_result[0] = avail_out as u32;
      write_result[1] = avail_in as u32;
    }

    Ok(())
  }

  #[fast]
  fn close(&self) {
    let mut ctx = self.ctx.borrow_mut();
    let _ = ctx.take();
  }
}

/// The error code name that Node's `ZstdStrerror` gives for a zstd error.
fn zstd_error_code_name(
  code: zstd::zstd_safe::zstd_sys::ZSTD_ErrorCode,
) -> &'static str {
  use zstd::zstd_safe::zstd_sys::ZSTD_ErrorCode::*;
  match code {
    ZSTD_error_no_error => "ZSTD_error_no_error",
    ZSTD_error_GENERIC => "ZSTD_error_GENERIC",
    ZSTD_error_prefix_unknown => "ZSTD_error_prefix_unknown",
    ZSTD_error_version_unsupported => "ZSTD_error_version_unsupported",
    ZSTD_error_frameParameter_unsupported => {
      "ZSTD_error_frameParameter_unsupported"
    }
    ZSTD_error_frameParameter_windowTooLarge => {
      "ZSTD_error_frameParameter_windowTooLarge"
    }
    ZSTD_error_corruption_detected => "ZSTD_error_corruption_detected",
    ZSTD_error_checksum_wrong => "ZSTD_error_checksum_wrong",
    ZSTD_error_literals_headerWrong => "ZSTD_error_literals_headerWrong",
    ZSTD_error_dictionary_corrupted => "ZSTD_error_dictionary_corrupted",
    ZSTD_error_dictionary_wrong => "ZSTD_error_dictionary_wrong",
    ZSTD_error_dictionaryCreation_failed => {
      "ZSTD_error_dictionaryCreation_failed"
    }
    ZSTD_error_parameter_unsupported => "ZSTD_error_parameter_unsupported",
    ZSTD_error_parameter_combination_unsupported => {
      "ZSTD_error_parameter_combination_unsupported"
    }
    ZSTD_error_parameter_outOfBound => "ZSTD_error_parameter_outOfBound",
    ZSTD_error_tableLog_tooLarge => "ZSTD_error_tableLog_tooLarge",
    ZSTD_error_maxSymbolValue_tooLarge => "ZSTD_error_maxSymbolValue_tooLarge",
    ZSTD_error_maxSymbolValue_tooSmall => "ZSTD_error_maxSymbolValue_tooSmall",
    ZSTD_error_stabilityCondition_notRespected => {
      "ZSTD_error_stabilityCondition_notRespected"
    }
    ZSTD_error_stage_wrong => "ZSTD_error_stage_wrong",
    ZSTD_error_init_missing => "ZSTD_error_init_missing",
    ZSTD_error_memory_allocation => "ZSTD_error_memory_allocation",
    ZSTD_error_workSpace_tooSmall => "ZSTD_error_workSpace_tooSmall",
    ZSTD_error_dstSize_tooSmall => "ZSTD_error_dstSize_tooSmall",
    ZSTD_error_srcSize_wrong => "ZSTD_error_srcSize_wrong",
    ZSTD_error_dstBuffer_null => "ZSTD_error_dstBuffer_null",
    ZSTD_error_noForwardProgress_destFull => {
      "ZSTD_error_noForwardProgress_destFull"
    }
    ZSTD_error_noForwardProgress_inputEmpty => {
      "ZSTD_error_noForwardProgress_inputEmpty"
    }
    _ => "ZSTD_error_GENERIC",
  }
}

/// A zstd stream error, with the message, code, and errno that Node's
/// `CompressionError` passes to `onerror`.
#[derive(Clone, Copy, Debug, PartialEq)]
struct ZstdStreamError {
  message: &'static str,
  code: &'static str,
  errno: i32,
}

impl ZstdStreamError {
  fn from_code(code: usize) -> Self {
    // SAFETY: `ZSTD_getErrorCode` only reads its argument.
    let error = unsafe { zstd::zstd_safe::zstd_sys::ZSTD_getErrorCode(code) };
    Self {
      message: zstd::zstd_safe::get_error_name(code),
      code: zstd_error_code_name(error),
      errno: error as i32,
    }
  }

  fn trailing_junk(errno: i32) -> Self {
    Self {
      message: "Trailing junk found after the end of the compressed stream",
      code: "ERR_TRAILING_JUNK_AFTER_STREAM_END",
      errno,
    }
  }
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
#[class(generic)]
#[property("code" = "ERR_ZLIB_INITIALIZATION_FAILED")]
#[error("Failed to load zstd dictionary")]
struct ZstdDictionaryLoadError;

const ZSTD_E_END: i32 = 2;

/// The decoder state of Node's `ZstdDecompressContext`: it decodes
/// concatenated frames, skips skippable frames, ignores or rejects input after
/// the last frame, and reports a frame that the input ends inside.
struct ZstdDecoder {
  // The raw context, not `zstd::stream::raw::Decoder`: the decoder turns
  // errors into `io::Error` text, and Node reports the numeric error code.
  dctx: zstd::zstd_safe::DCtx<'static>,
  frame_complete: bool,
  decoding_frame_after_complete: bool,
  reject_garbage_after_end: bool,
  ignoring_trailing_input: bool,
  frame_prefix_size: usize,
  possible_frame_types: u8,
  error: Option<ZstdStreamError>,
}

impl ZstdDecoder {
  fn new(
    dctx: zstd::zstd_safe::DCtx<'static>,
    reject_garbage_after_end: bool,
  ) -> Self {
    Self {
      dctx,
      frame_complete: false,
      decoding_frame_after_complete: false,
      reject_garbage_after_end,
      ignoring_trailing_input: false,
      frame_prefix_size: 0,
      possible_frame_types: 0,
      error: None,
    }
  }

  /// Reset the session and keep the dictionary and parameters.
  fn reset(&mut self) {
    let _ = self
      .dctx
      .reset(zstd::zstd_safe::ResetDirective::SessionOnly);
    self.frame_complete = false;
    self.decoding_frame_after_complete = false;
    self.ignoring_trailing_input = false;
    self.frame_prefix_size = 0;
    self.possible_frame_types = 0;
    self.error = None;
  }

  /// Decompress as Node's `DoThreadPoolWork` and `GetErrorInfo` do. On
  /// success, return the write result `[avail_out, avail_in]`.
  fn write(
    &mut self,
    flush: i32,
    input: &[u8],
    output: &mut [u8],
  ) -> Result<[u32; 2], ZstdStreamError> {
    use zstd::stream::raw::InBuffer;
    use zstd::stream::raw::OutBuffer;

    let out_len = output.len();
    let mut in_buffer = InBuffer::around(input);
    let mut out_buffer = OutBuffer::around(output);
    self.decompress(&mut in_buffer, &mut out_buffer);
    if let Some(error) = self.error {
      return Err(error);
    }

    let avail_in = input.len() - in_buffer.pos();
    let avail_out = out_len - out_buffer.pos();
    if flush == ZSTD_E_END
      && !self.frame_complete
      && avail_in == 0
      && avail_out > 0
    {
      // The input ends inside a frame. Only a partial magic number after the
      // last complete frame is trailing input, not a truncated frame.
      if !self.decoding_frame_after_complete || self.frame_prefix_size >= 4 {
        return Err(ZstdStreamError {
          message: "unexpected end of file",
          code: "Z_BUF_ERROR",
          errno: Z_BUF_ERROR,
        });
      }
      if self.reject_garbage_after_end {
        return Err(ZstdStreamError::trailing_junk(-1));
      }
    }
    Ok([avail_out as u32, avail_in as u32])
  }

  fn decompress(
    &mut self,
    input: &mut zstd::stream::raw::InBuffer<'_>,
    output: &mut zstd::stream::raw::OutBuffer<'_, [u8]>,
  ) {
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
    const SKIPPABLE_MAGIC: [u8; 4] = [0x50, 0x2a, 0x4d, 0x18];

    if self.ignoring_trailing_input {
      return;
    }

    // The JavaScript processing loop retries with empty input when the
    // previous call filled the output buffer. Do not read that retry as the
    // start of a new, incomplete frame.
    if self.frame_complete && input.src.is_empty() {
      return;
    }

    loop {
      if self.frame_complete {
        self.decoding_frame_after_complete = true;
        self.frame_prefix_size = 0;
        self.possible_frame_types = 0b11;
      }

      if self.decoding_frame_after_complete && self.frame_prefix_size < 4 {
        // Look at the next magic number without consuming it. Bit 0b01 is a
        // zstd frame and bit 0b10 is a skippable frame.
        let prefix = &input.src[input.pos()..];
        for &byte in prefix.iter().take(4 - self.frame_prefix_size) {
          let index = self.frame_prefix_size;
          if byte != ZSTD_MAGIC[index] {
            self.possible_frame_types &= !0b01;
          }
          let skippable = if index == 0 {
            byte & 0xf0 == SKIPPABLE_MAGIC[0]
          } else {
            byte == SKIPPABLE_MAGIC[index]
          };
          if !skippable {
            self.possible_frame_types &= !0b10;
          }
          self.frame_prefix_size += 1;
        }

        if self.possible_frame_types == 0 {
          self.frame_complete = true;
          self.decoding_frame_after_complete = false;
          if self.reject_garbage_after_end {
            self.error = Some(ZstdStreamError::trailing_junk(
              zstd::zstd_safe::zstd_sys::ZSTD_ErrorCode::ZSTD_error_GENERIC
                as i32,
            ));
          } else {
            self.ignoring_trailing_input = true;
          }
          return;
        }
      }

      match self.dctx.decompress_stream(output, input) {
        Ok(remaining) => {
          self.frame_complete = remaining == 0;
          if self.frame_complete {
            self.decoding_frame_after_complete = false;
          }
        }
        Err(code) => {
          self.frame_complete = false;
          self.error = Some(ZstdStreamError::from_code(code));
          return;
        }
      }

      if !(self.frame_complete
        && input.pos() < input.src.len()
        && output.pos() < output.capacity())
      {
        return;
      }
    }
  }
}

struct ZstdDecompressCtx {
  decoder: ZstdDecoder,
  callback: v8::Global<v8::Function>,
}

pub struct ZstdDecompress {
  ctx: Rc<RefCell<Option<ZstdDecompressCtx>>>,
}

// SAFETY: we're sure this can be GCed
unsafe impl deno_core::GarbageCollected for ZstdDecompress {
  fn trace(&self, _visitor: &mut deno_core::v8::cppgc::Visitor) {}

  fn get_name(&self) -> &'static std::ffi::CStr {
    c"ZstdDecompress"
  }
}

#[op2]
impl ZstdDecompress {
  #[constructor]
  #[cppgc]
  fn new(#[smi] _mode: i32) -> ZstdDecompress {
    ZstdDecompress {
      ctx: Rc::new(RefCell::new(None)),
    }
  }

  fn init(
    &self,
    #[buffer] params: &[u32],
    #[scoped] callback: v8::Global<v8::Function>,
    pledged_src_size: v8::Local<v8::Value>,
    #[buffer] dictionary: Option<&[u8]>,
    reject_garbage_after_end: bool,
  ) -> Result<bool, JsErrorBox> {
    use zstd::zstd_safe::DCtx;
    use zstd::zstd_safe::DParameter;

    // Unused for decompression, but Node validates it for both modes.
    parse_pledged_src_size(pledged_src_size).map_err(JsErrorBox::from_err)?;

    let mut dctx = DCtx::create();
    if dctx.init().is_err() {
      return Ok(false);
    }

    // Load the dictionary after `init()`, which drops any dictionary.
    if let Some(dictionary) = dictionary
      && !dictionary.is_empty()
      && dctx.load_dictionary(dictionary).is_err()
    {
      return Err(JsErrorBox::from_err(ZstdDictionaryLoadError));
    }

    // Apply decompression parameters
    for (i, &value) in params.iter().enumerate() {
      if value == 0xFFFFFFFF {
        continue; // Skip unset parameters
      }
      // ZSTD_d_windowLogMax = 100
      let param = match i {
        100 => DParameter::WindowLogMax(value),
        _ => continue, // Skip unknown parameters
      };
      if dctx.set_parameter(param).is_err() {
        return Ok(false);
      }
    }

    self.ctx.borrow_mut().replace(ZstdDecompressCtx {
      decoder: ZstdDecoder::new(dctx, reject_garbage_after_end),
      callback,
    });
    Ok(true)
  }

  #[fast]
  fn params(&self) {
    // no-op
  }

  #[fast]
  fn reset(&self) {
    let mut ctx = self.ctx.borrow_mut();
    if let Some(ctx) = ctx.as_mut() {
      ctx.decoder.reset();
    }
  }

  #[fast]
  #[reentrant]
  pub fn write(
    &self,
    #[this] this: v8::Global<v8::Object>,
    scope: &mut v8::PinScope<'_, '_>,
    #[smi] flush: i32,
    #[buffer] input: &[u8],
    #[smi] in_off: u32,
    #[smi] in_len: u32,
    #[buffer] out: &mut [u8],
    #[smi] out_off: u32,
    #[smi] out_len: u32,
    #[buffer] write_result: &mut [u32],
  ) -> Result<(), JsErrorBox> {
    let (result, callback) = {
      let mut ctx = self.ctx.borrow_mut();
      let ctx = ctx.as_mut().expect("ZstdDecompress not initialized");

      let input_slice = slice_input(input, in_off, in_len)?;
      let output_slice = slice_output(out, out_off, out_len)?;

      let result = ctx.decoder.write(flush, input_slice, output_slice);
      (result, v8::Local::new(scope, &ctx.callback))
    };

    // Match Node's `CheckError`: on an error, call `onerror` and do not
    // update the write result or call the write callback.
    let this = v8::Local::new(scope, &this);
    match result {
      Ok(avail) => {
        if write_result.len() >= 2 {
          write_result[..2].copy_from_slice(&avail);
        }
        let _ = callback.call(scope, this.into(), &[]);
      }
      Err(error) => {
        call_onerror(scope, this, error.message, error.errno, error.code);
      }
    }

    Ok(())
  }

  #[fast]
  #[reentrant]
  pub fn write_sync(
    &self,
    #[this] this: v8::Global<v8::Object>,
    scope: &mut v8::PinScope<'_, '_>,
    #[smi] flush: i32,
    #[buffer] input: &[u8],
    #[smi] in_off: u32,
    #[smi] in_len: u32,
    #[buffer] out: &mut [u8],
    #[smi] out_off: u32,
    #[smi] out_len: u32,
    #[buffer] write_result: &mut [u32],
  ) -> Result<(), JsErrorBox> {
    let result = {
      let mut ctx = self.ctx.borrow_mut();
      let ctx = ctx.as_mut().expect("ZstdDecompress not initialized");

      let input_slice = slice_input(input, in_off, in_len)?;
      let output_slice = slice_output(out, out_off, out_len)?;

      ctx.decoder.write(flush, input_slice, output_slice)
    };

    match result {
      Ok(avail) => {
        if write_result.len() >= 2 {
          write_result[..2].copy_from_slice(&avail);
        }
      }
      Err(error) => {
        let this = v8::Local::new(scope, &this);
        call_onerror(scope, this, error.message, error.errno, error.code);
      }
    }

    Ok(())
  }

  #[fast]
  fn close(&self) {
    let mut ctx = self.ctx.borrow_mut();
    let _ = ctx.take();
  }
}

#[op2(fast)]
pub fn op_zlib_crc32_string(#[string] data: &str, value: u32) -> u32 {
  // SAFETY: `data` is a valid buffer.
  unsafe {
    zlib::crc32(value as c_ulong, data.as_ptr(), data.len() as u32) as u32
  }
}

#[op2(fast)]
pub fn op_zlib_crc32(#[buffer] data: &[u8], value: u32) -> u32 {
  // SAFETY: `data` is a valid buffer.
  unsafe {
    zlib::crc32(value as c_ulong, data.as_ptr(), data.len() as u32) as u32
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn brotli_decoder_error_names() {
    use ffi::decompressor::ffi::BrotliDecoderErrorCode as Code;
    assert_eq!(
      brotli_decoder_error_name(
        Code::BROTLI_DECODER_ERROR_FORMAT_PADDING_2 as i32
      ),
      "_ERROR_FORMAT_PADDING_2"
    );
    assert_eq!(
      brotli_decoder_error_name(
        Code::BROTLI_DECODER_ERROR_FORMAT_CL_SPACE as i32
      ),
      "_ERROR_FORMAT_CL_SPACE"
    );
    assert_eq!(
      brotli_decoder_error_name(Code::BROTLI_DECODER_ERROR_UNREACHABLE as i32),
      "_ERROR_UNREACHABLE"
    );
    assert_eq!(brotli_decoder_error_name(-17), "INVALID");
  }

  #[test]
  fn brotli_encoder_operation_values() {
    assert!(matches!(
      encoder_operation(0),
      Ok(BrotliEncoderOperation::BROTLI_OPERATION_PROCESS)
    ));
    assert!(matches!(
      encoder_operation(1),
      Ok(BrotliEncoderOperation::BROTLI_OPERATION_FLUSH)
    ));
    assert!(matches!(
      encoder_operation(2),
      Ok(BrotliEncoderOperation::BROTLI_OPERATION_FINISH)
    ));
    assert!(matches!(
      encoder_operation(3),
      Ok(BrotliEncoderOperation::BROTLI_OPERATION_EMIT_METADATA)
    ));
    for operation in 4..=u8::MAX {
      assert!(encoder_operation(operation).is_err());
    }
  }

  #[test]
  fn brotli_encoder_parameter_values() {
    for parameter in [0, 6, 150, 162, 164, 171] {
      assert!(encoder_param(parameter).is_some());
    }
    for parameter in [7, 149, 163, 170, 172, 256] {
      assert!(encoder_param(parameter).is_none());
    }
  }

  fn zstd_decoder(reject_garbage_after_end: bool) -> ZstdDecoder {
    let mut dctx = zstd::zstd_safe::DCtx::create();
    dctx.init().unwrap();
    ZstdDecoder::new(dctx, reject_garbage_after_end)
  }

  /// Write `input` in one call with an output buffer of `out_len` bytes, and
  /// retry with the remaining input while the output buffer is full, as the
  /// JavaScript processing loop does.
  fn zstd_decode(
    decoder: &mut ZstdDecoder,
    flush: i32,
    mut input: &[u8],
    out_len: usize,
  ) -> Result<(Vec<u8>, usize), ZstdStreamError> {
    let mut decoded = Vec::new();
    loop {
      let mut out = vec![0; out_len];
      let [avail_out, avail_in] = decoder.write(flush, input, &mut out)?;
      decoded.extend_from_slice(&out[..out_len - avail_out as usize]);
      input = &input[input.len() - avail_in as usize..];
      if avail_out != 0 {
        return Ok((decoded, input.len()));
      }
    }
  }

  #[test]
  fn zstd_decoder_concatenated_and_skippable_frames() {
    let mut input = zstd::bulk::compress(b"abc", 3).unwrap();
    // A skippable frame: magic 0x184D2A5?, a 4-byte size, then the payload.
    input.extend_from_slice(&[0x53, 0x2a, 0x4d, 0x18, 2, 0, 0, 0, 7, 7]);
    input.extend(zstd::bulk::compress(b"def", 3).unwrap());

    for out_len in [1, 64] {
      let mut decoder = zstd_decoder(false);
      let (decoded, avail_in) =
        zstd_decode(&mut decoder, ZSTD_E_END, &input, out_len).unwrap();
      assert_eq!(decoded, b"abcdef");
      assert_eq!(avail_in, 0);
    }
  }

  #[test]
  fn zstd_decoder_trailing_junk() {
    let mut input = zstd::bulk::compress(b"abc", 3).unwrap();
    input.extend_from_slice(b"junk");

    let mut decoder = zstd_decoder(false);
    let (decoded, avail_in) =
      zstd_decode(&mut decoder, ZSTD_E_END, &input, 64).unwrap();
    assert_eq!(decoded, b"abc");
    assert_eq!(avail_in, 4);

    let mut decoder = zstd_decoder(true);
    let error = zstd_decode(&mut decoder, ZSTD_E_END, &input, 64).unwrap_err();
    assert_eq!(error.code, "ERR_TRAILING_JUNK_AFTER_STREAM_END");

    // A partial magic number at the end is trailing input too.
    let mut input = zstd::bulk::compress(b"abc", 3).unwrap();
    input.extend_from_slice(&[0x28, 0xb5]);
    let mut decoder = zstd_decoder(false);
    let (decoded, _) =
      zstd_decode(&mut decoder, ZSTD_E_END, &input, 64).unwrap();
    assert_eq!(decoded, b"abc");
    let mut decoder = zstd_decoder(true);
    let error = zstd_decode(&mut decoder, ZSTD_E_END, &input, 64).unwrap_err();
    assert_eq!(error.code, "ERR_TRAILING_JUNK_AFTER_STREAM_END");
    assert_eq!(error.errno, -1);
  }

  #[test]
  fn zstd_decoder_truncated_frame() {
    let input = zstd::bulk::compress(&[b'a'; 1000], 3).unwrap();
    let truncated = &input[..input.len() / 2];

    let mut decoder = zstd_decoder(false);
    let error =
      zstd_decode(&mut decoder, ZSTD_E_END, truncated, 64).unwrap_err();
    assert_eq!(
      error,
      ZstdStreamError {
        message: "unexpected end of file",
        code: "Z_BUF_ERROR",
        errno: Z_BUF_ERROR,
      }
    );

    // A flush that does not end the stream accepts the partial frame.
    let mut decoder = zstd_decoder(false);
    assert!(zstd_decode(&mut decoder, 1, truncated, 64).is_ok());

    // A second write that ends the stream reports the incomplete frame.
    let mut decoder = zstd_decoder(false);
    zstd_decode(&mut decoder, 0, truncated, 64).unwrap();
    assert!(zstd_decode(&mut decoder, ZSTD_E_END, &[], 64).is_err());

    // Ending after a complete frame is not an empty, truncated frame.
    let mut decoder = zstd_decoder(false);
    zstd_decode(&mut decoder, 0, &input, 64).unwrap();
    assert!(zstd_decode(&mut decoder, ZSTD_E_END, &[], 64).is_ok());
  }

  #[test]
  fn zstd_decoder_reset_keeps_dictionary() {
    let dictionary = b"a dictionary with some content to reference";
    let input = zstd::bulk::Compressor::with_dictionary(3, dictionary)
      .unwrap()
      .compress(b"some content to reference")
      .unwrap();

    let mut dctx = zstd::zstd_safe::DCtx::create();
    dctx.init().unwrap();
    dctx.load_dictionary(dictionary).unwrap();
    let mut decoder = ZstdDecoder::new(dctx, false);

    assert!(zstd_decode(&mut decoder, ZSTD_E_END, b"not zstd", 64).is_err());
    decoder.reset();
    let (decoded, _) =
      zstd_decode(&mut decoder, ZSTD_E_END, &input, 64).unwrap();
    assert_eq!(decoded, b"some content to reference");
  }

  #[test]
  fn zlib_start_write() {
    // buffer, length, should pass
    type WriteVector = (&'static [u8], u32, u32, bool);
    const WRITE_VECTORS: [WriteVector; 8] = [
      (b"Hello", 5, 0, true),
      (b"H", 1, 0, true),
      (b"", 0, 0, true),
      // Overrun the buffer
      (b"H", 5, 0, false),
      (b"ello", 5, 0, false),
      (b"Hello", 5, 1, false),
      (b"H", 1, 1, false),
      (b"", 0, 1, false),
    ];

    for (input, len, offset, expected) in WRITE_VECTORS.iter() {
      let mut stream = ZlibInner {
        mode: Mode::Inflate,
        ..Default::default()
      };

      stream.init_stream().unwrap();
      assert_eq!(stream.err, Z_OK);
      assert_eq!(
        stream
          .start_write(input, *offset, *len, &mut [], 0, 0, Flush::None)
          .is_ok(),
        *expected
      );
      assert_eq!(stream.err, Z_OK);
      stream.close().unwrap();
    }
  }
}
