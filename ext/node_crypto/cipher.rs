// Copyright 2018-2026 the Deno authors. MIT license.

use std::borrow::Cow;
use std::cell::RefCell;
use std::ffi::CString;
use std::rc::Rc;

use aes::cipher::Block;
use aes::cipher::BlockDecrypt;
use aes::cipher::BlockSizeUser;
use aes::cipher::BlockDecryptMut;
use aes::cipher::BlockEncrypt;
use aes::cipher::BlockEncryptMut;
use aes::cipher::KeyIvInit;
use aes::cipher::KeySizeUser;
use aes::cipher::StreamCipher;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::typenum::{
  U1,
  U10,
  U11,
  U12,
  U13,
  U14,
  U15,
  U16,
  U2,
  U3,
  U4,
  U5,
  U6,
  U7,
  U8,
  U9,
};
use deno_core::Resource;
use deno_error::JsErrorClass;
use digest::Digest;
use digest::KeyInit;
use digest::generic_array::GenericArray;
use ocb3::aead::AeadInPlace as Ocb3AeadInPlace;
use rand::RngCore;
use subtle::ConstantTimeEq;

type Tag = Option<Vec<u8>>;
type KeyWrapIv = [u8; 8];
type KeyWrapPadIv = [u8; 4];
const TDES_WRAP_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

type Aes128Gcm = aead_gcm_stream::AesGcm<aes::Aes128>;
type Aes256Gcm = aead_gcm_stream::AesGcm<aes::Aes256>;

#[derive(Debug)]
enum CipherInitError {
  ContextAllocation,
  InitFailed,
}

/// ChaCha20-Poly1305 cipher backed by aws-lc-sys (BoringSSL).
///
/// Uses the streaming EVP_CIPHER API for hardware-accelerated performance
/// on all platforms (NEON on aarch64, AVX2/SSE on x86_64).
struct ChaCha20Poly1305Cipher {
  ctx: *mut aws_lc_sys::EVP_CIPHER_CTX,
  aad_buf: Vec<u8>,
  aad_flushed: bool,
  auth_tag_length: usize,
}

// SAFETY: ChaCha20Poly1305Cipher is only accessed from a single thread
// (via RefCell in CipherContext/DecipherContext). The EVP_CIPHER_CTX
// pointer is exclusively owned by this struct.
unsafe impl Send for ChaCha20Poly1305Cipher {}

impl ChaCha20Poly1305Cipher {
  fn new(
    key: &[u8],
    iv: &[u8],
    auth_tag_length: usize,
    encrypting: bool,
  ) -> Result<Self, CipherInitError> {
    // SAFETY: We allocate a new EVP_CIPHER_CTX and initialize it with
    // validated key/iv. The ctx is exclusively owned by this struct and
    // freed in Drop.
    unsafe {
      let ctx = aws_lc_sys::EVP_CIPHER_CTX_new();
      if ctx.is_null() {
        return Err(CipherInitError::ContextAllocation);
      }

      let cipher = aws_lc_sys::EVP_chacha20_poly1305();
      let enc = if encrypting { 1 } else { 0 };
      let ret = aws_lc_sys::EVP_CipherInit_ex(
        ctx,
        cipher,
        std::ptr::null_mut(),
        key.as_ptr(),
        iv.as_ptr(),
        enc,
      );
      if ret != 1 {
        aws_lc_sys::EVP_CIPHER_CTX_free(ctx);
        return Err(CipherInitError::InitFailed);
      }

      Ok(ChaCha20Poly1305Cipher {
        ctx,
        aad_buf: Vec::new(),
        aad_flushed: false,
        auth_tag_length,
      })
    }
  }

  fn set_aad(&mut self, aad: &[u8]) {
    self.aad_buf.extend_from_slice(aad);
  }

  /// Flush buffered AAD to EVP context. Called lazily before the first
  /// encrypt/decrypt so that multiple setAAD() calls are concatenated.
  fn flush_aad(&mut self) {
    if !self.aad_flushed {
      self.aad_flushed = true;
      if !self.aad_buf.is_empty() {
        // SAFETY: ctx is valid, aad_buf is a valid slice. Passing NULL
        // output tells EVP this is AAD, not plaintext/ciphertext.
        // Length is validated to fit in i32 before casting.
        unsafe {
          let aad_len: i32 = self
            .aad_buf
            .len()
            .try_into()
            .expect("AAD length exceeds i32::MAX");
          let mut outl: i32 = 0;
          let ret = aws_lc_sys::EVP_CipherUpdate(
            self.ctx,
            std::ptr::null_mut(),
            &mut outl,
            self.aad_buf.as_ptr(),
            aad_len,
          );
          assert_eq!(ret, 1, "EVP_CipherUpdate for AAD failed");
        }
      }
    }
  }

  fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
    debug_assert!(output.len() >= input.len());
    self.flush_aad();
    // SAFETY: ctx is valid and initialized for encryption. output is
    // caller-provided with at least input.len() bytes. EVP_CipherUpdate
    // writes at most input.len() bytes for a stream cipher.
    // Length is validated to fit in i32 before casting.
    unsafe {
      let input_len: i32 = input
        .len()
        .try_into()
        .expect("input length exceeds i32::MAX");
      let mut outl: i32 = 0;
      let ret = aws_lc_sys::EVP_CipherUpdate(
        self.ctx,
        output.as_mut_ptr(),
        &mut outl,
        input.as_ptr(),
        input_len,
      );
      assert_eq!(ret, 1, "EVP_CipherUpdate for encryption failed");
    }
  }

  fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {
    debug_assert!(output.len() >= input.len());
    self.flush_aad();
    // SAFETY: ctx is valid and initialized for decryption. output is
    // caller-provided with at least input.len() bytes.
    // Length is validated to fit in i32 before casting.
    unsafe {
      let input_len: i32 = input
        .len()
        .try_into()
        .expect("input length exceeds i32::MAX");
      let mut outl: i32 = 0;
      let ret = aws_lc_sys::EVP_CipherUpdate(
        self.ctx,
        output.as_mut_ptr(),
        &mut outl,
        input.as_ptr(),
        input_len,
      );
      assert_eq!(ret, 1, "EVP_CipherUpdate for decryption failed");
    }
  }

  fn compute_tag(mut self) -> Vec<u8> {
    self.flush_aad();
    // SAFETY: ctx is valid. CipherFinal_ex finalizes the AEAD operation,
    // then CTRL_AEAD_GET_TAG retrieves the computed authentication tag.
    // The tag buffer is freshly allocated with the correct length
    // (validated to 1..=16 at construction).
    unsafe {
      let mut outl: i32 = 0;
      let ret = aws_lc_sys::EVP_CipherFinal_ex(
        self.ctx,
        std::ptr::null_mut(),
        &mut outl,
      );
      assert_eq!(ret, 1, "EVP_CipherFinal_ex failed");

      let mut tag = vec![0u8; self.auth_tag_length];
      let ret = aws_lc_sys::EVP_CIPHER_CTX_ctrl(
        self.ctx,
        aws_lc_sys::EVP_CTRL_AEAD_GET_TAG,
        self.auth_tag_length as i32,
        tag.as_mut_ptr() as *mut std::ffi::c_void,
      );
      assert_eq!(ret, 1, "EVP_CTRL_AEAD_GET_TAG failed");

      tag
    }
  }

  fn verify_tag(mut self, auth_tag: &[u8]) -> bool {
    self.flush_aad();
    // SAFETY: ctx is valid and initialized for decryption. We set the
    // expected tag via CTRL_AEAD_SET_TAG, then CipherFinal_ex performs
    // constant-time tag comparison internally, returning 0 on mismatch.
    unsafe {
      let ret = aws_lc_sys::EVP_CIPHER_CTX_ctrl(
        self.ctx,
        aws_lc_sys::EVP_CTRL_AEAD_SET_TAG,
        auth_tag.len() as i32,
        auth_tag.as_ptr() as *mut std::ffi::c_void,
      );
      if ret != 1 {
        return false;
      }

      let mut outl: i32 = 0;
      let ret = aws_lc_sys::EVP_CipherFinal_ex(
        self.ctx,
        std::ptr::null_mut(),
        &mut outl,
      );
      ret == 1
    }
  }
}

impl Drop for ChaCha20Poly1305Cipher {
  fn drop(&mut self) {
    // SAFETY: ctx was allocated by EVP_CIPHER_CTX_new and is exclusively
    // owned by this struct. This is the only place it is freed.
    unsafe {
      aws_lc_sys::EVP_CIPHER_CTX_free(self.ctx);
    }
  }
}

#[derive(Clone, Copy)]
enum OpenSslAeadMode {
  Ccm,
  Ocb,
}

struct OpenSslAeadCipher {
  ctx: *mut aws_lc_sys::EVP_CIPHER_CTX,
  aad_buf: Vec<u8>,
  aad_flushed: bool,
  auth_tag_length: usize,
  plaintext_length: Option<usize>,
  mode: OpenSslAeadMode,
}

unsafe impl Send for OpenSslAeadCipher {}

impl OpenSslAeadCipher {
  fn new(
    cipher: *const aws_lc_sys::EVP_CIPHER,
    key: &[u8],
    iv: &[u8],
    auth_tag_length: usize,
    encrypting: bool,
    mode: OpenSslAeadMode,
  ) -> Result<Self, CipherInitError> {
    unsafe {
      let ctx = aws_lc_sys::EVP_CIPHER_CTX_new();
      if ctx.is_null() {
        return Err(CipherInitError::ContextAllocation);
      }

      let enc = if encrypting { 1 } else { 0 };
      let ret = aws_lc_sys::EVP_CipherInit_ex(
        ctx,
        cipher,
        std::ptr::null_mut(),
        std::ptr::null(),
        std::ptr::null(),
        enc,
      );
      if ret != 1 {
        aws_lc_sys::EVP_CIPHER_CTX_free(ctx);
        return Err(CipherInitError::InitFailed);
      }

      let ret = aws_lc_sys::EVP_CIPHER_CTX_ctrl(
        ctx,
        aws_lc_sys::EVP_CTRL_AEAD_SET_IVLEN,
        iv.len() as i32,
        std::ptr::null_mut(),
      );
      if ret != 1 {
        aws_lc_sys::EVP_CIPHER_CTX_free(ctx);
        return Err(CipherInitError::InitFailed);
      }

      let ret = aws_lc_sys::EVP_CIPHER_CTX_ctrl(
        ctx,
        aws_lc_sys::EVP_CTRL_AEAD_SET_TAG,
        auth_tag_length as i32,
        std::ptr::null_mut(),
      );
      if ret != 1 {
        aws_lc_sys::EVP_CIPHER_CTX_free(ctx);
        return Err(CipherInitError::InitFailed);
      }

      let ret = aws_lc_sys::EVP_CipherInit_ex(
        ctx,
        std::ptr::null(),
        std::ptr::null_mut(),
        key.as_ptr(),
        iv.as_ptr(),
        enc,
      );
      if ret != 1 {
        aws_lc_sys::EVP_CIPHER_CTX_free(ctx);
        return Err(CipherInitError::InitFailed);
      }

      Ok(OpenSslAeadCipher {
        ctx,
        aad_buf: Vec::new(),
        aad_flushed: false,
        auth_tag_length,
        plaintext_length: None,
        mode,
      })
    }
  }

  fn set_aad(&mut self, aad: &[u8], plaintext_length: Option<usize>) {
    self.aad_buf.extend_from_slice(aad);
    if plaintext_length.is_some() {
      self.plaintext_length = plaintext_length;
    }
  }

  fn flush_aad(
    &mut self,
    fallback_plaintext_length: Option<usize>,
  ) -> Result<(), CipherInitError> {
    if self.aad_flushed {
      return Ok(());
    }

    unsafe {
      if let OpenSslAeadMode::Ccm = self.mode {
        if let Some(plaintext_length) =
          self.plaintext_length.or(fallback_plaintext_length)
        {
          let plaintext_length: i32 = plaintext_length
            .try_into()
            .expect("plaintext length exceeds i32::MAX");
          let mut outl = 0;
          let ret = aws_lc_sys::EVP_CipherUpdate(
            self.ctx,
            std::ptr::null_mut(),
            &mut outl,
            std::ptr::null(),
            plaintext_length,
          );
          if ret != 1 {
            return Err(CipherInitError::InitFailed);
          }
        }
      }

      if !self.aad_buf.is_empty() {
        let aad_len: i32 = self
          .aad_buf
          .len()
          .try_into()
          .expect("AAD length exceeds i32::MAX");
        let mut outl = 0;
        let ret = aws_lc_sys::EVP_CipherUpdate(
          self.ctx,
          std::ptr::null_mut(),
          &mut outl,
          self.aad_buf.as_ptr(),
          aad_len,
        );
        if ret != 1 {
          return Err(CipherInitError::InitFailed);
        }
      }
    }

    self.aad_flushed = true;
    Ok(())
  }

  fn encrypt(
    &mut self,
    input: &[u8],
    output: &mut [u8],
  ) -> Result<(), CipherInitError> {
    let fallback_plaintext_length = if input.is_empty() {
      None
    } else {
      Some(input.len())
    };
    self.flush_aad(fallback_plaintext_length)?;
    unsafe {
      let input_len: i32 = input
        .len()
        .try_into()
        .expect("input length exceeds i32::MAX");
      let mut outl = 0;
      let ret = aws_lc_sys::EVP_CipherUpdate(
        self.ctx,
        output.as_mut_ptr(),
        &mut outl,
        input.as_ptr(),
        input_len,
      );
      if ret != 1 || outl as usize != input.len() {
        return Err(CipherInitError::InitFailed);
      }
    }
    Ok(())
  }

  fn decrypt(
    &mut self,
    input: &[u8],
    output: &mut [u8],
  ) -> Result<(), CipherInitError> {
    let fallback_plaintext_length = if input.is_empty() {
      None
    } else {
      Some(input.len())
    };
    self.flush_aad(fallback_plaintext_length)?;
    unsafe {
      let input_len: i32 = input
        .len()
        .try_into()
        .expect("input length exceeds i32::MAX");
      let mut outl = 0;
      let ret = aws_lc_sys::EVP_CipherUpdate(
        self.ctx,
        output.as_mut_ptr(),
        &mut outl,
        input.as_ptr(),
        input_len,
      );
      if ret != 1 || outl as usize != input.len() {
        return Err(CipherInitError::InitFailed);
      }
    }
    Ok(())
  }

  fn compute_tag(
    mut self,
    final_input_len: Option<usize>,
  ) -> Result<Vec<u8>, CipherInitError> {
    self.flush_aad(final_input_len)?;
    unsafe {
      let mut outl = 0;
      let ret = aws_lc_sys::EVP_CipherFinal_ex(
        self.ctx,
        std::ptr::null_mut(),
        &mut outl,
      );
      if ret != 1 {
        return Err(CipherInitError::InitFailed);
      }

      let mut tag = vec![0u8; self.auth_tag_length];
      let ret = aws_lc_sys::EVP_CIPHER_CTX_ctrl(
        self.ctx,
        aws_lc_sys::EVP_CTRL_AEAD_GET_TAG,
        self.auth_tag_length as i32,
        tag.as_mut_ptr() as *mut std::ffi::c_void,
      );
      if ret != 1 {
        return Err(CipherInitError::InitFailed);
      }

      Ok(tag)
    }
  }

  fn decrypt_and_verify(
    mut self,
    input: &[u8],
    output: &mut [u8],
    auth_tag: &[u8],
  ) -> Result<bool, CipherInitError> {
    unsafe {
      let ret = aws_lc_sys::EVP_CIPHER_CTX_ctrl(
        self.ctx,
        aws_lc_sys::EVP_CTRL_AEAD_SET_TAG,
        auth_tag.len() as i32,
        auth_tag.as_ptr() as *mut std::ffi::c_void,
      );
      if ret != 1 {
        return Err(CipherInitError::InitFailed);
      }
    }

    let fallback_plaintext_length = if input.is_empty() {
      None
    } else {
      Some(input.len())
    };
    self.flush_aad(fallback_plaintext_length)?;
    unsafe {
      let input_len: i32 = input
        .len()
        .try_into()
        .expect("input length exceeds i32::MAX");
      let mut outl = 0;
      let ret = aws_lc_sys::EVP_CipherUpdate(
        self.ctx,
        output.as_mut_ptr(),
        &mut outl,
        input.as_ptr(),
        input_len,
      );
      if ret != 1 || outl as usize != input.len() {
        return Err(CipherInitError::InitFailed);
      }
    }

    match self.mode {
      OpenSslAeadMode::Ccm => Ok(true),
      OpenSslAeadMode::Ocb => unsafe {
        let ret = aws_lc_sys::EVP_CIPHER_CTX_ctrl(
          self.ctx,
          aws_lc_sys::EVP_CTRL_AEAD_SET_TAG,
          auth_tag.len() as i32,
          auth_tag.as_ptr() as *mut std::ffi::c_void,
        );
        if ret != 1 {
          return Err(CipherInitError::InitFailed);
        }
        let mut outl = 0;
        let ret = aws_lc_sys::EVP_CipherFinal_ex(
          self.ctx,
          std::ptr::null_mut(),
          &mut outl,
        );
        Ok(ret == 1)
      },
    }
  }
}

impl Drop for OpenSslAeadCipher {
  fn drop(&mut self) {
    unsafe {
      aws_lc_sys::EVP_CIPHER_CTX_free(self.ctx);
    }
  }
}

struct RustOcbCipher {
  key: Vec<u8>,
  iv: Vec<u8>,
  aad_buf: Vec<u8>,
  auth_tag_length: usize,
  pending_tag: Option<Vec<u8>>,
}

impl RustOcbCipher {
  fn new(key: &[u8], iv: &[u8], auth_tag_length: usize) -> Self {
    Self {
      key: key.to_vec(),
      iv: iv.to_vec(),
      aad_buf: Vec::new(),
      auth_tag_length,
      pending_tag: None,
    }
  }

  fn set_aad(&mut self, aad: &[u8], _plaintext_length: Option<usize>) {
    self.aad_buf.extend_from_slice(aad);
  }

  fn encrypt(
    &mut self,
    input: &[u8],
    output: &mut [u8],
  ) -> Result<(), CipherInitError> {
    let (ciphertext, tag) = ocb_encrypt_dispatch(
      &self.key,
      &self.iv,
      &self.aad_buf,
      input,
      self.auth_tag_length,
    )?;
    output[..ciphertext.len()].copy_from_slice(&ciphertext);
    self.pending_tag = Some(tag);
    Ok(())
  }

  fn compute_tag(self, _final_input_len: Option<usize>) -> Result<Vec<u8>, CipherInitError> {
    if let Some(tag) = self.pending_tag {
      return Ok(tag);
    }

    let (_, tag) = ocb_encrypt_dispatch(
      &self.key,
      &self.iv,
      &self.aad_buf,
      &[],
      self.auth_tag_length,
    )?;
    Ok(tag)
  }

  fn decrypt_and_verify(
    &mut self,
    input: &[u8],
    output: &mut [u8],
    auth_tag: &[u8],
  ) -> Result<bool, CipherInitError> {
    let Some(plaintext) = ocb_decrypt_dispatch(
      &self.key,
      &self.iv,
      &self.aad_buf,
      input,
      auth_tag,
    )? else {
      return Ok(false);
    };
    output[..plaintext.len()].copy_from_slice(&plaintext);
    Ok(true)
  }
}

macro_rules! ocb_encrypt_concrete {
  ($cipher:ty, $nonce_size:ty, $tag_size:ty, $key:expr, $iv:expr, $aad:expr, $input:expr) => {{
    let cipher = ocb3::Ocb3::<$cipher, $nonce_size, $tag_size>::new_from_slice($key)
      .map_err(|_| CipherInitError::InitFailed)?;
    let nonce = ocb3::GenericArray::from_slice($iv);
    let mut ciphertext = $input.to_vec();
    let tag = cipher
      .encrypt_in_place_detached(nonce, $aad, &mut ciphertext)
      .map_err(|_| CipherInitError::InitFailed)?;
    Ok((ciphertext, tag.to_vec()))
  }};
}

macro_rules! ocb_decrypt_concrete {
  ($cipher:ty, $nonce_size:ty, $tag_size:ty, $key:expr, $iv:expr, $aad:expr, $input:expr, $auth_tag:expr) => {{
    let cipher = ocb3::Ocb3::<$cipher, $nonce_size, $tag_size>::new_from_slice($key)
      .map_err(|_| CipherInitError::InitFailed)?;
    let nonce = ocb3::GenericArray::from_slice($iv);
    let tag = ocb3::GenericArray::from_slice($auth_tag);
    let mut plaintext = $input.to_vec();
    match cipher.decrypt_in_place_detached(nonce, $aad, &mut plaintext, tag) {
      Ok(()) => Ok(Some(plaintext)),
      Err(_) => Ok(None),
    }
  }};
}

macro_rules! ocb_dispatch_tag_encrypt {
  ($cipher:ty, $nonce_size:ty, $key:expr, $iv:expr, $aad:expr, $input:expr, $tag_len:expr) => {{
    match $tag_len {
      1 => ocb_encrypt_concrete!($cipher, $nonce_size, U1, $key, $iv, $aad, $input),
      2 => ocb_encrypt_concrete!($cipher, $nonce_size, U2, $key, $iv, $aad, $input),
      3 => ocb_encrypt_concrete!($cipher, $nonce_size, U3, $key, $iv, $aad, $input),
      4 => ocb_encrypt_concrete!($cipher, $nonce_size, U4, $key, $iv, $aad, $input),
      5 => ocb_encrypt_concrete!($cipher, $nonce_size, U5, $key, $iv, $aad, $input),
      6 => ocb_encrypt_concrete!($cipher, $nonce_size, U6, $key, $iv, $aad, $input),
      7 => ocb_encrypt_concrete!($cipher, $nonce_size, U7, $key, $iv, $aad, $input),
      8 => ocb_encrypt_concrete!($cipher, $nonce_size, U8, $key, $iv, $aad, $input),
      9 => ocb_encrypt_concrete!($cipher, $nonce_size, U9, $key, $iv, $aad, $input),
      10 => ocb_encrypt_concrete!($cipher, $nonce_size, U10, $key, $iv, $aad, $input),
      11 => ocb_encrypt_concrete!($cipher, $nonce_size, U11, $key, $iv, $aad, $input),
      12 => ocb_encrypt_concrete!($cipher, $nonce_size, U12, $key, $iv, $aad, $input),
      13 => ocb_encrypt_concrete!($cipher, $nonce_size, U13, $key, $iv, $aad, $input),
      14 => ocb_encrypt_concrete!($cipher, $nonce_size, U14, $key, $iv, $aad, $input),
      15 => ocb_encrypt_concrete!($cipher, $nonce_size, U15, $key, $iv, $aad, $input),
      16 => ocb_encrypt_concrete!($cipher, $nonce_size, U16, $key, $iv, $aad, $input),
      _ => Err(CipherInitError::InitFailed),
    }
  }};
}

macro_rules! ocb_dispatch_tag_decrypt {
  ($cipher:ty, $nonce_size:ty, $key:expr, $iv:expr, $aad:expr, $input:expr, $auth_tag:expr) => {{
    match $auth_tag.len() {
      1 => ocb_decrypt_concrete!($cipher, $nonce_size, U1, $key, $iv, $aad, $input, $auth_tag),
      2 => ocb_decrypt_concrete!($cipher, $nonce_size, U2, $key, $iv, $aad, $input, $auth_tag),
      3 => ocb_decrypt_concrete!($cipher, $nonce_size, U3, $key, $iv, $aad, $input, $auth_tag),
      4 => ocb_decrypt_concrete!($cipher, $nonce_size, U4, $key, $iv, $aad, $input, $auth_tag),
      5 => ocb_decrypt_concrete!($cipher, $nonce_size, U5, $key, $iv, $aad, $input, $auth_tag),
      6 => ocb_decrypt_concrete!($cipher, $nonce_size, U6, $key, $iv, $aad, $input, $auth_tag),
      7 => ocb_decrypt_concrete!($cipher, $nonce_size, U7, $key, $iv, $aad, $input, $auth_tag),
      8 => ocb_decrypt_concrete!($cipher, $nonce_size, U8, $key, $iv, $aad, $input, $auth_tag),
      9 => ocb_decrypt_concrete!($cipher, $nonce_size, U9, $key, $iv, $aad, $input, $auth_tag),
      10 => ocb_decrypt_concrete!($cipher, $nonce_size, U10, $key, $iv, $aad, $input, $auth_tag),
      11 => ocb_decrypt_concrete!($cipher, $nonce_size, U11, $key, $iv, $aad, $input, $auth_tag),
      12 => ocb_decrypt_concrete!($cipher, $nonce_size, U12, $key, $iv, $aad, $input, $auth_tag),
      13 => ocb_decrypt_concrete!($cipher, $nonce_size, U13, $key, $iv, $aad, $input, $auth_tag),
      14 => ocb_decrypt_concrete!($cipher, $nonce_size, U14, $key, $iv, $aad, $input, $auth_tag),
      15 => ocb_decrypt_concrete!($cipher, $nonce_size, U15, $key, $iv, $aad, $input, $auth_tag),
      16 => ocb_decrypt_concrete!($cipher, $nonce_size, U16, $key, $iv, $aad, $input, $auth_tag),
      _ => Err(CipherInitError::InitFailed),
    }
  }};
}

macro_rules! ocb_dispatch_nonce_encrypt {
  ($cipher:ty, $key:expr, $iv:expr, $aad:expr, $input:expr, $tag_len:expr) => {{
    match $iv.len() {
      6 => ocb_dispatch_tag_encrypt!($cipher, U6, $key, $iv, $aad, $input, $tag_len),
      7 => ocb_dispatch_tag_encrypt!($cipher, U7, $key, $iv, $aad, $input, $tag_len),
      8 => ocb_dispatch_tag_encrypt!($cipher, U8, $key, $iv, $aad, $input, $tag_len),
      9 => ocb_dispatch_tag_encrypt!($cipher, U9, $key, $iv, $aad, $input, $tag_len),
      10 => ocb_dispatch_tag_encrypt!($cipher, U10, $key, $iv, $aad, $input, $tag_len),
      11 => ocb_dispatch_tag_encrypt!($cipher, U11, $key, $iv, $aad, $input, $tag_len),
      12 => ocb_dispatch_tag_encrypt!($cipher, U12, $key, $iv, $aad, $input, $tag_len),
      13 => ocb_dispatch_tag_encrypt!($cipher, U13, $key, $iv, $aad, $input, $tag_len),
      14 => ocb_dispatch_tag_encrypt!($cipher, U14, $key, $iv, $aad, $input, $tag_len),
      15 => ocb_dispatch_tag_encrypt!($cipher, U15, $key, $iv, $aad, $input, $tag_len),
      _ => Err(CipherInitError::InitFailed),
    }
  }};
}

macro_rules! ocb_dispatch_nonce_decrypt {
  ($cipher:ty, $key:expr, $iv:expr, $aad:expr, $input:expr, $auth_tag:expr) => {{
    match $iv.len() {
      6 => ocb_dispatch_tag_decrypt!($cipher, U6, $key, $iv, $aad, $input, $auth_tag),
      7 => ocb_dispatch_tag_decrypt!($cipher, U7, $key, $iv, $aad, $input, $auth_tag),
      8 => ocb_dispatch_tag_decrypt!($cipher, U8, $key, $iv, $aad, $input, $auth_tag),
      9 => ocb_dispatch_tag_decrypt!($cipher, U9, $key, $iv, $aad, $input, $auth_tag),
      10 => ocb_dispatch_tag_decrypt!($cipher, U10, $key, $iv, $aad, $input, $auth_tag),
      11 => ocb_dispatch_tag_decrypt!($cipher, U11, $key, $iv, $aad, $input, $auth_tag),
      12 => ocb_dispatch_tag_decrypt!($cipher, U12, $key, $iv, $aad, $input, $auth_tag),
      13 => ocb_dispatch_tag_decrypt!($cipher, U13, $key, $iv, $aad, $input, $auth_tag),
      14 => ocb_dispatch_tag_decrypt!($cipher, U14, $key, $iv, $aad, $input, $auth_tag),
      15 => ocb_dispatch_tag_decrypt!($cipher, U15, $key, $iv, $aad, $input, $auth_tag),
      _ => Err(CipherInitError::InitFailed),
    }
  }};
}

fn ocb_encrypt_dispatch(
  key: &[u8],
  iv: &[u8],
  aad: &[u8],
  input: &[u8],
  auth_tag_length: usize,
) -> Result<(Vec<u8>, Vec<u8>), CipherInitError> {
  match key.len() {
    16 => ocb_dispatch_nonce_encrypt!(aes::Aes128, key, iv, aad, input, auth_tag_length),
    24 => ocb_dispatch_nonce_encrypt!(aes::Aes192, key, iv, aad, input, auth_tag_length),
    32 => ocb_dispatch_nonce_encrypt!(aes::Aes256, key, iv, aad, input, auth_tag_length),
    _ => Err(CipherInitError::InitFailed),
  }
}

fn ocb_decrypt_dispatch(
  key: &[u8],
  iv: &[u8],
  aad: &[u8],
  input: &[u8],
  auth_tag: &[u8],
) -> Result<Option<Vec<u8>>, CipherInitError> {
  match key.len() {
    16 => ocb_dispatch_nonce_decrypt!(aes::Aes128, key, iv, aad, input, auth_tag),
    24 => ocb_dispatch_nonce_decrypt!(aes::Aes192, key, iv, aad, input, auth_tag),
    32 => ocb_dispatch_nonce_decrypt!(aes::Aes256, key, iv, aad, input, auth_tag),
    _ => Err(CipherInitError::InitFailed),
  }
}

fn evp_cipher_by_name(
  algorithm_name: &str,
) -> Option<*const aws_lc_sys::EVP_CIPHER> {
  let algorithm_name = CString::new(algorithm_name).ok()?;
  let cipher =
    unsafe { aws_lc_sys::EVP_get_cipherbyname(algorithm_name.as_ptr()) };
  if cipher.is_null() {
    None
  } else {
    Some(cipher)
  }
}

#[derive(Debug, Clone, Copy)]
enum AesKeyWrapError {
  InvalidDataSize,
  InvalidOutputSize,
  IntegrityCheckFailed,
}

#[derive(Debug, Clone, Copy)]
enum TdesWrapError {
  InvalidDataSize,
  IntegrityCheckFailed,
}

fn tdes_cbc_encrypt(
  key: &[u8],
  iv: &KeyWrapIv,
  input: &[u8],
  output: &mut [u8],
) -> Result<(), TdesWrapError> {
  if input.len() != output.len() || !input.len().is_multiple_of(8) {
    return Err(TdesWrapError::InvalidDataSize);
  }

  let mut encryptor =
    cbc::Encryptor::<des::TdesEde3>::new(key.into(), iv.into());
  for (input, output) in input.chunks(8).zip(output.chunks_mut(8)) {
    encryptor.encrypt_block_b2b_mut(
      GenericArray::from_slice(input),
      GenericArray::from_mut_slice(output),
    );
  }
  Ok(())
}

fn tdes_cbc_decrypt(
  key: &[u8],
  iv: &KeyWrapIv,
  input: &[u8],
  output: &mut [u8],
) -> Result<(), TdesWrapError> {
  if input.len() != output.len() || !input.len().is_multiple_of(8) {
    return Err(TdesWrapError::InvalidDataSize);
  }

  let mut decryptor =
    cbc::Decryptor::<des::TdesEde3>::new(key.into(), iv.into());
  for (input, output) in input.chunks(8).zip(output.chunks_mut(8)) {
    decryptor.decrypt_block_b2b_mut(
      GenericArray::from_slice(input),
      GenericArray::from_mut_slice(output),
    );
  }
  Ok(())
}

fn tdes_wrap_encrypt(
  key: &[u8],
  input: &[u8],
) -> Result<Vec<u8>, TdesWrapError> {
  if input.is_empty() || !input.len().is_multiple_of(8) {
    return Err(TdesWrapError::InvalidDataSize);
  }

  let mut output = vec![0u8; input.len() + 16];
  output[8..8 + input.len()].copy_from_slice(input);
  let icv = sha1::Sha1::digest(input);
  output[8 + input.len()..].copy_from_slice(&icv[..8]);

  let mut iv = [0u8; 8];
  rand::thread_rng().fill_bytes(&mut iv);
  output[..8].copy_from_slice(&iv);

  let mut inner = vec![0u8; input.len() + 8];
  tdes_cbc_encrypt(key, &iv, &output[8..], &mut inner)?;
  output[8..].copy_from_slice(&inner);
  output.reverse();

  let mut wrapped = vec![0u8; output.len()];
  tdes_cbc_encrypt(key, &TDES_WRAP_IV, &output, &mut wrapped)?;
  Ok(wrapped)
}

fn tdes_wrap_decrypt(
  key: &[u8],
  input: &[u8],
) -> Result<Vec<u8>, TdesWrapError> {
  if input.len() < 24 || !input.len().is_multiple_of(8) {
    return Err(TdesWrapError::InvalidDataSize);
  }

  let mut reversed = vec![0u8; input.len()];
  tdes_cbc_decrypt(key, &TDES_WRAP_IV, input, &mut reversed)?;
  reversed.reverse();

  let mut inner_iv = [0u8; 8];
  inner_iv.copy_from_slice(&reversed[..8]);
  let mut plaintext_and_icv = vec![0u8; input.len() - 8];
  tdes_cbc_decrypt(
    key,
    &inner_iv,
    &reversed[8..],
    &mut plaintext_and_icv,
  )?;

  let plaintext_len = plaintext_and_icv
    .len()
    .checked_sub(8)
    .ok_or(TdesWrapError::InvalidDataSize)?;
  let plaintext = &plaintext_and_icv[..plaintext_len];
  let expected_icv = sha1::Sha1::digest(plaintext);
  if plaintext_and_icv[plaintext_len..] != expected_icv[..8] {
    return Err(TdesWrapError::IntegrityCheckFailed);
  }

  Ok(plaintext.to_vec())
}

fn xor_key_wrap_t(iv: &mut KeyWrapIv, t: u64) {
  for (value, xor) in iv.iter_mut().zip(t.to_be_bytes()) {
    *value ^= xor;
  }
}

fn aes_key_wrap_encrypt<C>(
  cipher: &C,
  iv: &KeyWrapIv,
  data: &[u8],
  output: &mut [u8],
) -> Result<(), AesKeyWrapError>
where
  C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
  if data.is_empty() || !data.len().is_multiple_of(8) {
    return Err(AesKeyWrapError::InvalidDataSize);
  }

  if output.len() != data.len() + 8 {
    return Err(AesKeyWrapError::InvalidOutputSize);
  }

  let n = data.len() / 8;
  let mut a = *iv;
  output[8..].copy_from_slice(data);

  for j in 0..6 {
    for i in 0..n {
      let mut block = Block::<C>::default();
      block[..8].copy_from_slice(&a);
      block[8..].copy_from_slice(&output[8 + i * 8..8 + (i + 1) * 8]);
      cipher.encrypt_block(&mut block);
      a.copy_from_slice(&block[..8]);
      xor_key_wrap_t(&mut a, (n * j + i + 1) as u64);
      output[8 + i * 8..8 + (i + 1) * 8].copy_from_slice(&block[8..]);
    }
  }

  output[..8].copy_from_slice(&a);
  Ok(())
}

fn aes_key_wrap_decrypt<C>(
  cipher: &C,
  iv: &KeyWrapIv,
  data: &[u8],
  output: &mut [u8],
) -> Result<(), AesKeyWrapError>
where
  C: BlockDecrypt + BlockSizeUser<BlockSize = U16>,
{
  if data.len() <= 8 || !data.len().is_multiple_of(8) {
    return Err(AesKeyWrapError::InvalidDataSize);
  }

  if output.len() != data.len() - 8 {
    return Err(AesKeyWrapError::InvalidOutputSize);
  }

  let n = output.len() / 8;
  let mut a = [0u8; 8];
  a.copy_from_slice(&data[..8]);
  output.copy_from_slice(&data[8..]);

  for j in (0..6).rev() {
    for i in (0..n).rev() {
      let mut block = Block::<C>::default();
      let mut a_with_t = a;
      xor_key_wrap_t(&mut a_with_t, (n * j + i + 1) as u64);
      block[..8].copy_from_slice(&a_with_t);
      block[8..].copy_from_slice(&output[i * 8..(i + 1) * 8]);
      cipher.decrypt_block(&mut block);
      a.copy_from_slice(&block[..8]);
      output[i * 8..(i + 1) * 8].copy_from_slice(&block[8..]);
    }
  }

  if a == *iv {
    Ok(())
  } else {
    Err(AesKeyWrapError::IntegrityCheckFailed)
  }
}

fn aes_key_wrap_decrypt_raw<C>(
  cipher: &C,
  data: &[u8],
  output: &mut [u8],
) -> Result<KeyWrapIv, AesKeyWrapError>
where
  C: BlockDecrypt + BlockSizeUser<BlockSize = U16>,
{
  if data.len() <= 8 || !data.len().is_multiple_of(8) {
    return Err(AesKeyWrapError::InvalidDataSize);
  }

  if output.len() != data.len() - 8 {
    return Err(AesKeyWrapError::InvalidOutputSize);
  }

  let n = output.len() / 8;
  let mut a = [0u8; 8];
  a.copy_from_slice(&data[..8]);
  output.copy_from_slice(&data[8..]);

  for j in (0..6).rev() {
    for i in (0..n).rev() {
      let mut block = Block::<C>::default();
      let mut a_with_t = a;
      xor_key_wrap_t(&mut a_with_t, (n * j + i + 1) as u64);
      block[..8].copy_from_slice(&a_with_t);
      block[8..].copy_from_slice(&output[i * 8..(i + 1) * 8]);
      cipher.decrypt_block(&mut block);
      a.copy_from_slice(&block[..8]);
      output[i * 8..(i + 1) * 8].copy_from_slice(&block[8..]);
    }
  }

  Ok(a)
}

fn aes_key_wrap_pad_encrypt<C>(
  cipher: &C,
  iv_prefix: &KeyWrapPadIv,
  data: &[u8],
  output: &mut [u8],
) -> Result<usize, AesKeyWrapError>
where
  C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
  if data.is_empty() {
    return Err(AesKeyWrapError::InvalidDataSize);
  }

  let mut aiv = [0u8; 8];
  aiv[..4].copy_from_slice(iv_prefix);
  aiv[4..].copy_from_slice(&(data.len() as u32).to_be_bytes());

  if data.len() <= 8 {
    if output.len() != 16 {
      return Err(AesKeyWrapError::InvalidOutputSize);
    }
    let mut block = Block::<C>::default();
    block[..8].copy_from_slice(&aiv);
    block[8..8 + data.len()].copy_from_slice(data);
    cipher.encrypt_block(&mut block);
    output[..16].copy_from_slice(&block);
    return Ok(16);
  }

  let padded_len = (data.len() + 7) & !7;
  if output.len() != padded_len + 8 {
    return Err(AesKeyWrapError::InvalidOutputSize);
  }

  let mut padded = vec![0u8; padded_len];
  padded[..data.len()].copy_from_slice(data);
  aes_key_wrap_encrypt(cipher, &aiv, &padded, output)?;
  Ok(padded_len + 8)
}

fn aes_key_wrap_pad_decrypt<C>(
  cipher: &C,
  iv_prefix: &KeyWrapPadIv,
  data: &[u8],
  output: &mut [u8],
) -> Result<usize, AesKeyWrapError>
where
  C: BlockDecrypt + BlockSizeUser<BlockSize = U16>,
{
  if data.len() < 16 || !data.len().is_multiple_of(8) {
    return Err(AesKeyWrapError::InvalidDataSize);
  }

  if data.len() == 16 {
    if output.len() < 8 {
      return Err(AesKeyWrapError::InvalidOutputSize);
    }
    let mut block = Block::<C>::default();
    block.copy_from_slice(data);
    cipher.decrypt_block(&mut block);

    if block[..4] != iv_prefix[..] {
      return Err(AesKeyWrapError::IntegrityCheckFailed);
    }

    let claimed_len =
      u32::from_be_bytes(block[4..8].try_into().expect("slice length")) as usize;
    if !(1..=8).contains(&claimed_len) {
      return Err(AesKeyWrapError::IntegrityCheckFailed);
    }
    if block[8 + claimed_len..].iter().any(|byte| *byte != 0) {
      return Err(AesKeyWrapError::IntegrityCheckFailed);
    }

    output[..claimed_len].copy_from_slice(&block[8..8 + claimed_len]);
    return Ok(claimed_len);
  }

  let padded_len = data.len() - 8;
  if output.len() < padded_len {
    return Err(AesKeyWrapError::InvalidOutputSize);
  }

  let aiv = aes_key_wrap_decrypt_raw(cipher, data, &mut output[..padded_len])?;
  if aiv[..4] != iv_prefix[..] {
    return Err(AesKeyWrapError::IntegrityCheckFailed);
  }

  let claimed_len =
    u32::from_be_bytes(aiv[4..].try_into().expect("slice length")) as usize;
  if claimed_len == 0 || claimed_len > padded_len {
    return Err(AesKeyWrapError::IntegrityCheckFailed);
  }
  if ((claimed_len - 1) >> 3) != ((data.len() - 9) >> 3) {
    return Err(AesKeyWrapError::IntegrityCheckFailed);
  }
  if output[claimed_len..padded_len].iter().any(|byte| *byte != 0) {
    return Err(AesKeyWrapError::IntegrityCheckFailed);
  }

  Ok(claimed_len)
}

enum Cipher {
  Aes128Cbc(Box<cbc::Encryptor<aes::Aes128>>),
  Aes128Ecb(Box<ecb::Encryptor<aes::Aes128>>),
  Aes192Cbc(Box<cbc::Encryptor<aes::Aes192>>),
  Aes192Ecb(Box<ecb::Encryptor<aes::Aes192>>),
  Aes256Ecb(Box<ecb::Encryptor<aes::Aes256>>),
  Aes128Gcm(Box<Aes128Gcm>, Option<usize>),
  Aes128Ccm(Box<OpenSslAeadCipher>),
  Aes192Ccm(Box<OpenSslAeadCipher>),
  Aes256Ccm(Box<OpenSslAeadCipher>),
  Aes128Ocb(Box<RustOcbCipher>),
  Aes192Ocb(Box<RustOcbCipher>),
  Aes256Ocb(Box<RustOcbCipher>),
  Aes256Gcm(Box<Aes256Gcm>, Option<usize>),
  Aes256Cbc(Box<cbc::Encryptor<aes::Aes256>>),
  Aes128Ctr(Box<ctr::Ctr128BE<aes::Aes128>>),
  Aes192Ctr(Box<ctr::Ctr128BE<aes::Aes192>>),
  Aes256Ctr(Box<ctr::Ctr128BE<aes::Aes256>>),
  DesEde3Cbc(Box<cbc::Encryptor<des::TdesEde3>>),
  Aes128Wrap(Box<aes::Aes128>, KeyWrapIv),
  Aes192Wrap(Box<aes::Aes192>, KeyWrapIv),
  Aes256Wrap(Box<aes::Aes256>, KeyWrapIv),
  Aes128WrapPad(Box<aes::Aes128>, KeyWrapPadIv),
  Aes192WrapPad(Box<aes::Aes192>, KeyWrapPadIv),
  Aes256WrapPad(Box<aes::Aes256>, KeyWrapPadIv),
  Des3Wrap(Vec<u8>),
  ChaCha20Poly1305(Box<ChaCha20Poly1305Cipher>),
}

enum Decipher {
  Aes128Cbc(Box<cbc::Decryptor<aes::Aes128>>),
  Aes128Ecb(Box<ecb::Decryptor<aes::Aes128>>),
  Aes192Cbc(Box<cbc::Decryptor<aes::Aes192>>),
  Aes192Ecb(Box<ecb::Decryptor<aes::Aes192>>),
  Aes256Ecb(Box<ecb::Decryptor<aes::Aes256>>),
  Aes128Gcm(Box<Aes128Gcm>, Option<usize>),
  Aes128Ccm(Box<OpenSslAeadCipher>),
  Aes192Ccm(Box<OpenSslAeadCipher>),
  Aes256Ccm(Box<OpenSslAeadCipher>),
  Aes128Ocb(Box<RustOcbCipher>),
  Aes192Ocb(Box<RustOcbCipher>),
  Aes256Ocb(Box<RustOcbCipher>),
  Aes256Gcm(Box<Aes256Gcm>, Option<usize>),
  Aes256Cbc(Box<cbc::Decryptor<aes::Aes256>>),
  Aes128Ctr(Box<ctr::Ctr128BE<aes::Aes128>>),
  Aes192Ctr(Box<ctr::Ctr128BE<aes::Aes192>>),
  Aes256Ctr(Box<ctr::Ctr128BE<aes::Aes256>>),
  DesEde3Cbc(Box<cbc::Decryptor<des::TdesEde3>>),
  Aes128Wrap(Box<aes::Aes128>, KeyWrapIv),
  Aes192Wrap(Box<aes::Aes192>, KeyWrapIv),
  Aes256Wrap(Box<aes::Aes256>, KeyWrapIv),
  Aes128WrapPad(Box<aes::Aes128>, KeyWrapPadIv),
  Aes192WrapPad(Box<aes::Aes192>, KeyWrapPadIv),
  Aes256WrapPad(Box<aes::Aes256>, KeyWrapPadIv),
  Des3Wrap(Vec<u8>),
  ChaCha20Poly1305(Box<ChaCha20Poly1305Cipher>, Option<usize>),
  // TODO(kt3k): add more algorithms Aes128GCM, etc.
}

pub struct CipherContext {
  cipher: Rc<RefCell<Cipher>>,
}

pub struct DecipherContext {
  decipher: Rc<RefCell<Decipher>>,
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum CipherContextError {
  #[class(type)]
  #[error("Cipher context is already in use")]
  ContextInUse,
  #[class(inherit)]
  #[error("{0}")]
  Resource(#[from] deno_core::error::ResourceError),
  #[class(inherit)]
  #[error(transparent)]
  Cipher(#[from] CipherError),
}

impl CipherContext {
  pub fn new(
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    auth_tag_length: Option<usize>,
  ) -> Result<Self, CipherContextError> {
    Ok(Self {
      cipher: Rc::new(RefCell::new(Cipher::new(
        algorithm,
        key,
        iv,
        auth_tag_length,
      )?)),
    })
  }

  pub fn set_aad(&self, aad: &[u8], plaintext_length: Option<usize>) {
    self.cipher.borrow_mut().set_aad(aad, plaintext_length);
  }

  pub fn encrypt(&self, input: &[u8], output: &mut [u8]) {
    self.cipher.borrow_mut().encrypt(input, output);
  }

  pub fn take_tag(self) -> Tag {
    Rc::try_unwrap(self.cipher).ok()?.into_inner().take_tag()
  }

  pub fn r#final(
    self,
    auto_pad: bool,
    input: &[u8],
    output: &mut [u8],
  ) -> Result<Tag, CipherContextError> {
    Rc::try_unwrap(self.cipher)
      .map_err(|_| CipherContextError::ContextInUse)?
      .into_inner()
      .r#final(auto_pad, input, output)
      .map_err(Into::into)
  }

  pub fn final_key_wrap(
    self,
    input: &[u8],
  ) -> Result<Vec<u8>, CipherContextError> {
    Rc::try_unwrap(self.cipher)
      .map_err(|_| CipherContextError::ContextInUse)?
      .into_inner()
      .final_key_wrap(input)
      .map_err(Into::into)
  }
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum DecipherContextError {
  #[class(type)]
  #[error("Decipher context is already in use")]
  ContextInUse,
  #[class(inherit)]
  #[error("{0}")]
  Resource(#[from] deno_core::error::ResourceError),
  #[class(inherit)]
  #[error(transparent)]
  Decipher(#[from] DecipherError),
}

impl DecipherContext {
  pub fn new(
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    auth_tag_length: Option<usize>,
  ) -> Result<Self, DecipherContextError> {
    Ok(Self {
      decipher: Rc::new(RefCell::new(Decipher::new(
        algorithm,
        key,
        iv,
        auth_tag_length,
      )?)),
    })
  }

  pub fn validate_auth_tag(
    &self,
    length: usize,
  ) -> Result<(), DecipherContextError> {
    self.decipher.borrow().validate_auth_tag(length)?;

    Ok(())
  }

  pub fn set_aad(&self, aad: &[u8], plaintext_length: Option<usize>) {
    self.decipher.borrow_mut().set_aad(aad, plaintext_length);
  }

  pub fn decrypt(&self, input: &[u8], output: &mut [u8]) {
    self.decipher.borrow_mut().decrypt(input, output);
  }

  pub fn r#final(
    self,
    auto_pad: bool,
    input: &[u8],
    output: &mut [u8],
    auth_tag: &[u8],
  ) -> Result<(), DecipherContextError> {
    Rc::try_unwrap(self.decipher)
      .map_err(|_| DecipherContextError::ContextInUse)?
      .into_inner()
      .r#final(auto_pad, input, output, auth_tag)
      .map_err(Into::into)
  }

  pub fn final_key_wrap(
    self,
    input: &[u8],
  ) -> Result<Vec<u8>, DecipherContextError> {
    Rc::try_unwrap(self.decipher)
      .map_err(|_| DecipherContextError::ContextInUse)?
      .into_inner()
      .final_key_wrap(input)
      .map_err(Into::into)
  }
}

impl Resource for CipherContext {
  fn name(&self) -> Cow<'_, str> {
    "cryptoCipher".into()
  }
}

impl Resource for DecipherContext {
  fn name(&self) -> Cow<'_, str> {
    "cryptoDecipher".into()
  }
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum CipherError {
  #[class(type)]
  #[error("IV length must be 12 bytes")]
  InvalidIvLength,
  #[class(range)]
  #[error("Invalid key length")]
  InvalidKeyLength,
  #[class(range)]
  #[error("Invalid AES key wrap data size")]
  InvalidDataSize,
  #[class(type)]
  #[error("Invalid initialization vector")]
  InvalidInitializationVector,
  #[class(type)]
  #[error("bad decrypt")]
  CannotPadInputData,
  #[class(type)]
  #[error("Unknown cipher {0}")]
  UnknownCipher(String),
  #[class(type)]
  #[error("Invalid authentication tag length: {0}")]
  InvalidAuthTag(usize),
}

fn is_valid_chacha20_poly1305_tag_length(tag_len: usize) -> bool {
  (1..=16).contains(&tag_len)
}

fn is_valid_ccm_tag_length(tag_len: usize) -> bool {
  matches!(tag_len, 4 | 6 | 8 | 10 | 12 | 14 | 16)
}

fn is_valid_ocb_tag_length(tag_len: usize) -> bool {
  (1..=16).contains(&tag_len)
}

fn map_cipher_init_error(error: CipherInitError) -> CipherError {
  match error {
    CipherInitError::ContextAllocation => {
      panic!("Failed to allocate EVP_CIPHER_CTX")
    }
    CipherInitError::InitFailed => CipherError::InvalidDataSize,
  }
}

fn map_decipher_init_error(error: CipherInitError) -> DecipherError {
  match error {
    CipherInitError::ContextAllocation => {
      panic!("Failed to allocate EVP_CIPHER_CTX")
    }
    CipherInitError::InitFailed => DecipherError::DataAuthenticationFailed,
  }
}

impl Cipher {
  fn new(
    algorithm_name: &str,
    key: &[u8],
    iv: &[u8],
    auth_tag_length: Option<usize>,
  ) -> Result<Self, CipherError> {
    use Cipher::*;
    Ok(match algorithm_name {
      "aes128" | "aes-128-cbc" => {
        if key.len() != 16 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(CipherError::InvalidInitializationVector);
        }
        Aes128Cbc(Box::new(cbc::Encryptor::new(key.into(), iv.into())))
      }
      "aes-128-ecb" => {
        if key.len() != 16 {
          return Err(CipherError::InvalidKeyLength);
        }
        if !iv.is_empty() {
          return Err(CipherError::InvalidInitializationVector);
        }
        Aes128Ecb(Box::new(ecb::Encryptor::new(key.into())))
      }
      "aes192" | "aes-192-cbc" => {
        if key.len() != 24 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(CipherError::InvalidInitializationVector);
        }
        Aes192Cbc(Box::new(cbc::Encryptor::new(key.into(), iv.into())))
      }
      "aes-192-ecb" => {
        if key.len() != 24 {
          return Err(CipherError::InvalidKeyLength);
        }
        if !iv.is_empty() {
          return Err(CipherError::InvalidInitializationVector);
        }
        Aes192Ecb(Box::new(ecb::Encryptor::new(key.into())))
      }
      "aes-256-ecb" => {
        if key.len() != 32 {
          return Err(CipherError::InvalidKeyLength);
        }
        if !iv.is_empty() {
          return Err(CipherError::InvalidInitializationVector);
        }
        Aes256Ecb(Box::new(ecb::Encryptor::new(key.into())))
      }
      "aes-128-gcm" => {
        if key.len() != aes::Aes128::key_size() {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.is_empty() {
          return Err(CipherError::InvalidInitializationVector);
        }

        if let Some(tag_len) = auth_tag_length
          && !is_valid_gcm_tag_length(tag_len)
        {
          return Err(CipherError::InvalidAuthTag(tag_len));
        }

        let cipher =
          aead_gcm_stream::AesGcm::<aes::Aes128>::new(key.into(), iv);

        Aes128Gcm(Box::new(cipher), auth_tag_length)
      }
      "aes-128-ccm" => {
        if key.len() != 16 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.is_empty() {
          return Err(CipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ccm_tag_length(tag_len) {
          return Err(CipherError::InvalidAuthTag(tag_len));
        }
        Aes128Ccm(Box::new(
          OpenSslAeadCipher::new(
            unsafe { aws_lc_sys::EVP_aes_128_ccm() },
            key,
            iv,
            tag_len,
            true,
            OpenSslAeadMode::Ccm,
          )
          .map_err(map_cipher_init_error)?,
        ))
      }
      "aes-192-ccm" => {
        if key.len() != 24 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.is_empty() {
          return Err(CipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ccm_tag_length(tag_len) {
          return Err(CipherError::InvalidAuthTag(tag_len));
        }
        Aes192Ccm(Box::new(
          OpenSslAeadCipher::new(
            unsafe { aws_lc_sys::EVP_aes_192_ccm() },
            key,
            iv,
            tag_len,
            true,
            OpenSslAeadMode::Ccm,
          )
          .map_err(map_cipher_init_error)?,
        ))
      }
      "aes-256-ccm" => {
        if key.len() != 32 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.is_empty() {
          return Err(CipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ccm_tag_length(tag_len) {
          return Err(CipherError::InvalidAuthTag(tag_len));
        }
        Aes256Ccm(Box::new(
          OpenSslAeadCipher::new(
            unsafe { aws_lc_sys::EVP_aes_256_ccm() },
            key,
            iv,
            tag_len,
            true,
            OpenSslAeadMode::Ccm,
          )
          .map_err(map_cipher_init_error)?,
        ))
      }
      "aes-128-ocb" => {
        if key.len() != 16 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() < 6 || iv.len() > 15 {
          return Err(CipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ocb_tag_length(tag_len) {
          return Err(CipherError::InvalidAuthTag(tag_len));
        }
        Aes128Ocb(Box::new(RustOcbCipher::new(key, iv, tag_len)))
      }
      "aes-192-ocb" => {
        if key.len() != 24 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() < 6 || iv.len() > 15 {
          return Err(CipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ocb_tag_length(tag_len) {
          return Err(CipherError::InvalidAuthTag(tag_len));
        }
        Aes192Ocb(Box::new(RustOcbCipher::new(key, iv, tag_len)))
      }
      "aes-256-ocb" => {
        if key.len() != 32 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() < 6 || iv.len() > 15 {
          return Err(CipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ocb_tag_length(tag_len) {
          return Err(CipherError::InvalidAuthTag(tag_len));
        }
        Aes256Ocb(Box::new(RustOcbCipher::new(key, iv, tag_len)))
      }
      "aes-256-gcm" => {
        if key.len() != aes::Aes256::key_size() {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.is_empty() {
          return Err(CipherError::InvalidInitializationVector);
        }

        if let Some(tag_len) = auth_tag_length
          && !is_valid_gcm_tag_length(tag_len)
        {
          return Err(CipherError::InvalidAuthTag(tag_len));
        }

        let cipher =
          aead_gcm_stream::AesGcm::<aes::Aes256>::new(key.into(), iv);

        Aes256Gcm(Box::new(cipher), auth_tag_length)
      }
      "aes256" | "aes-256-cbc" => {
        if key.len() != 32 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(CipherError::InvalidInitializationVector);
        }

        Aes256Cbc(Box::new(cbc::Encryptor::new(key.into(), iv.into())))
      }
      "aes-256-ctr" => {
        if key.len() != 32 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(CipherError::InvalidInitializationVector);
        }
        Aes256Ctr(Box::new(ctr::Ctr128BE::new(key.into(), iv.into())))
      }
      "aes-192-ctr" => {
        if key.len() != 24 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(CipherError::InvalidInitializationVector);
        }
        Aes192Ctr(Box::new(ctr::Ctr128BE::new(key.into(), iv.into())))
      }
      "aes-128-ctr" => {
        if key.len() != 16 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(CipherError::InvalidInitializationVector);
        }
        Aes128Ctr(Box::new(ctr::Ctr128BE::new(key.into(), iv.into())))
      }
      "des-ede3-cbc" => {
        if key.len() != 24 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 8 {
          return Err(CipherError::InvalidInitializationVector);
        }
        DesEde3Cbc(Box::new(cbc::Encryptor::new(key.into(), iv.into())))
      }
      "aes128-wrap" | "id-aes128-wrap" => {
        if key.len() != 16 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 8 {
          return Err(CipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 8];
        iv_bytes.copy_from_slice(iv);
        Aes128Wrap(
          Box::new(aes::Aes128::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "aes192-wrap" | "id-aes192-wrap" => {
        if key.len() != 24 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 8 {
          return Err(CipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 8];
        iv_bytes.copy_from_slice(iv);
        Aes192Wrap(
          Box::new(aes::Aes192::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "aes256-wrap" | "id-aes256-wrap" => {
        if key.len() != 32 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 8 {
          return Err(CipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 8];
        iv_bytes.copy_from_slice(iv);
        Aes256Wrap(
          Box::new(aes::Aes256::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "id-aes128-wrap-pad" | "aes128-wrap-pad" => {
        if key.len() != 16 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 4 {
          return Err(CipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 4];
        iv_bytes.copy_from_slice(iv);
        Aes128WrapPad(
          Box::new(aes::Aes128::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "id-aes192-wrap-pad" | "aes192-wrap-pad" => {
        if key.len() != 24 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 4 {
          return Err(CipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 4];
        iv_bytes.copy_from_slice(iv);
        Aes192WrapPad(
          Box::new(aes::Aes192::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "id-aes256-wrap-pad" | "aes256-wrap-pad" => {
        if key.len() != 32 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 4 {
          return Err(CipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 4];
        iv_bytes.copy_from_slice(iv);
        Aes256WrapPad(
          Box::new(aes::Aes256::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "des3-wrap" => {
        if key.len() != 24 {
          return Err(CipherError::InvalidKeyLength);
        }
        if !iv.is_empty() {
          return Err(CipherError::InvalidInitializationVector);
        }
        Des3Wrap(key.to_vec())
      }
      "chacha20-poly1305" => {
        if key.len() != 32 {
          return Err(CipherError::InvalidKeyLength);
        }
        if iv.len() != 12 {
          return Err(CipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_chacha20_poly1305_tag_length(tag_len) {
          return Err(CipherError::InvalidAuthTag(tag_len));
        }
        ChaCha20Poly1305(Box::new(
          ChaCha20Poly1305Cipher::new(key, iv, tag_len, true).map_err(|e| {
            match e {
              CipherInitError::ContextAllocation => {
                panic!("Failed to allocate EVP_CIPHER_CTX")
              }
              CipherInitError::InitFailed => CipherError::InvalidKeyLength,
            }
          })?,
        ))
      }
      _ => return Err(CipherError::UnknownCipher(algorithm_name.to_string())),
    })
  }

  fn set_aad(&mut self, aad: &[u8], plaintext_length: Option<usize>) {
    use Cipher::*;
    match self {
      Aes128Gcm(cipher, _) => {
        cipher.set_aad(aad);
      }
      Aes256Gcm(cipher, _) => {
        cipher.set_aad(aad);
      }
      Aes128Ccm(cipher)
      | Aes192Ccm(cipher)
      | Aes256Ccm(cipher) => {
        cipher.set_aad(aad, plaintext_length);
      }
      Aes128Ocb(cipher) | Aes192Ocb(cipher) | Aes256Ocb(cipher) => {
        cipher.set_aad(aad, plaintext_length);
      }
      ChaCha20Poly1305(cipher) => {
        cipher.set_aad(aad);
      }
      _ => {}
    }
  }

  /// encrypt encrypts the data in the middle of the input.
  fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
    use Cipher::*;
    match self {
      Aes128Cbc(encryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          encryptor.encrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes128Ecb(encryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          encryptor.encrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes192Cbc(encryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          encryptor.encrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes192Ecb(encryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          encryptor.encrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes256Ecb(encryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          encryptor.encrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes128Gcm(cipher, _) => {
        output[..input.len()].copy_from_slice(input);
        cipher.encrypt(output);
      }
      Aes256Gcm(cipher, _) => {
        output[..input.len()].copy_from_slice(input);
        cipher.encrypt(output);
      }
      Aes128Ccm(cipher)
      | Aes192Ccm(cipher)
      | Aes256Ccm(cipher) => {
        cipher.encrypt(input, output).expect("AEAD encrypt failed");
      }
      Aes128Ocb(cipher) | Aes192Ocb(cipher) | Aes256Ocb(cipher) => {
        cipher.encrypt(input, output).expect("AEAD encrypt failed");
      }
      Aes256Cbc(encryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          encryptor.encrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes256Ctr(encryptor) => {
        encryptor.apply_keystream_b2b(input, output).unwrap();
      }
      Aes192Ctr(encryptor) => {
        encryptor.apply_keystream_b2b(input, output).unwrap();
      }
      Aes128Ctr(encryptor) => {
        encryptor.apply_keystream_b2b(input, output).unwrap();
      }
      DesEde3Cbc(encryptor) => {
        assert!(input.len().is_multiple_of(8));
        for (input, output) in input.chunks(8).zip(output.chunks_mut(8)) {
          encryptor.encrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes128Wrap(..)
      | Aes192Wrap(..)
      | Aes256Wrap(..)
      | Aes128WrapPad(..)
      | Aes192WrapPad(..)
      | Aes256WrapPad(..)
      | Des3Wrap(..) => {}
      ChaCha20Poly1305(cipher) => {
        cipher.encrypt(input, output);
      }
    }
  }

  /// r#final encrypts the last block of the input data.
  fn r#final(
    self,
    auto_pad: bool,
    input: &[u8],
    output: &mut [u8],
  ) -> Result<Tag, CipherError> {
    use Cipher::*;
    match (self, auto_pad) {
      (Aes128Cbc(encryptor), true) => {
        let _ = (*encryptor)
          .encrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| CipherError::CannotPadInputData)?;
        Ok(None)
      }
      (Aes128Cbc(mut encryptor), false) => {
        encryptor.encrypt_block_b2b_mut(
          GenericArray::from_slice(input),
          GenericArray::from_mut_slice(output),
        );
        Ok(None)
      }
      (Aes128Ecb(encryptor), true) => {
        let _ = (*encryptor)
          .encrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| CipherError::CannotPadInputData)?;
        Ok(None)
      }
      (Aes128Ecb(mut encryptor), false) => {
        encryptor.encrypt_block_b2b_mut(
          GenericArray::from_slice(input),
          GenericArray::from_mut_slice(output),
        );
        Ok(None)
      }
      (Aes192Cbc(encryptor), true) => {
        let _ = (*encryptor)
          .encrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| CipherError::CannotPadInputData)?;
        Ok(None)
      }
      (Aes192Cbc(mut encryptor), false) => {
        encryptor.encrypt_block_b2b_mut(
          GenericArray::from_slice(input),
          GenericArray::from_mut_slice(output),
        );
        Ok(None)
      }
      (Aes192Ecb(encryptor), true) => {
        let _ = (*encryptor)
          .encrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| CipherError::CannotPadInputData)?;
        Ok(None)
      }
      (Aes192Ecb(mut encryptor), false) => {
        encryptor.encrypt_block_b2b_mut(
          GenericArray::from_slice(input),
          GenericArray::from_mut_slice(output),
        );
        Ok(None)
      }
      (Aes256Ecb(encryptor), true) => {
        let _ = (*encryptor)
          .encrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| CipherError::CannotPadInputData)?;
        Ok(None)
      }
      (Aes256Ecb(mut encryptor), false) => {
        encryptor.encrypt_block_b2b_mut(
          GenericArray::from_slice(input),
          GenericArray::from_mut_slice(output),
        );
        Ok(None)
      }
      (Aes128Gcm(cipher, auth_tag_length), _) => {
        let mut tag = cipher.finish().to_vec();
        if let Some(tag_len) = auth_tag_length {
          tag.truncate(tag_len);
        }
        Ok(Some(tag))
      }
      (Aes128Ccm(mut cipher), _)
      | (Aes192Ccm(mut cipher), _)
      | (Aes256Ccm(mut cipher), _) => {
        cipher
          .encrypt(input, output)
          .map_err(map_cipher_init_error)?;
        let tag = cipher
          .compute_tag(Some(input.len()))
          .map_err(map_cipher_init_error)?;
        Ok(Some(tag))
      }
      (Aes128Ocb(mut cipher), _)
      | (Aes192Ocb(mut cipher), _)
      | (Aes256Ocb(mut cipher), _) => {
        if !input.is_empty() {
          cipher
            .encrypt(input, output)
            .map_err(map_cipher_init_error)?;
        }
        let tag = cipher
          .compute_tag(Some(input.len()))
          .map_err(map_cipher_init_error)?;
        Ok(Some(tag))
      }
      (Aes256Gcm(cipher, auth_tag_length), _) => {
        let mut tag = cipher.finish().to_vec();
        if let Some(tag_len) = auth_tag_length {
          tag.truncate(tag_len);
        }
        Ok(Some(tag))
      }
      (Aes256Cbc(encryptor), true) => {
        let _ = (*encryptor)
          .encrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| CipherError::CannotPadInputData)?;
        Ok(None)
      }
      (Aes256Cbc(mut encryptor), false) => {
        encryptor.encrypt_block_b2b_mut(
          GenericArray::from_slice(input),
          GenericArray::from_mut_slice(output),
        );
        Ok(None)
      }
      (Aes256Ctr(_) | Aes128Ctr(_) | Aes192Ctr(_), _) => Ok(None),
      (Aes128Wrap(cipher, iv), _) => {
        aes_key_wrap_encrypt(cipher.as_ref(), &iv, input, output)
          .map_err(|_| CipherError::InvalidDataSize)?;
        Ok(None)
      }
      (Aes192Wrap(cipher, iv), _) => {
        aes_key_wrap_encrypt(cipher.as_ref(), &iv, input, output)
          .map_err(|_| CipherError::InvalidDataSize)?;
        Ok(None)
      }
      (Aes256Wrap(cipher, iv), _) => {
        aes_key_wrap_encrypt(cipher.as_ref(), &iv, input, output)
          .map_err(|_| CipherError::InvalidDataSize)?;
        Ok(None)
      }
      (Aes128WrapPad(cipher, iv), _) => {
        aes_key_wrap_pad_encrypt(cipher.as_ref(), &iv, input, output)
          .map_err(|_| CipherError::InvalidDataSize)?;
        Ok(None)
      }
      (Aes192WrapPad(cipher, iv), _) => {
        aes_key_wrap_pad_encrypt(cipher.as_ref(), &iv, input, output)
          .map_err(|_| CipherError::InvalidDataSize)?;
        Ok(None)
      }
      (Aes256WrapPad(cipher, iv), _) => {
        aes_key_wrap_pad_encrypt(cipher.as_ref(), &iv, input, output)
          .map_err(|_| CipherError::InvalidDataSize)?;
        Ok(None)
      }
      (Des3Wrap(..), _) => Err(CipherError::InvalidDataSize),
      (ChaCha20Poly1305(cipher), _) => {
        let tag = cipher.compute_tag();
        Ok(Some(tag))
      }
      (DesEde3Cbc(encryptor), true) => {
        let _ = (*encryptor)
          .encrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| CipherError::CannotPadInputData)?;
        Ok(None)
      }
      (DesEde3Cbc(mut encryptor), false) => {
        encryptor.encrypt_block_b2b_mut(
          GenericArray::from_slice(input),
          GenericArray::from_mut_slice(output),
        );
        Ok(None)
      }
    }
  }

  fn final_key_wrap(self, input: &[u8]) -> Result<Vec<u8>, CipherError> {
    use Cipher::*;
    match self {
      Aes128Wrap(cipher, iv) => {
        let mut output = vec![0u8; input.len() + 8];
        aes_key_wrap_encrypt(cipher.as_ref(), &iv, input, &mut output)
          .map_err(|_| CipherError::InvalidDataSize)?;
        Ok(output)
      }
      Aes192Wrap(cipher, iv) => {
        let mut output = vec![0u8; input.len() + 8];
        aes_key_wrap_encrypt(cipher.as_ref(), &iv, input, &mut output)
          .map_err(|_| CipherError::InvalidDataSize)?;
        Ok(output)
      }
      Aes256Wrap(cipher, iv) => {
        let mut output = vec![0u8; input.len() + 8];
        aes_key_wrap_encrypt(cipher.as_ref(), &iv, input, &mut output)
          .map_err(|_| CipherError::InvalidDataSize)?;
        Ok(output)
      }
      Aes128WrapPad(cipher, iv) => {
        let padded_len = (input.len() + 7) & !7;
        let output_len = if input.len() <= 8 { 16 } else { padded_len + 8 };
        let mut output = vec![0u8; output_len];
        let output_len =
          aes_key_wrap_pad_encrypt(cipher.as_ref(), &iv, input, &mut output)
            .map_err(|_| CipherError::InvalidDataSize)?;
        output.truncate(output_len);
        Ok(output)
      }
      Aes192WrapPad(cipher, iv) => {
        let padded_len = (input.len() + 7) & !7;
        let output_len = if input.len() <= 8 { 16 } else { padded_len + 8 };
        let mut output = vec![0u8; output_len];
        let output_len =
          aes_key_wrap_pad_encrypt(cipher.as_ref(), &iv, input, &mut output)
            .map_err(|_| CipherError::InvalidDataSize)?;
        output.truncate(output_len);
        Ok(output)
      }
      Aes256WrapPad(cipher, iv) => {
        let padded_len = (input.len() + 7) & !7;
        let output_len = if input.len() <= 8 { 16 } else { padded_len + 8 };
        let mut output = vec![0u8; output_len];
        let output_len =
          aes_key_wrap_pad_encrypt(cipher.as_ref(), &iv, input, &mut output)
            .map_err(|_| CipherError::InvalidDataSize)?;
        output.truncate(output_len);
        Ok(output)
      }
      Des3Wrap(key) => tdes_wrap_encrypt(&key, input)
        .map_err(|_| CipherError::InvalidDataSize),
      _ => Err(CipherError::InvalidDataSize),
    }
  }

  fn take_tag(self) -> Tag {
    use Cipher::*;
    match self {
      Aes128Gcm(cipher, auth_tag_length) => {
        let mut tag = cipher.finish().to_vec();
        if let Some(tag_len) = auth_tag_length {
          tag.truncate(tag_len);
        }
        Some(tag)
      }
      Aes256Gcm(cipher, auth_tag_length) => {
        let mut tag = cipher.finish().to_vec();
        if let Some(tag_len) = auth_tag_length {
          tag.truncate(tag_len);
        }
        Some(tag)
      }
      ChaCha20Poly1305(cipher) => {
        let tag = cipher.compute_tag();
        Some(tag)
      }
      _ => None,
    }
  }
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
#[property("library" = "Provider routines")]
#[property("reason" = self.reason())]
#[property("code" = self.code())]
pub enum DecipherError {
  #[class(type)]
  #[error("IV length must be 12 bytes")]
  InvalidIvLength,
  #[class(range)]
  #[error("Invalid key length")]
  InvalidKeyLength,
  #[class(range)]
  #[error("Invalid AES key wrap data size")]
  InvalidDataSize,
  #[class(type)]
  #[error("Invalid authentication tag length: {0}")]
  InvalidAuthTag(usize),
  #[class(range)]
  #[error("error:1C80006B:Provider routines::wrong final block length")]
  InvalidFinalBlockLength,
  #[class(type)]
  #[error("Invalid initialization vector")]
  InvalidInitializationVector,
  #[class(type)]
  #[error("error:1C800064:Provider routines::bad decrypt")]
  CannotUnpadInputData,
  #[class(type)]
  #[error("Unsupported state or unable to authenticate data")]
  DataAuthenticationFailed,
  #[class(type)]
  #[error("Unknown cipher {0}")]
  UnknownCipher(String),
}

impl DecipherError {
  fn code(&self) -> deno_error::PropertyValue {
    match self {
      Self::InvalidIvLength => {
        deno_error::PropertyValue::String("ERR_CRYPTO_INVALID_IV_LENGTH".into())
      }
      Self::InvalidKeyLength => deno_error::PropertyValue::String(
        "ERR_CRYPTO_INVALID_KEY_LENGTH".into(),
      ),
      Self::InvalidAuthTag(_) => {
        deno_error::PropertyValue::String("ERR_CRYPTO_INVALID_AUTH_TAG".into())
      }
      Self::InvalidFinalBlockLength => deno_error::PropertyValue::String(
        "ERR_OSSL_WRONG_FINAL_BLOCK_LENGTH".into(),
      ),
      Self::CannotUnpadInputData => {
        deno_error::PropertyValue::String("ERR_OSSL_BAD_DECRYPT".into())
      }
      _ => deno_error::PropertyValue::String("ERR_CRYPTO_DECIPHER".into()),
    }
  }

  fn reason(&self) -> deno_error::PropertyValue {
    match self {
      Self::InvalidFinalBlockLength => {
        deno_error::PropertyValue::String("wrong final block length".into())
      }
      Self::CannotUnpadInputData => {
        deno_error::PropertyValue::String("bad decrypt".into())
      }
      _ => deno_error::PropertyValue::String(self.get_message()),
    }
  }
}

macro_rules! assert_block_len {
  ($input:expr, $len:expr) => {
    if $input != $len {
      return Err(DecipherError::InvalidFinalBlockLength);
    }
  };
}

fn is_valid_gcm_tag_length(tag_len: usize) -> bool {
  tag_len == 4 || tag_len == 8 || (12..=16).contains(&tag_len)
}

impl Decipher {
  fn new(
    algorithm_name: &str,
    key: &[u8],
    iv: &[u8],
    auth_tag_length: Option<usize>,
  ) -> Result<Self, DecipherError> {
    use Decipher::*;
    Ok(match algorithm_name {
      "aes-128-cbc" => {
        if key.len() != 16 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        Aes128Cbc(Box::new(cbc::Decryptor::new(key.into(), iv.into())))
      }
      "aes-128-ecb" => {
        if key.len() != 16 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if !iv.is_empty() {
          return Err(DecipherError::InvalidInitializationVector);
        }
        Aes128Ecb(Box::new(ecb::Decryptor::new(key.into())))
      }
      "aes192" | "aes-192-cbc" => {
        if key.len() != 24 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        Aes192Cbc(Box::new(cbc::Decryptor::new(key.into(), iv.into())))
      }
      "aes-192-ecb" => {
        if key.len() != 24 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if !iv.is_empty() {
          return Err(DecipherError::InvalidInitializationVector);
        }
        Aes192Ecb(Box::new(ecb::Decryptor::new(key.into())))
      }
      "aes-256-ecb" => {
        if key.len() != 32 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if !iv.is_empty() {
          return Err(DecipherError::InvalidInitializationVector);
        }
        Aes256Ecb(Box::new(ecb::Decryptor::new(key.into())))
      }
      "aes-128-gcm" => {
        if key.len() != aes::Aes128::key_size() {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.is_empty() {
          return Err(DecipherError::InvalidInitializationVector);
        }

        if let Some(tag_len) = auth_tag_length
          && !is_valid_gcm_tag_length(tag_len)
        {
          return Err(DecipherError::InvalidAuthTag(tag_len));
        }

        let decipher =
          aead_gcm_stream::AesGcm::<aes::Aes128>::new(key.into(), iv);

        Aes128Gcm(Box::new(decipher), auth_tag_length)
      }
      "aes-128-ccm" => {
        if key.len() != 16 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.is_empty() {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ccm_tag_length(tag_len) {
          return Err(DecipherError::InvalidAuthTag(tag_len));
        }
        Aes128Ccm(Box::new(
          OpenSslAeadCipher::new(
            unsafe { aws_lc_sys::EVP_aes_128_ccm() },
            key,
            iv,
            tag_len,
            false,
            OpenSslAeadMode::Ccm,
          )
          .map_err(map_decipher_init_error)?,
        ))
      }
      "aes-192-ccm" => {
        if key.len() != 24 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.is_empty() {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ccm_tag_length(tag_len) {
          return Err(DecipherError::InvalidAuthTag(tag_len));
        }
        Aes192Ccm(Box::new(
          OpenSslAeadCipher::new(
            unsafe { aws_lc_sys::EVP_aes_192_ccm() },
            key,
            iv,
            tag_len,
            false,
            OpenSslAeadMode::Ccm,
          )
          .map_err(map_decipher_init_error)?,
        ))
      }
      "aes-256-ccm" => {
        if key.len() != 32 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.is_empty() {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ccm_tag_length(tag_len) {
          return Err(DecipherError::InvalidAuthTag(tag_len));
        }
        Aes256Ccm(Box::new(
          OpenSslAeadCipher::new(
            unsafe { aws_lc_sys::EVP_aes_256_ccm() },
            key,
            iv,
            tag_len,
            false,
            OpenSslAeadMode::Ccm,
          )
          .map_err(map_decipher_init_error)?,
        ))
      }
      "aes-128-ocb" => {
        if key.len() != 16 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() < 6 || iv.len() > 15 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ocb_tag_length(tag_len) {
          return Err(DecipherError::InvalidAuthTag(tag_len));
        }
        Aes128Ocb(Box::new(RustOcbCipher::new(key, iv, tag_len)))
      }
      "aes-192-ocb" => {
        if key.len() != 24 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() < 6 || iv.len() > 15 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ocb_tag_length(tag_len) {
          return Err(DecipherError::InvalidAuthTag(tag_len));
        }
        Aes192Ocb(Box::new(RustOcbCipher::new(key, iv, tag_len)))
      }
      "aes-256-ocb" => {
        if key.len() != 32 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() < 6 || iv.len() > 15 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_ocb_tag_length(tag_len) {
          return Err(DecipherError::InvalidAuthTag(tag_len));
        }
        Aes256Ocb(Box::new(RustOcbCipher::new(key, iv, tag_len)))
      }
      "aes-256-gcm" => {
        if key.len() != aes::Aes256::key_size() {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.is_empty() {
          return Err(DecipherError::InvalidInitializationVector);
        }

        if let Some(tag_len) = auth_tag_length
          && !is_valid_gcm_tag_length(tag_len)
        {
          return Err(DecipherError::InvalidAuthTag(tag_len));
        }

        let decipher =
          aead_gcm_stream::AesGcm::<aes::Aes256>::new(key.into(), iv);

        Aes256Gcm(Box::new(decipher), auth_tag_length)
      }
      "aes256" | "aes-256-cbc" => {
        if key.len() != 32 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(DecipherError::InvalidInitializationVector);
        }

        Aes256Cbc(Box::new(cbc::Decryptor::new(key.into(), iv.into())))
      }
      "aes-256-ctr" => {
        if key.len() != 32 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        Aes256Ctr(Box::new(ctr::Ctr128BE::new(key.into(), iv.into())))
      }
      "aes-192-ctr" => {
        if key.len() != 24 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        Aes192Ctr(Box::new(ctr::Ctr128BE::new(key.into(), iv.into())))
      }
      "aes-128-ctr" => {
        if key.len() != 16 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 16 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        Aes128Ctr(Box::new(ctr::Ctr128BE::new(key.into(), iv.into())))
      }
      "des-ede3-cbc" => {
        if key.len() != 24 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 8 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        DesEde3Cbc(Box::new(cbc::Decryptor::new(key.into(), iv.into())))
      }
      "aes128-wrap" | "id-aes128-wrap" => {
        if key.len() != 16 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 8 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 8];
        iv_bytes.copy_from_slice(iv);
        Aes128Wrap(
          Box::new(aes::Aes128::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "aes192-wrap" | "id-aes192-wrap" => {
        if key.len() != 24 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 8 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 8];
        iv_bytes.copy_from_slice(iv);
        Aes192Wrap(
          Box::new(aes::Aes192::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "aes256-wrap" | "id-aes256-wrap" => {
        if key.len() != 32 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 8 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 8];
        iv_bytes.copy_from_slice(iv);
        Aes256Wrap(
          Box::new(aes::Aes256::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "id-aes128-wrap-pad" | "aes128-wrap-pad" => {
        if key.len() != 16 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 4 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 4];
        iv_bytes.copy_from_slice(iv);
        Aes128WrapPad(
          Box::new(aes::Aes128::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "id-aes192-wrap-pad" | "aes192-wrap-pad" => {
        if key.len() != 24 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 4 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 4];
        iv_bytes.copy_from_slice(iv);
        Aes192WrapPad(
          Box::new(aes::Aes192::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "id-aes256-wrap-pad" | "aes256-wrap-pad" => {
        if key.len() != 32 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 4 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let mut iv_bytes = [0u8; 4];
        iv_bytes.copy_from_slice(iv);
        Aes256WrapPad(
          Box::new(aes::Aes256::new(GenericArray::from_slice(key))),
          iv_bytes,
        )
      }
      "des3-wrap" => {
        if key.len() != 24 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if !iv.is_empty() {
          return Err(DecipherError::InvalidInitializationVector);
        }
        Des3Wrap(key.to_vec())
      }
      "chacha20-poly1305" => {
        if key.len() != 32 {
          return Err(DecipherError::InvalidKeyLength);
        }
        if iv.len() != 12 {
          return Err(DecipherError::InvalidInitializationVector);
        }
        let tag_len = auth_tag_length.unwrap_or(16);
        if !is_valid_chacha20_poly1305_tag_length(tag_len) {
          return Err(DecipherError::InvalidAuthTag(tag_len));
        }
        ChaCha20Poly1305(
          Box::new(
            ChaCha20Poly1305Cipher::new(key, iv, tag_len, false).map_err(
              |e| match e {
                CipherInitError::ContextAllocation => {
                  panic!("Failed to allocate EVP_CIPHER_CTX")
                }
                CipherInitError::InitFailed => DecipherError::InvalidKeyLength,
              },
            )?,
          ),
          auth_tag_length,
        )
      }
      _ => {
        return Err(DecipherError::UnknownCipher(algorithm_name.to_string()));
      }
    })
  }

  fn validate_auth_tag(&self, length: usize) -> Result<(), DecipherError> {
    match self {
      Decipher::Aes128Gcm(_, Some(tag_len))
      | Decipher::Aes256Gcm(_, Some(tag_len)) => {
        if *tag_len != length {
          return Err(DecipherError::InvalidAuthTag(length));
        }
      }
      Decipher::Aes128Gcm(_, None) | Decipher::Aes256Gcm(_, None) => {
        if !is_valid_gcm_tag_length(length) {
          return Err(DecipherError::InvalidAuthTag(length));
        }
      }
      Decipher::ChaCha20Poly1305(_, Some(tag_len)) => {
        if *tag_len != length {
          return Err(DecipherError::InvalidAuthTag(length));
        }
      }
      Decipher::ChaCha20Poly1305(_, None) => {
        // Default tag length is 16; reject anything else
        if length != 16 {
          return Err(DecipherError::InvalidAuthTag(length));
        }
      }
      Decipher::Aes128Ccm(cipher)
      | Decipher::Aes192Ccm(cipher)
      | Decipher::Aes256Ccm(cipher) => {
        if length != cipher.auth_tag_length {
          return Err(DecipherError::InvalidAuthTag(length));
        }
      }
      Decipher::Aes128Ocb(cipher)
      | Decipher::Aes192Ocb(cipher)
      | Decipher::Aes256Ocb(cipher) => {
        if length != cipher.auth_tag_length {
          return Err(DecipherError::InvalidAuthTag(length));
        }
      }
      _ => {}
    }
    Ok(())
  }

  fn set_aad(&mut self, aad: &[u8], plaintext_length: Option<usize>) {
    use Decipher::*;
    match self {
      Aes128Gcm(decipher, _) => {
        decipher.set_aad(aad);
      }
      Aes256Gcm(decipher, _) => {
        decipher.set_aad(aad);
      }
      Aes128Ccm(decipher)
      | Aes192Ccm(decipher)
      | Aes256Ccm(decipher) => {
        decipher.set_aad(aad, plaintext_length);
      }
      Aes128Ocb(decipher) | Aes192Ocb(decipher) | Aes256Ocb(decipher) => {
        decipher.set_aad(aad, plaintext_length);
      }
      ChaCha20Poly1305(decipher, _) => {
        decipher.set_aad(aad);
      }
      _ => {}
    }
  }

  /// decrypt decrypts the data in the middle of the input.
  fn decrypt(&mut self, input: &[u8], output: &mut [u8]) {
    use Decipher::*;
    match self {
      Aes128Cbc(decryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          decryptor.decrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes128Ecb(decryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          decryptor.decrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes192Cbc(decryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          decryptor.decrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes192Ecb(decryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          decryptor.decrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes256Ecb(decryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          decryptor.decrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes128Gcm(decipher, _) => {
        output[..input.len()].copy_from_slice(input);
        decipher.decrypt(output);
      }
      Aes256Gcm(decipher, _) => {
        output[..input.len()].copy_from_slice(input);
        decipher.decrypt(output);
      }
      Aes128Ccm(decipher)
      | Aes192Ccm(decipher)
      | Aes256Ccm(decipher) => {
        decipher.decrypt(input, output).expect("AEAD decrypt failed");
      }
      Aes128Ocb(..) | Aes192Ocb(..) | Aes256Ocb(..) => {}
      Aes256Cbc(decryptor) => {
        assert!(input.len().is_multiple_of(16));
        for (input, output) in input.chunks(16).zip(output.chunks_mut(16)) {
          decryptor.decrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes256Ctr(decryptor) => {
        decryptor.apply_keystream_b2b(input, output).unwrap();
      }
      Aes192Ctr(decryptor) => {
        decryptor.apply_keystream_b2b(input, output).unwrap();
      }
      Aes128Ctr(decryptor) => {
        decryptor.apply_keystream_b2b(input, output).unwrap();
      }
      DesEde3Cbc(decryptor) => {
        assert!(input.len().is_multiple_of(8));
        for (input, output) in input.chunks(8).zip(output.chunks_mut(8)) {
          decryptor.decrypt_block_b2b_mut(input.into(), output.into());
        }
      }
      Aes128Wrap(..)
      | Aes192Wrap(..)
      | Aes256Wrap(..)
      | Aes128WrapPad(..)
      | Aes192WrapPad(..)
      | Aes256WrapPad(..)
      | Des3Wrap(..) => {}
      ChaCha20Poly1305(decipher, _) => {
        decipher.decrypt(input, output);
      }
    }
  }

  /// r#final decrypts the last block of the input data.
  fn r#final(
    self,
    auto_pad: bool,
    input: &[u8],
    output: &mut [u8],
    auth_tag: &[u8],
  ) -> Result<(), DecipherError> {
    use Decipher::*;

    if input.is_empty()
      && !matches!(
        self,
        Aes128Ecb(..)
          | Aes192Cbc(..)
          | Aes192Ecb(..)
          | Aes256Ecb(..)
          | Aes128Gcm(..)
          | Aes128Ccm(..)
          | Aes192Ccm(..)
          | Aes256Ccm(..)
          | Aes128Ocb(..)
          | Aes192Ocb(..)
          | Aes256Ocb(..)
          | Aes256Gcm(..)
          | ChaCha20Poly1305(..)
      )
    {
      return Ok(());
    }

    match (self, auto_pad) {
      (Aes128Cbc(decryptor), true) => {
        assert_block_len!(input.len(), 16);
        let _ = (*decryptor)
          .decrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| DecipherError::CannotUnpadInputData)?;
        Ok(())
      }
      (Aes128Cbc(mut decryptor), false) => {
        if !input.is_empty() {
          assert_block_len!(input.len(), 16);
          decryptor.decrypt_block_b2b_mut(
            GenericArray::from_slice(input),
            GenericArray::from_mut_slice(output),
          );
        }
        Ok(())
      }
      (Aes128Ecb(decryptor), true) => {
        assert_block_len!(input.len(), 16);
        let _ = (*decryptor)
          .decrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| DecipherError::CannotUnpadInputData)?;
        Ok(())
      }
      (Aes128Ecb(mut decryptor), false) => {
        if !input.is_empty() {
          assert_block_len!(input.len(), 16);
          decryptor.decrypt_block_b2b_mut(
            GenericArray::from_slice(input),
            GenericArray::from_mut_slice(output),
          );
        }
        Ok(())
      }
      (Aes192Cbc(decryptor), true) => {
        assert_block_len!(input.len(), 16);
        let _ = (*decryptor)
          .decrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| DecipherError::CannotUnpadInputData)?;
        Ok(())
      }
      (Aes192Cbc(mut decryptor), false) => {
        if !input.is_empty() {
          assert_block_len!(input.len(), 16);
          decryptor.decrypt_block_b2b_mut(
            GenericArray::from_slice(input),
            GenericArray::from_mut_slice(output),
          );
        }
        Ok(())
      }
      (Aes192Ecb(decryptor), true) => {
        assert_block_len!(input.len(), 16);
        let _ = (*decryptor)
          .decrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| DecipherError::CannotUnpadInputData)?;
        Ok(())
      }
      (Aes192Ecb(mut decryptor), false) => {
        if !input.is_empty() {
          assert_block_len!(input.len(), 16);
          decryptor.decrypt_block_b2b_mut(
            GenericArray::from_slice(input),
            GenericArray::from_mut_slice(output),
          );
        }
        Ok(())
      }
      (Aes256Ecb(decryptor), true) => {
        assert_block_len!(input.len(), 16);
        let _ = (*decryptor)
          .decrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| DecipherError::CannotUnpadInputData)?;
        Ok(())
      }
      (Aes256Ecb(mut decryptor), false) => {
        if !input.is_empty() {
          assert_block_len!(input.len(), 16);
          decryptor.decrypt_block_b2b_mut(
            GenericArray::from_slice(input),
            GenericArray::from_mut_slice(output),
          );
        }
        Ok(())
      }
      (Aes128Gcm(decipher, auth_tag_length), _) => {
        let tag = decipher.finish();
        let tag_slice = tag.as_slice();
        let truncated_tag = if let Some(len) = auth_tag_length {
          &tag_slice[..len]
        } else {
          tag_slice
        };
        if truncated_tag.ct_eq(auth_tag).into() {
          Ok(())
        } else {
          Err(DecipherError::DataAuthenticationFailed)
        }
      }
      (Aes256Gcm(decipher, auth_tag_length), _) => {
        let tag = decipher.finish();
        let tag_slice = tag.as_slice();
        let truncated_tag = if let Some(len) = auth_tag_length {
          &tag_slice[..len]
        } else {
          tag_slice
        };
        if truncated_tag.ct_eq(auth_tag).into() {
          Ok(())
        } else {
          Err(DecipherError::DataAuthenticationFailed)
        }
      }
      (Aes128Ccm(decipher), _)
      | (Aes192Ccm(decipher), _)
      | (Aes256Ccm(decipher), _) => {
        if auth_tag.is_empty() {
          return Err(DecipherError::DataAuthenticationFailed);
        }
        let verified = decipher
          .decrypt_and_verify(input, output, auth_tag)
          .map_err(map_decipher_init_error)?;
        if verified {
          Ok(())
        } else {
          Err(DecipherError::DataAuthenticationFailed)
        }
      }
      (Aes128Ocb(mut decipher), _)
      | (Aes192Ocb(mut decipher), _)
      | (Aes256Ocb(mut decipher), _) => {
        if auth_tag.is_empty() {
          return Err(DecipherError::DataAuthenticationFailed);
        }
        let verified = decipher
          .decrypt_and_verify(input, output, auth_tag)
          .map_err(map_decipher_init_error)?;
        if verified {
          Ok(())
        } else {
          Err(DecipherError::DataAuthenticationFailed)
        }
      }
      (ChaCha20Poly1305(decipher, _), _) => {
        if auth_tag.is_empty() {
          return Err(DecipherError::DataAuthenticationFailed);
        }
        if decipher.verify_tag(auth_tag) {
          Ok(())
        } else {
          Err(DecipherError::DataAuthenticationFailed)
        }
      }
      (Aes256Cbc(decryptor), true) => {
        assert_block_len!(input.len(), 16);
        let _ = (*decryptor)
          .decrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| DecipherError::CannotUnpadInputData)?;
        Ok(())
      }
      (Aes256Cbc(mut decryptor), false) => {
        if !input.is_empty() {
          assert_block_len!(input.len(), 16);
          decryptor.decrypt_block_b2b_mut(
            GenericArray::from_slice(input),
            GenericArray::from_mut_slice(output),
          );
        }
        Ok(())
      }
      (Aes256Ctr(mut decryptor), _) => {
        decryptor.apply_keystream_b2b(input, output).unwrap();
        Ok(())
      }
      (Aes192Ctr(mut decryptor), _) => {
        decryptor.apply_keystream_b2b(input, output).unwrap();
        Ok(())
      }
      (Aes128Ctr(mut decryptor), _) => {
        decryptor.apply_keystream_b2b(input, output).unwrap();
        Ok(())
      }
      (Aes128Wrap(cipher, iv), _) => aes_key_wrap_decrypt(
        cipher.as_ref(),
        &iv,
        input,
        output,
      )
      .map_err(|error| match error {
        AesKeyWrapError::IntegrityCheckFailed => {
          DecipherError::DataAuthenticationFailed
        }
        _ => DecipherError::InvalidDataSize,
      }),
      (Aes192Wrap(cipher, iv), _) => aes_key_wrap_decrypt(
        cipher.as_ref(),
        &iv,
        input,
        output,
      )
      .map_err(|error| match error {
        AesKeyWrapError::IntegrityCheckFailed => {
          DecipherError::DataAuthenticationFailed
        }
        _ => DecipherError::InvalidDataSize,
      }),
      (Aes256Wrap(cipher, iv), _) => aes_key_wrap_decrypt(
        cipher.as_ref(),
        &iv,
        input,
        output,
      )
      .map_err(|error| match error {
        AesKeyWrapError::IntegrityCheckFailed => {
          DecipherError::DataAuthenticationFailed
        }
        _ => DecipherError::InvalidDataSize,
      }),
      (Aes128WrapPad(cipher, iv), _) => {
        let output_len =
          aes_key_wrap_pad_decrypt(cipher.as_ref(), &iv, input, output)
            .map_err(|error| match error {
              AesKeyWrapError::IntegrityCheckFailed => {
                DecipherError::DataAuthenticationFailed
              }
              _ => DecipherError::InvalidDataSize,
            })?;
        output[output_len..].fill(0);
        Ok(())
      }
      (Aes192WrapPad(cipher, iv), _) => {
        let output_len =
          aes_key_wrap_pad_decrypt(cipher.as_ref(), &iv, input, output)
            .map_err(|error| match error {
              AesKeyWrapError::IntegrityCheckFailed => {
                DecipherError::DataAuthenticationFailed
              }
              _ => DecipherError::InvalidDataSize,
            })?;
        output[output_len..].fill(0);
        Ok(())
      }
      (Aes256WrapPad(cipher, iv), _) => {
        let output_len =
          aes_key_wrap_pad_decrypt(cipher.as_ref(), &iv, input, output)
            .map_err(|error| match error {
              AesKeyWrapError::IntegrityCheckFailed => {
                DecipherError::DataAuthenticationFailed
              }
              _ => DecipherError::InvalidDataSize,
            })?;
        output[output_len..].fill(0);
        Ok(())
      }
      (DesEde3Cbc(decryptor), true) => {
        assert_block_len!(input.len(), 8);
        let _ = (*decryptor)
          .decrypt_padded_b2b_mut::<Pkcs7>(input, output)
          .map_err(|_| DecipherError::CannotUnpadInputData)?;
        Ok(())
      }
      (DesEde3Cbc(mut decryptor), false) => {
        if !input.is_empty() {
          assert_block_len!(input.len(), 8);
          decryptor.decrypt_block_b2b_mut(
            GenericArray::from_slice(input),
            GenericArray::from_mut_slice(output),
          );
        }
        Ok(())
      }
      (Des3Wrap(..), _) => Err(DecipherError::InvalidDataSize),
    }
  }

  fn final_key_wrap(self, input: &[u8]) -> Result<Vec<u8>, DecipherError> {
    use Decipher::*;
    match self {
      Aes128Wrap(cipher, iv) => {
        let output_len =
          input.len().checked_sub(8).ok_or(DecipherError::InvalidDataSize)?;
        let mut output = vec![0u8; output_len];
        aes_key_wrap_decrypt(cipher.as_ref(), &iv, input, &mut output).map_err(
          |error| match error {
            AesKeyWrapError::IntegrityCheckFailed => {
              DecipherError::DataAuthenticationFailed
            }
            _ => DecipherError::InvalidDataSize,
          },
        )?;
        Ok(output)
      }
      Aes192Wrap(cipher, iv) => {
        let output_len =
          input.len().checked_sub(8).ok_or(DecipherError::InvalidDataSize)?;
        let mut output = vec![0u8; output_len];
        aes_key_wrap_decrypt(cipher.as_ref(), &iv, input, &mut output).map_err(
          |error| match error {
            AesKeyWrapError::IntegrityCheckFailed => {
              DecipherError::DataAuthenticationFailed
            }
            _ => DecipherError::InvalidDataSize,
          },
        )?;
        Ok(output)
      }
      Aes256Wrap(cipher, iv) => {
        let output_len =
          input.len().checked_sub(8).ok_or(DecipherError::InvalidDataSize)?;
        let mut output = vec![0u8; output_len];
        aes_key_wrap_decrypt(cipher.as_ref(), &iv, input, &mut output).map_err(
          |error| match error {
            AesKeyWrapError::IntegrityCheckFailed => {
              DecipherError::DataAuthenticationFailed
            }
            _ => DecipherError::InvalidDataSize,
          },
        )?;
        Ok(output)
      }
      Aes128WrapPad(cipher, iv) => {
        let mut output = vec![0u8; input.len()];
        let output_len =
          aes_key_wrap_pad_decrypt(cipher.as_ref(), &iv, input, &mut output)
            .map_err(|error| match error {
              AesKeyWrapError::IntegrityCheckFailed => {
                DecipherError::DataAuthenticationFailed
              }
              _ => DecipherError::InvalidDataSize,
            })?;
        output.truncate(output_len);
        Ok(output)
      }
      Aes192WrapPad(cipher, iv) => {
        let mut output = vec![0u8; input.len()];
        let output_len =
          aes_key_wrap_pad_decrypt(cipher.as_ref(), &iv, input, &mut output)
            .map_err(|error| match error {
              AesKeyWrapError::IntegrityCheckFailed => {
                DecipherError::DataAuthenticationFailed
              }
              _ => DecipherError::InvalidDataSize,
            })?;
        output.truncate(output_len);
        Ok(output)
      }
      Aes256WrapPad(cipher, iv) => {
        let mut output = vec![0u8; input.len()];
        let output_len =
          aes_key_wrap_pad_decrypt(cipher.as_ref(), &iv, input, &mut output)
            .map_err(|error| match error {
              AesKeyWrapError::IntegrityCheckFailed => {
                DecipherError::DataAuthenticationFailed
              }
              _ => DecipherError::InvalidDataSize,
            })?;
        output.truncate(output_len);
        Ok(output)
      }
      Des3Wrap(key) => tdes_wrap_decrypt(&key, input).map_err(|error| {
        match error {
          TdesWrapError::IntegrityCheckFailed => {
            DecipherError::DataAuthenticationFailed
          }
          TdesWrapError::InvalidDataSize => DecipherError::InvalidDataSize,
        }
      }),
      _ => Err(DecipherError::InvalidDataSize),
    }
  }
}
