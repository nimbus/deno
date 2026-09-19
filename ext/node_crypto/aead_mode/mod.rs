// Copyright 2018-2026 the Deno authors. MIT license.

//! AES-CCM and AES-OCB for `createCipheriv` and `createDecipheriv`.
//!
//! The state rules follow Node.js `CipherBase` (`src/crypto/crypto_cipher.cc`)
//! over the OpenSSL 3.0 providers in `ccm` and `ocb`: the authentication tag
//! state (unknown, known, passed to the provider), the CCM message length
//! limit, the CCM decipher that reports authentication failure at final, and
//! the tag that `getAuthTag` returns after final.

mod aes_block;
mod ccm;
mod ocb;

use std::borrow::Cow;
use std::cell::RefCell;

use deno_core::OpState;
use deno_core::Resource;
use deno_core::convert::Uint8Array;
use deno_core::op2;

use self::aes_block::AesBlock;
use self::ccm::CcmGetTagError;
use self::ccm::CcmProvider;
use self::ocb::OcbProvider;

/// Node.js `kNoAuthTagLength`.
const NO_AUTH_TAG_LENGTH: u32 = u32::MAX;

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum AeadModeError {
  #[class(type)]
  #[property("code" = "ERR_CRYPTO_UNKNOWN_CIPHER")]
  #[error("Unknown cipher")]
  UnknownCipher,
  #[class(type)]
  #[property("code" = "ERR_CRYPTO_INVALID_IV")]
  #[error("Invalid initialization vector")]
  InvalidIv,
  #[class(type)]
  #[property("code" = "ERR_CRYPTO_INVALID_AUTH_TAG")]
  #[error("authTagLength required for {0}")]
  AuthTagLengthRequired(String),
  #[class(type)]
  #[property("code" = "ERR_CRYPTO_INVALID_AUTH_TAG")]
  #[error("Invalid authentication tag length: {0}")]
  InvalidAuthTagLength(u32),
  #[class(range)]
  #[property("code" = "ERR_CRYPTO_INVALID_KEYLEN")]
  #[error("Invalid key length")]
  InvalidKeyLength,
  #[class(type)]
  #[property("code" = "ERR_MISSING_ARGS")]
  #[error("options.plaintextLength required for CCM mode with AAD")]
  MissingPlaintextLength,
  #[class(range)]
  #[property("code" = "ERR_CRYPTO_INVALID_MESSAGELEN")]
  #[error("Invalid message length")]
  InvalidMessageLength,
  /// `CipherBase::Update` failed and the OpenSSL error queue is empty.
  #[class(generic)]
  #[error("Trying to add data in unsupported state")]
  UnsupportedState,
  /// `CipherBase::Final` failed and the OpenSSL error queue is empty.
  #[class(generic)]
  #[error("Unsupported state or unable to authenticate data")]
  AuthenticationFailed,
  /// `CipherBase::Final` failed with `PROV_R_TAG_NOT_SET` in the queue.
  #[class(generic)]
  #[property("code" = "ERR_OSSL_TAG_NOT_SET")]
  #[property("library" = "Provider routines")]
  #[property("reason" = "tag not set")]
  #[error("error:1C800077:Provider routines::tag not set")]
  TagNotSet,
  #[class(inherit)]
  #[error(transparent)]
  Resource(#[from] deno_core::error::ResourceError),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
  Ccm,
  Ocb,
}

/// Returns the mode and key length for a cipher name, which OpenSSL matches
/// without regard to case.
fn lookup(algorithm: &str) -> Option<(Mode, usize)> {
  Some(match algorithm.to_ascii_lowercase().as_str() {
    "aes-128-ccm" | "id-aes128-ccm" => (Mode::Ccm, 16),
    "aes-192-ccm" | "id-aes192-ccm" => (Mode::Ccm, 24),
    "aes-256-ccm" | "id-aes256-ccm" => (Mode::Ccm, 32),
    "aes-128-ocb" => (Mode::Ocb, 16),
    "aes-192-ocb" => (Mode::Ocb, 24),
    "aes-256-ocb" => (Mode::Ocb, 32),
    _ => return None,
  })
}

enum Provider {
  Ccm(CcmProvider),
  Ocb(OcbProvider),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthTagState {
  Unknown,
  Known,
  PassedToProvider,
}

/// The state of one Node.js `CipherBase` in CCM or OCB mode, until final.
pub struct AeadModeContext {
  encrypt: bool,
  provider: Provider,
  auth_tag_len: usize,
  auth_tag: [u8; 16],
  auth_tag_state: AuthTagState,
  pending_auth_failed: bool,
  max_message_size: u64,
}

impl AeadModeContext {
  /// `CipherBase::InitIv` and `CipherBase::CommonInit`.
  pub fn new(
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    auth_tag_len: u32,
    encrypt: bool,
  ) -> Result<Self, AeadModeError> {
    let (mode, key_len) =
      lookup(algorithm).ok_or(AeadModeError::UnknownCipher)?;
    if iv.is_empty() {
      return Err(AeadModeError::InvalidIv);
    }
    // EVP_CTRL_AEAD_SET_IVLEN.
    let iv_valid = match mode {
      Mode::Ccm => (7..=13).contains(&iv.len()),
      Mode::Ocb => (1..=15).contains(&iv.len()),
    };
    if !iv_valid {
      return Err(AeadModeError::InvalidIv);
    }
    if auth_tag_len == NO_AUTH_TAG_LENGTH {
      return Err(AeadModeError::AuthTagLengthRequired(algorithm.to_string()));
    }
    // EVP_CTRL_AEAD_SET_TAG without data.
    let tag_valid = match mode {
      Mode::Ccm => {
        auth_tag_len.is_multiple_of(2) && (4..=16).contains(&auth_tag_len)
      }
      Mode::Ocb => auth_tag_len <= 16,
    };
    if !tag_valid {
      return Err(AeadModeError::InvalidAuthTagLength(auth_tag_len));
    }
    let auth_tag_len = auth_tag_len as usize;
    let max_message_size = match iv.len() {
      12 => 16777215,
      13 => 65535,
      _ => i32::MAX as u64,
    };
    // EVP_CIPHER_CTX_set_key_length.
    if key.len() != key_len {
      return Err(AeadModeError::InvalidKeyLength);
    }
    let block = AesBlock::new(key).ok_or(AeadModeError::InvalidKeyLength)?;
    let provider = match mode {
      Mode::Ccm => Provider::Ccm(
        CcmProvider::new(block, encrypt, iv, auth_tag_len)
          .map_err(|_| AeadModeError::InvalidIv)?,
      ),
      Mode::Ocb => Provider::Ocb(
        OcbProvider::new(block, encrypt, iv, auth_tag_len)
          .map_err(|_| AeadModeError::InvalidIv)?,
      ),
    };
    Ok(Self {
      encrypt,
      provider,
      auth_tag_len,
      auth_tag: [0u8; 16],
      auth_tag_state: AuthTagState::Unknown,
      pending_auth_failed: false,
      max_message_size,
    })
  }

  /// `CipherBase::MaybePassAuthTagToOpenSSL`.
  fn maybe_pass_auth_tag(&mut self) -> bool {
    if self.auth_tag_state == AuthTagState::Known {
      let tag = &self.auth_tag[..self.auth_tag_len];
      let passed = match &mut self.provider {
        Provider::Ccm(p) => p.set_tag(tag),
        Provider::Ocb(p) => p.set_tag(tag),
      };
      if !passed {
        return false;
      }
      self.auth_tag_state = AuthTagState::PassedToProvider;
    }
    true
  }

  /// `CipherBase::CheckCCMMessageLength`.
  fn check_ccm_message_length(&self, len: u64) -> Result<(), AeadModeError> {
    if len > self.max_message_size {
      return Err(AeadModeError::InvalidMessageLength);
    }
    Ok(())
  }

  /// `CipherBase::SetAAD`. `Ok(false)` is the state failure that JavaScript
  /// reports as `ERR_CRYPTO_INVALID_STATE`.
  ///
  /// Node.js reads `plaintextLength` as an `Int32` and aborts the process for
  /// a larger value. A larger value here exceeds every CCM message limit, so
  /// it fails the length check instead.
  pub fn set_aad(
    &mut self,
    aad: &[u8],
    plaintext_len: Option<u64>,
  ) -> Result<bool, AeadModeError> {
    if matches!(self.provider, Provider::Ccm(_)) {
      let plaintext_len =
        plaintext_len.ok_or(AeadModeError::MissingPlaintextLength)?;
      self.check_ccm_message_length(plaintext_len)?;
      if !self.encrypt && !self.maybe_pass_auth_tag() {
        return Ok(false);
      }
      let Provider::Ccm(p) = &mut self.provider else {
        unreachable!()
      };
      if !p.update_message_len(plaintext_len) {
        return Ok(false);
      }
      return Ok(p.update_aad(aad));
    }
    let Provider::Ocb(p) = &mut self.provider else {
      unreachable!()
    };
    Ok(p.update_aad(aad))
  }

  /// `CipherBase::Update`.
  pub fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AeadModeError> {
    if matches!(self.provider, Provider::Ccm(_)) {
      self.check_ccm_message_length(input.len() as u64)?;
    }
    if !self.encrypt {
      // Node.js CHECKs this. The tag length was validated in set_auth_tag.
      let passed = self.maybe_pass_auth_tag();
      debug_assert!(passed);
    }
    match &mut self.provider {
      Provider::Ccm(p) => match p.update_data(input) {
        Some(out) => Ok(out),
        // A CCM decipher reports the authentication failure at final.
        None if !self.encrypt => {
          self.pending_auth_failed = true;
          Ok(Vec::new())
        }
        None => Err(AeadModeError::UnsupportedState),
      },
      Provider::Ocb(p) => {
        p.update_data(input).ok_or(AeadModeError::UnsupportedState)
      }
    }
  }

  /// `CipherBase::SetAuthTag`. `Ok(false)` is the state failure that
  /// JavaScript reports as `ERR_CRYPTO_INVALID_STATE`.
  pub fn set_auth_tag(&mut self, tag: &[u8]) -> Result<bool, AeadModeError> {
    if self.encrypt || self.auth_tag_state != AuthTagState::Unknown {
      return Ok(false);
    }
    if tag.len() != self.auth_tag_len {
      return Err(AeadModeError::InvalidAuthTagLength(tag.len() as u32));
    }
    self.auth_tag = [0u8; 16];
    self.auth_tag[..tag.len()].copy_from_slice(tag);
    self.auth_tag_state = AuthTagState::Known;
    Ok(true)
  }

  /// `CipherBase::Final`. For a cipher, `tag_out` receives the tag that
  /// `getAuthTag` returns. That tag is zero bytes when final fails.
  pub fn finalize(
    mut self,
    tag_out: &mut [u8],
  ) -> Result<Vec<u8>, AeadModeError> {
    if !self.encrypt {
      self.maybe_pass_auth_tag();
    }
    let encrypt = self.encrypt;
    let auth_tag_len = self.auth_tag_len;
    let result = match &mut self.provider {
      Provider::Ccm(_) if !encrypt => {
        if self.pending_auth_failed {
          Err(AeadModeError::AuthenticationFailed)
        } else {
          Ok(Vec::new())
        }
      }
      Provider::Ccm(p) => {
        let _ = p.finalize();
        match p.get_tag(auth_tag_len) {
          Ok(tag) => {
            self.auth_tag[..auth_tag_len].copy_from_slice(&tag);
            Ok(Vec::new())
          }
          Err(CcmGetTagError::TagNotSet) => Err(AeadModeError::TagNotSet),
          Err(CcmGetTagError::Failed) => {
            Err(AeadModeError::AuthenticationFailed)
          }
        }
      }
      Provider::Ocb(p) => match p.finalize() {
        None => Err(AeadModeError::AuthenticationFailed),
        Some(out) if encrypt => match p.get_tag(auth_tag_len) {
          Some(tag) => {
            self.auth_tag[..auth_tag_len].copy_from_slice(&tag);
            Ok(out)
          }
          None => Err(AeadModeError::AuthenticationFailed),
        },
        Some(out) => Ok(out),
      },
    };
    if encrypt {
      tag_out[..auth_tag_len].copy_from_slice(&self.auth_tag[..auth_tag_len]);
    }
    result
  }
}

/// The resource that holds an `AeadModeContext` until final.
pub struct AeadModeResource(RefCell<Option<AeadModeContext>>);

impl Resource for AeadModeResource {
  fn name(&self) -> Cow<'_, str> {
    "cryptoAeadMode".into()
  }
}

fn with_context<R>(
  state: &mut OpState,
  rid: u32,
  f: impl FnOnce(&mut AeadModeContext) -> Result<R, AeadModeError>,
) -> Result<R, AeadModeError> {
  let resource = state.resource_table.get::<AeadModeResource>(rid)?;
  let mut context = resource.0.borrow_mut();
  let context = context
    .as_mut()
    .ok_or(deno_core::error::ResourceError::BadResourceId)?;
  f(context)
}

/// `auth_tag_length` is -1 or 4294967295 when the option is absent.
#[op2(fast)]
#[smi]
pub fn op_node_aead_mode_create(
  state: &mut OpState,
  #[string] algorithm: &str,
  #[buffer] key: &[u8],
  #[buffer] iv: &[u8],
  auth_tag_length: f64,
  encrypt: bool,
) -> Result<u32, AeadModeError> {
  let auth_tag_length = if auth_tag_length < 0.0 {
    NO_AUTH_TAG_LENGTH
  } else {
    auth_tag_length as u32
  };
  let context =
    AeadModeContext::new(algorithm, key, iv, auth_tag_length, encrypt)?;
  Ok(
    state
      .resource_table
      .add(AeadModeResource(RefCell::new(Some(context)))),
  )
}

/// `plaintext_length` is -1 when the option is absent.
#[op2(fast)]
pub fn op_node_aead_mode_set_aad(
  state: &mut OpState,
  #[smi] rid: u32,
  #[buffer] aad: &[u8],
  plaintext_length: f64,
) -> Result<bool, AeadModeError> {
  let plaintext_length = if plaintext_length < 0.0 {
    None
  } else {
    Some(plaintext_length as u64)
  };
  with_context(state, rid, |context| context.set_aad(aad, plaintext_length))
}

#[op2]
pub fn op_node_aead_mode_update(
  state: &mut OpState,
  #[smi] rid: u32,
  #[buffer] input: &[u8],
) -> Result<Uint8Array, AeadModeError> {
  with_context(state, rid, |context| context.update(input)).map(Into::into)
}

#[op2(fast)]
pub fn op_node_aead_mode_set_auth_tag(
  state: &mut OpState,
  #[smi] rid: u32,
  #[buffer] tag: &[u8],
) -> Result<bool, AeadModeError> {
  with_context(state, rid, |context| context.set_auth_tag(tag))
}

/// Closes the resource on every call, as `CipherBase::Final` releases the
/// OpenSSL context on every call.
#[op2]
pub fn op_node_aead_mode_final(
  state: &mut OpState,
  #[smi] rid: u32,
  #[buffer] tag_out: &mut [u8],
) -> Result<Uint8Array, AeadModeError> {
  let resource = state.resource_table.take::<AeadModeResource>(rid)?;
  let context = resource
    .0
    .borrow_mut()
    .take()
    .ok_or(deno_core::error::ResourceError::BadResourceId)?;
  context.finalize(tag_out).map(Into::into)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
  }

  fn cipher(algorithm: &str, iv: &[u8], tag_len: u32) -> AeadModeContext {
    let key_len = lookup(algorithm).unwrap().1;
    AeadModeContext::new(algorithm, &vec![1u8; key_len], iv, tag_len, true)
      .unwrap()
  }

  fn decipher(algorithm: &str, iv: &[u8], tag_len: u32) -> AeadModeContext {
    let key_len = lookup(algorithm).unwrap().1;
    AeadModeContext::new(algorithm, &vec![1u8; key_len], iv, tag_len, false)
      .unwrap()
  }

  fn err<T>(result: Result<T, AeadModeError>) -> String {
    match result {
      Ok(_) => panic!("expected an error"),
      Err(e) => e.to_string(),
    }
  }

  // Node.js v20.20.2 constructor errors, in CommonInit order.
  #[test]
  fn node20_init_errors() {
    let new = |alg: &str, key: usize, iv: usize, tag: u32| {
      AeadModeContext::new(alg, &vec![0u8; key], &vec![0u8; iv], tag, true)
    };
    assert!(matches!(
      new("aes128-ccm", 16, 12, 8),
      Err(AeadModeError::UnknownCipher)
    ));
    assert!(new("AES-128-CCM", 16, 12, 8).is_ok());
    assert!(new("id-aes256-CCM", 32, 12, 8).is_ok());
    assert!(new("AES-256-OCB", 32, 12, 8).is_ok());
    assert!(matches!(
      new("aes-128-ccm", 16, 0, 8),
      Err(AeadModeError::InvalidIv)
    ));
    assert!(matches!(
      new("aes-128-ocb", 16, 16, 8),
      Err(AeadModeError::InvalidIv)
    ));
    assert_eq!(
      err(new("aes-128-ccm", 16, 12, NO_AUTH_TAG_LENGTH)),
      "authTagLength required for aes-128-ccm"
    );
    assert_eq!(
      err(new("aes-128-ocb", 16, 12, 1 << 31)),
      "Invalid authentication tag length: 2147483648"
    );
    // The tag length is checked before the key length.
    assert_eq!(
      err(new("aes-128-ccm", 24, 13, 5)),
      "Invalid authentication tag length: 5"
    );
    // The IV length is checked before the tag length.
    assert!(matches!(
      new("aes-128-ccm", 24, 14, 5),
      Err(AeadModeError::InvalidIv)
    ));
    assert!(matches!(
      new("aes-128-ocb", 24, 12, 8),
      Err(AeadModeError::InvalidKeyLength)
    ));
  }

  // Node.js v20.20.2 CCM message limits.
  #[test]
  fn node20_ccm_message_limits() {
    let mut c = cipher("aes-128-ccm", &[0u8; 13], 8);
    assert_eq!(err(c.set_aad(b"x", Some(65536))), "Invalid message length");
    assert_eq!(err(c.update(&vec![0u8; 65536])), "Invalid message length");
    let mut c = cipher("aes-128-ccm", &[0u8; 7], 8);
    assert!(c.set_aad(b"x", Some(i32::MAX as u64)).unwrap());
    let mut c = cipher("aes-128-ccm", &[0u8; 12], 8);
    assert_eq!(
      err(c.set_aad(b"x", None)),
      "options.plaintextLength required for CCM mode with AAD"
    );
  }

  // Node.js v20.20.2: final without data raises PROV_R_TAG_NOT_SET, and
  // getAuthTag then returns zero bytes.
  #[test]
  fn node20_ccm_final_without_data() {
    let c = cipher("aes-128-ccm", &[0u8; 12], 8);
    let mut tag = [9u8; 16];
    assert!(matches!(
      c.finalize(&mut tag),
      Err(AeadModeError::TagNotSet)
    ));
    assert_eq!(tag[..8], [0u8; 8]);
    let mut c = cipher("aes-128-ccm", &[0u8; 12], 8);
    assert!(c.set_aad(b"", Some(0)).unwrap());
    assert!(matches!(
      c.finalize(&mut tag),
      Err(AeadModeError::TagNotSet)
    ));
  }

  // Node.js v20.20.2: a second CCM update fails, and final fails with the
  // default message because OpenSSL raises nothing.
  #[test]
  fn node20_ccm_second_update() {
    let mut c = cipher("aes-128-ccm", &[0u8; 12], 8);
    assert_eq!(hex(&c.update(b"abc").unwrap()), "6ed004");
    assert_eq!(
      err(c.update(b"de")),
      "Trying to add data in unsupported state"
    );
    let mut tag = [9u8; 16];
    assert_eq!(
      err(c.finalize(&mut tag)),
      "Unsupported state or unable to authenticate data"
    );
    assert_eq!(tag[..8], [0u8; 8]);
  }

  // Node.js v20.20.2: a CCM decipher with a wrong tag returns empty output
  // from update and fails at final.
  #[test]
  fn node20_ccm_decipher_failure() {
    let mut d = decipher("aes-128-ccm", &[0u8; 13], 8);
    assert!(d.set_auth_tag(&[0u8; 8]).unwrap());
    assert!(!d.set_auth_tag(&[0u8; 8]).unwrap());
    assert_eq!(d.update(&[0u8; 3]).unwrap(), Vec::<u8>::new());
    assert!(matches!(
      d.finalize(&mut [0u8; 16]),
      Err(AeadModeError::AuthenticationFailed)
    ));
    let mut d = decipher("aes-128-ccm", &[0u8; 12], 8);
    assert_eq!(d.update(&[0u8; 3]).unwrap(), Vec::<u8>::new());
    assert!(d.finalize(&mut [0u8; 16]).is_err());
  }

  #[test]
  fn ccm_round_trip() {
    let mut c = cipher("aes-192-ccm", &[5u8; 11], 10);
    assert!(c.set_aad(b"header", Some(21)).unwrap());
    let ct = c.update(b"ccm message 21 bytes!").unwrap();
    let mut tag = [0u8; 16];
    assert!(c.finalize(&mut tag).unwrap().is_empty());
    let mut d = decipher("aes-192-ccm", &[5u8; 11], 10);
    assert_eq!(
      err(d.set_auth_tag(&tag[..8])),
      "Invalid authentication tag length: 8"
    );
    assert!(d.set_auth_tag(&tag[..10]).unwrap());
    assert!(d.set_aad(b"header", Some(21)).unwrap());
    assert_eq!(d.update(&ct).unwrap(), b"ccm message 21 bytes!");
    assert!(d.finalize(&mut [0u8; 16]).unwrap().is_empty());
  }

  // Node.js v20.20.2: an OCB decipher accepts the tag after update.
  #[test]
  fn node20_ocb_late_tag() {
    let mut c = cipher("aes-128-ocb", &[0u8; 12], 16);
    let mut ct = c.update(b"late tag ocb").unwrap();
    let mut tag = [0u8; 16];
    ct.extend(c.finalize(&mut tag).unwrap());
    let mut d = decipher("aes-128-ocb", &[0u8; 12], 16);
    assert_eq!(d.update(&ct).unwrap(), Vec::<u8>::new());
    assert!(d.set_auth_tag(&tag).unwrap());
    assert_eq!(d.finalize(&mut [0u8; 16]).unwrap(), b"late tag ocb");
  }

  // Node.js v20.20.2: an OCB tag length of zero fails at first use.
  #[test]
  fn node20_ocb_zero_tag() {
    let mut c = cipher("aes-128-ocb", &[0u8; 12], 0);
    assert_eq!(
      err(c.update(b"abc")),
      "Trying to add data in unsupported state"
    );
    let mut c = cipher("aes-128-ocb", &[0u8; 12], 0);
    assert!(!c.set_aad(b"x", None).unwrap());
    let c = cipher("aes-128-ocb", &[0u8; 12], 0);
    assert_eq!(
      err(c.finalize(&mut [0u8; 16])),
      "Unsupported state or unable to authenticate data"
    );
    let mut d = decipher("aes-128-ocb", &[0u8; 12], 0);
    assert!(d.set_auth_tag(&[]).unwrap());
  }

  #[test]
  fn node20_ocb_decipher_without_tag() {
    let mut d = decipher("aes-128-ocb", &[0u8; 12], 8);
    assert_eq!(d.update(&[0u8; 3]).unwrap(), Vec::<u8>::new());
    assert!(matches!(
      d.finalize(&mut [0u8; 16]),
      Err(AeadModeError::AuthenticationFailed)
    ));
  }
}
