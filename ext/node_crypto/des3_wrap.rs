// Copyright 2018-2026 the Deno authors. MIT license.

//! Triple-DES key wrap (RFC 3217, `des3-wrap`, `id-smime-alg-CMS3DESwrap`)
//! for `createCipheriv` and `createDecipheriv`.
//!
//! The rules follow the OpenSSL `des3-wrap` cipher (`des_ede3_wrap` and
//! `des_ede3_unwrap` in `crypto/evp/e_des3.c`) that Node.js uses: a 24-byte
//! key, no IV, a random inner IV for each wrap, and input that is a multiple
//! of 8 bytes. Each `update` wraps or unwraps its input on its own, and an
//! empty `update` gives no output.

use aes::cipher::BlockDecryptMut;
use aes::cipher::BlockEncryptMut;
use aes::cipher::KeyIvInit;
use aes::cipher::block_padding::NoPadding;
use deno_core::convert::Uint8Array;
use deno_core::op2;
use digest::Digest;
use rand::RngCore;
use subtle::ConstantTimeEq;

const KEY_LEN: usize = 24;
const BLOCK_LEN: usize = 8;
/// The fixed IV of the outer encryption (RFC 3217 section 3.1, step 6).
const WRAP_IV: [u8; BLOCK_LEN] =
  [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

type TdesCbcEnc = cbc::Encryptor<des::TdesEde3>;
type TdesCbcDec = cbc::Decryptor<des::TdesEde3>;

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum Des3WrapError {
  #[class(range)]
  #[error("Invalid key length")]
  #[property("code" = "ERR_CRYPTO_INVALID_KEYLEN")]
  InvalidKeyLength,
  #[class(type)]
  #[error("Invalid initialization vector")]
  #[property("code" = "ERR_CRYPTO_INVALID_IV")]
  InvalidIv,
  #[class(range)]
  #[error("Invalid input length")]
  InvalidInputLength,
  #[class(type)]
  #[error("DES3 unwrap failed")]
  UnwrapFailed,
}

/// Checks the IV and the key in the order that Node.js `CipherBase` and
/// `EVP_CipherInit_ex` check them. The cipher has no IV.
pub fn check_params(key: &[u8], iv: &[u8]) -> Result<(), Des3WrapError> {
  if !iv.is_empty() {
    return Err(Des3WrapError::InvalidIv);
  }
  if key.len() != KEY_LEN {
    return Err(Des3WrapError::InvalidKeyLength);
  }
  Ok(())
}

fn icv(data: &[u8]) -> [u8; BLOCK_LEN] {
  let digest = sha1::Sha1::digest(data);
  let mut icv = [0u8; BLOCK_LEN];
  icv.copy_from_slice(&digest[..BLOCK_LEN]);
  icv
}

fn cbc_encrypt(key: &[u8], iv: &[u8; BLOCK_LEN], buf: &mut [u8]) {
  let len = buf.len();
  TdesCbcEnc::new(key.into(), iv.into())
    .encrypt_padded_mut::<NoPadding>(buf, len)
    .expect("the length is a multiple of the block size");
}

fn cbc_decrypt(key: &[u8], iv: &[u8; BLOCK_LEN], buf: &mut [u8]) {
  TdesCbcDec::new(key.into(), iv.into())
    .decrypt_padded_mut::<NoPadding>(buf)
    .expect("the length is a multiple of the block size");
}

/// Wraps `data`. The output is 16 bytes longer than the input.
pub fn wrap(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Des3WrapError> {
  if key.len() != KEY_LEN {
    return Err(Des3WrapError::InvalidKeyLength);
  }
  if data.is_empty() {
    return Ok(Vec::new());
  }
  if !data.len().is_multiple_of(BLOCK_LEN) {
    return Err(Des3WrapError::InvalidInputLength);
  }

  // out = IV || CBC(key, IV, data || ICV)
  let mut out = vec![0u8; data.len() + 2 * BLOCK_LEN];
  let mut iv = [0u8; BLOCK_LEN];
  rand::thread_rng().fill_bytes(&mut iv);
  out[..BLOCK_LEN].copy_from_slice(&iv);
  out[BLOCK_LEN..BLOCK_LEN + data.len()].copy_from_slice(data);
  out[BLOCK_LEN + data.len()..].copy_from_slice(&icv(data));
  cbc_encrypt(key, &iv, &mut out[BLOCK_LEN..]);

  // Reverse the byte order, then encrypt again with the fixed IV.
  out.reverse();
  cbc_encrypt(key, &WRAP_IV, &mut out);
  Ok(out)
}

/// Unwraps `data` and checks its integrity value. The output is 16 bytes
/// shorter than the input.
pub fn unwrap(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Des3WrapError> {
  if key.len() != KEY_LEN {
    return Err(Des3WrapError::InvalidKeyLength);
  }
  if data.is_empty() {
    return Ok(Vec::new());
  }
  if data.len() < 3 * BLOCK_LEN || !data.len().is_multiple_of(BLOCK_LEN) {
    return Err(Des3WrapError::InvalidInputLength);
  }

  let mut buf = data.to_vec();
  cbc_decrypt(key, &WRAP_IV, &mut buf);
  buf.reverse();

  // buf = IV || CBC(key, IV, plaintext || ICV)
  let (iv_block, rest) = buf.split_at_mut(BLOCK_LEN);
  let mut iv = [0u8; BLOCK_LEN];
  iv.copy_from_slice(iv_block);
  cbc_decrypt(key, &iv, rest);

  let (plaintext, expected_icv) = rest.split_at(rest.len() - BLOCK_LEN);
  if icv(plaintext).ct_eq(expected_icv).unwrap_u8() != 1 {
    return Err(Des3WrapError::UnwrapFailed);
  }
  Ok(plaintext.to_vec())
}

#[op2(fast)]
pub fn op_node_des3_wrap_check_params(
  #[buffer] key: &[u8],
  #[buffer] iv: &[u8],
) -> Result<(), Des3WrapError> {
  check_params(key, iv)
}

#[op2]
pub fn op_node_des3_wrap_key(
  #[buffer] key: &[u8],
  #[buffer] data: &[u8],
) -> Result<Uint8Array, Des3WrapError> {
  wrap(key, data).map(Into::into)
}

#[op2]
pub fn op_node_des3_unwrap_key(
  #[buffer] key: &[u8],
  #[buffer] data: &[u8],
) -> Result<Uint8Array, Des3WrapError> {
  unwrap(key, data).map(Into::into)
}
