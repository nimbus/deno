// Copyright 2018-2026 the Deno authors. MIT license.

//! The key and IV that the Node.js 20 `crypto.createCipher()` and
//! `crypto.createDecipher()` derive from a password.

use deno_core::op2;
use md5::Digest;
use md5::Md5;

/// `EVP_BytesToKey(cipher, EVP_md5(), nullptr, password, len, 1, key, iv)`,
/// as Node.js 20 `CipherBase::Init` calls it: MD5, no salt, one iteration.
/// Returns `key_len` key bytes followed by `iv_len` IV bytes.
pub fn bytes_to_key_md5(
  password: &[u8],
  key_len: usize,
  iv_len: usize,
) -> Vec<u8> {
  let total = key_len + iv_len;
  let mut out = Vec::with_capacity(total);
  let mut previous: Option<[u8; 16]> = None;
  while out.len() < total {
    let mut hasher = Md5::new();
    if let Some(previous) = &previous {
      hasher.update(previous);
    }
    hasher.update(password);
    let block: [u8; 16] = hasher.finalize().into();
    out.extend_from_slice(&block);
    previous = Some(block);
  }
  out.truncate(total);
  out
}

#[op2]
#[buffer]
pub fn op_node_password_cipher_key_iv(
  #[buffer] password: &[u8],
  #[smi] key_len: u32,
  #[smi] iv_len: u32,
) -> Vec<u8> {
  bytes_to_key_md5(password, key_len as usize, iv_len as usize)
}

#[cfg(test)]
mod tests {
  use super::bytes_to_key_md5;

  fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
  }

  // Known answers from `openssl enc -<cipher> -pass pass:password -nosalt
  // -md md5 -P` (OpenSSL 3.6.3).
  #[test]
  fn matches_openssl_for_each_key_and_iv_length() {
    assert_eq!(
      hex(&bytes_to_key_md5(b"password", 32, 16)),
      "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08\
       b7b4372cdfbcb3d16a2631b59b509e94"
    );
    assert_eq!(
      hex(&bytes_to_key_md5(b"password", 16, 16)),
      "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08"
    );
    assert_eq!(
      hex(&bytes_to_key_md5(b"password", 24, 0)),
      "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374a"
    );
  }

  #[test]
  fn derives_from_an_empty_password() {
    // MD5("") is d41d8cd98f00b204e9800998ecf8427e.
    assert_eq!(
      hex(&bytes_to_key_md5(b"", 16, 0)),
      "d41d8cd98f00b204e9800998ecf8427e"
    );
  }
}
