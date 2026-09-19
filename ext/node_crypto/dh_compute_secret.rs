// Copyright 2018-2026 the Deno authors. MIT license.

//! `DiffieHellman#computeSecret()` with the public-key checks of each
//! Node.js release line.
//!
//! Node.js 20 computes the secret first and classifies the key only when
//! OpenSSL rejects the secret. Node.js 22 checks the key with
//! `DH_check_pub_key()` before it computes the secret. That check includes
//! the subgroup check for OpenSSL named groups. Node.js 24 and later check
//! only the key range, then compute the secret.

use deno_core::JsBuffer;
use deno_core::OpState;
use deno_core::convert::Uint8Array;
use deno_core::op2;
use num_bigint_dig::BigUint;
use num_traits::One;
use num_traits::Zero;

use crate::dh::DiffieHellmanGroup;
use crate::dh::Modp1536;
use crate::dh::Modp2048;
use crate::dh::Modp3072;
use crate::dh::Modp4096;
use crate::dh::Modp6144;
use crate::dh::Modp8192;

/// How `DiffieHellman#computeSecret()` validates the other party's public
/// key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhComputeSecretPolicy {
  /// Match Node.js 20. Compute the secret first. When OpenSSL rejects the
  /// secret, classify the key as too small, too large, or of an invalid
  /// type.
  ComputeThenClassify,
  /// Match Node.js 22. Run `DH_check_pub_key()` first, including the
  /// subgroup check for OpenSSL named groups. A key that is too large is
  /// reported as an unspecified validation error, because the Node.js 22
  /// classification tests the too-small flag twice. When OpenSSL rejects the
  /// secret, return an empty buffer.
  CheckPublicKey,
  /// Match Node.js 24 and later. Reject a key outside `[2, p - 2]`, then
  /// compute the secret.
  CheckRangeThenCompute,
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum DhComputeSecretError {
  #[class(range)]
  #[property("code" = "ERR_CRYPTO_INVALID_KEYLEN")]
  #[error("Supplied key is too small")]
  KeyTooSmall,
  #[class(range)]
  #[property("code" = "ERR_CRYPTO_INVALID_KEYLEN")]
  #[error("Supplied key is too large")]
  KeyTooLarge,
  #[class(range)]
  #[property("code" = "ERR_CRYPTO_INVALID_KEYTYPE")]
  #[error("Invalid key type")]
  InvalidKeyType,
  #[class(range)]
  #[property("code" = "ERR_CRYPTO_INVALID_KEYTYPE")]
  #[error("Unspecified validation error")]
  UnspecifiedValidationError,
  #[class(generic)]
  #[property("code" = "ERR_CRYPTO_OPERATION_FAILED")]
  #[error("Failed to compute shared secret")]
  ComputeFailed,
}

/// `OPENSSL_DH_MAX_MODULUS_BITS`: OpenSSL does not compute a secret for a
/// larger modulus.
const MAX_COMPUTE_MODULUS_BITS: usize = 10_000;

#[op2]
pub fn op_node_dh_compute_secret_checked(
  state: &OpState,
  #[buffer] prime: JsBuffer,
  #[buffer] generator: JsBuffer,
  #[buffer] private_key: JsBuffer,
  #[buffer] their_public_key: JsBuffer,
) -> Result<Uint8Array, DhComputeSecretError> {
  let policy = state
    .try_borrow::<DhComputeSecretPolicy>()
    .copied()
    .unwrap_or(DhComputeSecretPolicy::CheckRangeThenCompute);
  compute_secret(
    policy,
    &BigUint::from_bytes_be(&prime),
    &BigUint::from_bytes_be(&generator),
    &BigUint::from_bytes_be(&private_key),
    &BigUint::from_bytes_be(&their_public_key),
  )
  .map(Into::into)
}

/// Computes `y^x mod p` for the public key `y` and the private key `x`, and
/// left-pads the secret to the byte length of `p`.
pub fn compute_secret(
  policy: DhComputeSecretPolicy,
  prime: &BigUint,
  generator: &BigUint,
  private_key: &BigUint,
  public_key: &BigUint,
) -> Result<Vec<u8>, DhComputeSecretError> {
  let range = KeyRange::of(public_key, prime);
  match policy {
    DhComputeSecretPolicy::ComputeThenClassify => {
      match openssl_compute_key(prime, private_key, public_key) {
        Some(secret) => Ok(secret),
        None => Err(match range {
          KeyRange::TooSmall => DhComputeSecretError::KeyTooSmall,
          KeyRange::TooLarge => DhComputeSecretError::KeyTooLarge,
          KeyRange::InRange => DhComputeSecretError::InvalidKeyType,
        }),
      }
    }
    DhComputeSecretPolicy::CheckPublicKey => {
      match range {
        KeyRange::TooSmall => return Err(DhComputeSecretError::KeyTooSmall),
        KeyRange::TooLarge => {
          return Err(DhComputeSecretError::UnspecifiedValidationError);
        }
        KeyRange::InRange => {}
      }
      if is_openssl_named_group(prime, generator) {
        // For every named group, q = (p - 1) / 2.
        let q = (prime - 1u32) >> 1;
        if !public_key.modpow(&q, prime).is_one() {
          return Err(DhComputeSecretError::UnspecifiedValidationError);
        }
      }
      Ok(
        openssl_compute_key(prime, private_key, public_key).unwrap_or_default(),
      )
    }
    DhComputeSecretPolicy::CheckRangeThenCompute => {
      match range {
        KeyRange::TooSmall => return Err(DhComputeSecretError::KeyTooSmall),
        KeyRange::TooLarge => return Err(DhComputeSecretError::KeyTooLarge),
        KeyRange::InRange => {}
      }
      openssl_compute_key(prime, private_key, public_key)
        .ok_or(DhComputeSecretError::ComputeFailed)
    }
  }
}

/// The range classification of `DH_check_pub_key()`.
enum KeyRange {
  /// `y <= 1`
  TooSmall,
  /// `y >= p - 1`
  TooLarge,
  InRange,
}

impl KeyRange {
  fn of(public_key: &BigUint, prime: &BigUint) -> Self {
    if public_key <= &BigUint::one() {
      Self::TooSmall
    } else if prime.is_zero() || public_key >= &(prime - 1u32) {
      Self::TooLarge
    } else {
      Self::InRange
    }
  }
}

/// The secret that OpenSSL `DH_compute_key()` accepts, padded to the byte
/// length of `p`. OpenSSL rejects a secret `z` when `z <= 1` or
/// `z == p - 1`, and rejects a modulus larger than
/// `OPENSSL_DH_MAX_MODULUS_BITS`.
fn openssl_compute_key(
  prime: &BigUint,
  private_key: &BigUint,
  public_key: &BigUint,
) -> Option<Vec<u8>> {
  if prime.bits() > MAX_COMPUTE_MODULUS_BITS || prime <= &BigUint::one() {
    return None;
  }
  let secret = public_key.modpow(private_key, prime);
  if secret <= BigUint::one() || secret == prime - 1u32 {
    return None;
  }
  let prime_len = prime.bits().div_ceil(8);
  let secret = secret.to_bytes_be();
  let mut padded = vec![0u8; prime_len - secret.len()];
  padded.extend_from_slice(&secret);
  Some(padded)
}

/// Whether `(p, g)` is a group that OpenSSL names, and so gives the subgroup
/// order `q` (`ossl_dh_cache_named_group()`). OpenSSL names the RFC 7919
/// FFDHE groups and the RFC 3526 MODP groups, all with generator 2.
fn is_openssl_named_group(prime: &BigUint, generator: &BigUint) -> bool {
  if generator != &BigUint::from(2u32) {
    return false;
  }
  [
    FFDHE2048,
    FFDHE3072,
    FFDHE4096,
    FFDHE6144,
    FFDHE8192,
    Modp1536::MODULUS,
    Modp2048::MODULUS,
    Modp3072::MODULUS,
    Modp4096::MODULUS,
    Modp6144::MODULUS,
    Modp8192::MODULUS,
  ]
  .iter()
  .any(|words| &biguint_from_words(words) == prime)
}

fn biguint_from_words(words: &[u32]) -> BigUint {
  let bytes: Vec<u8> = words.iter().flat_map(|x| x.to_be_bytes()).collect();
  BigUint::from_bytes_be(&bytes)
}

/// ffdhe2048 from RFC 7919 appendix A.
const FFDHE2048: &[u32] = &[
  0xFFFFFFFF, 0xFFFFFFFF, 0xADF85458, 0xA2BB4A9A, 0xAFDC5620, 0x273D3CF1,
  0xD8B9C583, 0xCE2D3695, 0xA9E13641, 0x146433FB, 0xCC939DCE, 0x249B3EF9,
  0x7D2FE363, 0x630C75D8, 0xF681B202, 0xAEC4617A, 0xD3DF1ED5, 0xD5FD6561,
  0x2433F51F, 0x5F066ED0, 0x85636555, 0x3DED1AF3, 0xB557135E, 0x7F57C935,
  0x984F0C70, 0xE0E68B77, 0xE2A689DA, 0xF3EFE872, 0x1DF158A1, 0x36ADE735,
  0x30ACCA4F, 0x483A797A, 0xBC0AB182, 0xB324FB61, 0xD108A94B, 0xB2C8E3FB,
  0xB96ADAB7, 0x60D7F468, 0x1D4F42A3, 0xDE394DF4, 0xAE56EDE7, 0x6372BB19,
  0x0B07A7C8, 0xEE0A6D70, 0x9E02FCE1, 0xCDF7E2EC, 0xC03404CD, 0x28342F61,
  0x9172FE9C, 0xE98583FF, 0x8E4F1232, 0xEEF28183, 0xC3FE3B1B, 0x4C6FAD73,
  0x3BB5FCBC, 0x2EC22005, 0xC58EF183, 0x7D1683B2, 0xC6F34A26, 0xC1B2EFFA,
  0x886B4238, 0x61285C97, 0xFFFFFFFF, 0xFFFFFFFF,
];

/// ffdhe3072 from RFC 7919 appendix A.
const FFDHE3072: &[u32] = &[
  0xFFFFFFFF, 0xFFFFFFFF, 0xADF85458, 0xA2BB4A9A, 0xAFDC5620, 0x273D3CF1,
  0xD8B9C583, 0xCE2D3695, 0xA9E13641, 0x146433FB, 0xCC939DCE, 0x249B3EF9,
  0x7D2FE363, 0x630C75D8, 0xF681B202, 0xAEC4617A, 0xD3DF1ED5, 0xD5FD6561,
  0x2433F51F, 0x5F066ED0, 0x85636555, 0x3DED1AF3, 0xB557135E, 0x7F57C935,
  0x984F0C70, 0xE0E68B77, 0xE2A689DA, 0xF3EFE872, 0x1DF158A1, 0x36ADE735,
  0x30ACCA4F, 0x483A797A, 0xBC0AB182, 0xB324FB61, 0xD108A94B, 0xB2C8E3FB,
  0xB96ADAB7, 0x60D7F468, 0x1D4F42A3, 0xDE394DF4, 0xAE56EDE7, 0x6372BB19,
  0x0B07A7C8, 0xEE0A6D70, 0x9E02FCE1, 0xCDF7E2EC, 0xC03404CD, 0x28342F61,
  0x9172FE9C, 0xE98583FF, 0x8E4F1232, 0xEEF28183, 0xC3FE3B1B, 0x4C6FAD73,
  0x3BB5FCBC, 0x2EC22005, 0xC58EF183, 0x7D1683B2, 0xC6F34A26, 0xC1B2EFFA,
  0x886B4238, 0x611FCFDC, 0xDE355B3B, 0x6519035B, 0xBC34F4DE, 0xF99C0238,
  0x61B46FC9, 0xD6E6C907, 0x7AD91D26, 0x91F7F7EE, 0x598CB0FA, 0xC186D91C,
  0xAEFE1309, 0x85139270, 0xB4130C93, 0xBC437944, 0xF4FD4452, 0xE2D74DD3,
  0x64F2E21E, 0x71F54BFF, 0x5CAE82AB, 0x9C9DF69E, 0xE86D2BC5, 0x22363A0D,
  0xABC52197, 0x9B0DEADA, 0x1DBF9A42, 0xD5C4484E, 0x0ABCD06B, 0xFA53DDEF,
  0x3C1B20EE, 0x3FD59D7C, 0x25E41D2B, 0x66C62E37, 0xFFFFFFFF, 0xFFFFFFFF,
];

/// ffdhe4096 from RFC 7919 appendix A.
const FFDHE4096: &[u32] = &[
  0xFFFFFFFF, 0xFFFFFFFF, 0xADF85458, 0xA2BB4A9A, 0xAFDC5620, 0x273D3CF1,
  0xD8B9C583, 0xCE2D3695, 0xA9E13641, 0x146433FB, 0xCC939DCE, 0x249B3EF9,
  0x7D2FE363, 0x630C75D8, 0xF681B202, 0xAEC4617A, 0xD3DF1ED5, 0xD5FD6561,
  0x2433F51F, 0x5F066ED0, 0x85636555, 0x3DED1AF3, 0xB557135E, 0x7F57C935,
  0x984F0C70, 0xE0E68B77, 0xE2A689DA, 0xF3EFE872, 0x1DF158A1, 0x36ADE735,
  0x30ACCA4F, 0x483A797A, 0xBC0AB182, 0xB324FB61, 0xD108A94B, 0xB2C8E3FB,
  0xB96ADAB7, 0x60D7F468, 0x1D4F42A3, 0xDE394DF4, 0xAE56EDE7, 0x6372BB19,
  0x0B07A7C8, 0xEE0A6D70, 0x9E02FCE1, 0xCDF7E2EC, 0xC03404CD, 0x28342F61,
  0x9172FE9C, 0xE98583FF, 0x8E4F1232, 0xEEF28183, 0xC3FE3B1B, 0x4C6FAD73,
  0x3BB5FCBC, 0x2EC22005, 0xC58EF183, 0x7D1683B2, 0xC6F34A26, 0xC1B2EFFA,
  0x886B4238, 0x611FCFDC, 0xDE355B3B, 0x6519035B, 0xBC34F4DE, 0xF99C0238,
  0x61B46FC9, 0xD6E6C907, 0x7AD91D26, 0x91F7F7EE, 0x598CB0FA, 0xC186D91C,
  0xAEFE1309, 0x85139270, 0xB4130C93, 0xBC437944, 0xF4FD4452, 0xE2D74DD3,
  0x64F2E21E, 0x71F54BFF, 0x5CAE82AB, 0x9C9DF69E, 0xE86D2BC5, 0x22363A0D,
  0xABC52197, 0x9B0DEADA, 0x1DBF9A42, 0xD5C4484E, 0x0ABCD06B, 0xFA53DDEF,
  0x3C1B20EE, 0x3FD59D7C, 0x25E41D2B, 0x669E1EF1, 0x6E6F52C3, 0x164DF4FB,
  0x7930E9E4, 0xE58857B6, 0xAC7D5F42, 0xD69F6D18, 0x7763CF1D, 0x55034004,
  0x87F55BA5, 0x7E31CC7A, 0x7135C886, 0xEFB4318A, 0xED6A1E01, 0x2D9E6832,
  0xA907600A, 0x918130C4, 0x6DC778F9, 0x71AD0038, 0x092999A3, 0x33CB8B7A,
  0x1A1DB93D, 0x7140003C, 0x2A4ECEA9, 0xF98D0ACC, 0x0A8291CD, 0xCEC97DCF,
  0x8EC9B55A, 0x7F88A46B, 0x4DB5A851, 0xF44182E1, 0xC68A007E, 0x5E655F6A,
  0xFFFFFFFF, 0xFFFFFFFF,
];

/// ffdhe6144 from RFC 7919 appendix A.
const FFDHE6144: &[u32] = &[
  0xFFFFFFFF, 0xFFFFFFFF, 0xADF85458, 0xA2BB4A9A, 0xAFDC5620, 0x273D3CF1,
  0xD8B9C583, 0xCE2D3695, 0xA9E13641, 0x146433FB, 0xCC939DCE, 0x249B3EF9,
  0x7D2FE363, 0x630C75D8, 0xF681B202, 0xAEC4617A, 0xD3DF1ED5, 0xD5FD6561,
  0x2433F51F, 0x5F066ED0, 0x85636555, 0x3DED1AF3, 0xB557135E, 0x7F57C935,
  0x984F0C70, 0xE0E68B77, 0xE2A689DA, 0xF3EFE872, 0x1DF158A1, 0x36ADE735,
  0x30ACCA4F, 0x483A797A, 0xBC0AB182, 0xB324FB61, 0xD108A94B, 0xB2C8E3FB,
  0xB96ADAB7, 0x60D7F468, 0x1D4F42A3, 0xDE394DF4, 0xAE56EDE7, 0x6372BB19,
  0x0B07A7C8, 0xEE0A6D70, 0x9E02FCE1, 0xCDF7E2EC, 0xC03404CD, 0x28342F61,
  0x9172FE9C, 0xE98583FF, 0x8E4F1232, 0xEEF28183, 0xC3FE3B1B, 0x4C6FAD73,
  0x3BB5FCBC, 0x2EC22005, 0xC58EF183, 0x7D1683B2, 0xC6F34A26, 0xC1B2EFFA,
  0x886B4238, 0x611FCFDC, 0xDE355B3B, 0x6519035B, 0xBC34F4DE, 0xF99C0238,
  0x61B46FC9, 0xD6E6C907, 0x7AD91D26, 0x91F7F7EE, 0x598CB0FA, 0xC186D91C,
  0xAEFE1309, 0x85139270, 0xB4130C93, 0xBC437944, 0xF4FD4452, 0xE2D74DD3,
  0x64F2E21E, 0x71F54BFF, 0x5CAE82AB, 0x9C9DF69E, 0xE86D2BC5, 0x22363A0D,
  0xABC52197, 0x9B0DEADA, 0x1DBF9A42, 0xD5C4484E, 0x0ABCD06B, 0xFA53DDEF,
  0x3C1B20EE, 0x3FD59D7C, 0x25E41D2B, 0x669E1EF1, 0x6E6F52C3, 0x164DF4FB,
  0x7930E9E4, 0xE58857B6, 0xAC7D5F42, 0xD69F6D18, 0x7763CF1D, 0x55034004,
  0x87F55BA5, 0x7E31CC7A, 0x7135C886, 0xEFB4318A, 0xED6A1E01, 0x2D9E6832,
  0xA907600A, 0x918130C4, 0x6DC778F9, 0x71AD0038, 0x092999A3, 0x33CB8B7A,
  0x1A1DB93D, 0x7140003C, 0x2A4ECEA9, 0xF98D0ACC, 0x0A8291CD, 0xCEC97DCF,
  0x8EC9B55A, 0x7F88A46B, 0x4DB5A851, 0xF44182E1, 0xC68A007E, 0x5E0DD902,
  0x0BFD64B6, 0x45036C7A, 0x4E677D2C, 0x38532A3A, 0x23BA4442, 0xCAF53EA6,
  0x3BB45432, 0x9B7624C8, 0x917BDD64, 0xB1C0FD4C, 0xB38E8C33, 0x4C701C3A,
  0xCDAD0657, 0xFCCFEC71, 0x9B1F5C3E, 0x4E46041F, 0x388147FB, 0x4CFDB477,
  0xA52471F7, 0xA9A96910, 0xB855322E, 0xDB6340D8, 0xA00EF092, 0x350511E3,
  0x0ABEC1FF, 0xF9E3A26E, 0x7FB29F8C, 0x183023C3, 0x587E38DA, 0x0077D9B4,
  0x763E4E4B, 0x94B2BBC1, 0x94C6651E, 0x77CAF992, 0xEEAAC023, 0x2A281BF6,
  0xB3A739C1, 0x22611682, 0x0AE8DB58, 0x47A67CBE, 0xF9C9091B, 0x462D538C,
  0xD72B0374, 0x6AE77F5E, 0x62292C31, 0x1562A846, 0x505DC82D, 0xB854338A,
  0xE49F5235, 0xC95B9117, 0x8CCF2DD5, 0xCACEF403, 0xEC9D1810, 0xC6272B04,
  0x5B3B71F9, 0xDC6B80D6, 0x3FDD4A8E, 0x9ADB1E69, 0x62A69526, 0xD43161C1,
  0xA41D570D, 0x7938DAD4, 0xA40E329C, 0xD0E40E65, 0xFFFFFFFF, 0xFFFFFFFF,
];

/// ffdhe8192 from RFC 7919 appendix A.
const FFDHE8192: &[u32] = &[
  0xFFFFFFFF, 0xFFFFFFFF, 0xADF85458, 0xA2BB4A9A, 0xAFDC5620, 0x273D3CF1,
  0xD8B9C583, 0xCE2D3695, 0xA9E13641, 0x146433FB, 0xCC939DCE, 0x249B3EF9,
  0x7D2FE363, 0x630C75D8, 0xF681B202, 0xAEC4617A, 0xD3DF1ED5, 0xD5FD6561,
  0x2433F51F, 0x5F066ED0, 0x85636555, 0x3DED1AF3, 0xB557135E, 0x7F57C935,
  0x984F0C70, 0xE0E68B77, 0xE2A689DA, 0xF3EFE872, 0x1DF158A1, 0x36ADE735,
  0x30ACCA4F, 0x483A797A, 0xBC0AB182, 0xB324FB61, 0xD108A94B, 0xB2C8E3FB,
  0xB96ADAB7, 0x60D7F468, 0x1D4F42A3, 0xDE394DF4, 0xAE56EDE7, 0x6372BB19,
  0x0B07A7C8, 0xEE0A6D70, 0x9E02FCE1, 0xCDF7E2EC, 0xC03404CD, 0x28342F61,
  0x9172FE9C, 0xE98583FF, 0x8E4F1232, 0xEEF28183, 0xC3FE3B1B, 0x4C6FAD73,
  0x3BB5FCBC, 0x2EC22005, 0xC58EF183, 0x7D1683B2, 0xC6F34A26, 0xC1B2EFFA,
  0x886B4238, 0x611FCFDC, 0xDE355B3B, 0x6519035B, 0xBC34F4DE, 0xF99C0238,
  0x61B46FC9, 0xD6E6C907, 0x7AD91D26, 0x91F7F7EE, 0x598CB0FA, 0xC186D91C,
  0xAEFE1309, 0x85139270, 0xB4130C93, 0xBC437944, 0xF4FD4452, 0xE2D74DD3,
  0x64F2E21E, 0x71F54BFF, 0x5CAE82AB, 0x9C9DF69E, 0xE86D2BC5, 0x22363A0D,
  0xABC52197, 0x9B0DEADA, 0x1DBF9A42, 0xD5C4484E, 0x0ABCD06B, 0xFA53DDEF,
  0x3C1B20EE, 0x3FD59D7C, 0x25E41D2B, 0x669E1EF1, 0x6E6F52C3, 0x164DF4FB,
  0x7930E9E4, 0xE58857B6, 0xAC7D5F42, 0xD69F6D18, 0x7763CF1D, 0x55034004,
  0x87F55BA5, 0x7E31CC7A, 0x7135C886, 0xEFB4318A, 0xED6A1E01, 0x2D9E6832,
  0xA907600A, 0x918130C4, 0x6DC778F9, 0x71AD0038, 0x092999A3, 0x33CB8B7A,
  0x1A1DB93D, 0x7140003C, 0x2A4ECEA9, 0xF98D0ACC, 0x0A8291CD, 0xCEC97DCF,
  0x8EC9B55A, 0x7F88A46B, 0x4DB5A851, 0xF44182E1, 0xC68A007E, 0x5E0DD902,
  0x0BFD64B6, 0x45036C7A, 0x4E677D2C, 0x38532A3A, 0x23BA4442, 0xCAF53EA6,
  0x3BB45432, 0x9B7624C8, 0x917BDD64, 0xB1C0FD4C, 0xB38E8C33, 0x4C701C3A,
  0xCDAD0657, 0xFCCFEC71, 0x9B1F5C3E, 0x4E46041F, 0x388147FB, 0x4CFDB477,
  0xA52471F7, 0xA9A96910, 0xB855322E, 0xDB6340D8, 0xA00EF092, 0x350511E3,
  0x0ABEC1FF, 0xF9E3A26E, 0x7FB29F8C, 0x183023C3, 0x587E38DA, 0x0077D9B4,
  0x763E4E4B, 0x94B2BBC1, 0x94C6651E, 0x77CAF992, 0xEEAAC023, 0x2A281BF6,
  0xB3A739C1, 0x22611682, 0x0AE8DB58, 0x47A67CBE, 0xF9C9091B, 0x462D538C,
  0xD72B0374, 0x6AE77F5E, 0x62292C31, 0x1562A846, 0x505DC82D, 0xB854338A,
  0xE49F5235, 0xC95B9117, 0x8CCF2DD5, 0xCACEF403, 0xEC9D1810, 0xC6272B04,
  0x5B3B71F9, 0xDC6B80D6, 0x3FDD4A8E, 0x9ADB1E69, 0x62A69526, 0xD43161C1,
  0xA41D570D, 0x7938DAD4, 0xA40E329C, 0xCFF46AAA, 0x36AD004C, 0xF600C838,
  0x1E425A31, 0xD951AE64, 0xFDB23FCE, 0xC9509D43, 0x687FEB69, 0xEDD1CC5E,
  0x0B8CC3BD, 0xF64B10EF, 0x86B63142, 0xA3AB8829, 0x555B2F74, 0x7C932665,
  0xCB2C0F1C, 0xC01BD702, 0x29388839, 0xD2AF05E4, 0x54504AC7, 0x8B758282,
  0x2846C0BA, 0x35C35F5C, 0x59160CC0, 0x46FD8251, 0x541FC68C, 0x9C86B022,
  0xBB709987, 0x6A460E74, 0x51A8A931, 0x09703FEE, 0x1C217E6C, 0x3826E52C,
  0x51AA691E, 0x0E423CFC, 0x99E9E316, 0x50C1217B, 0x624816CD, 0xAD9A95F9,
  0xD5B80194, 0x88D9C0A0, 0xA1FE3075, 0xA577E231, 0x83F81D4A, 0x3F2FA457,
  0x1EFC8CE0, 0xBA8A4FE8, 0xB6855DFE, 0x72B0A66E, 0xDED2FBAB, 0xFBE58A30,
  0xFAFABE1C, 0x5D71A87E, 0x2F741EF8, 0xC1FE86FE, 0xA6BBFDE5, 0x30677F0D,
  0x97D11D49, 0xF7A8443D, 0x0822E506, 0xA9F4614E, 0x011E2A94, 0x838FF88C,
  0xD68C8BB7, 0xC5C6424C, 0xFFFFFFFF, 0xFFFFFFFF,
];

#[cfg(test)]
mod tests {
  use super::*;

  // Expected outcomes come from Node.js v20.20.2, v22.23.1, v24.20.0 and
  // v26.8.1.
  const NODE20: DhComputeSecretPolicy =
    DhComputeSecretPolicy::ComputeThenClassify;
  const NODE22: DhComputeSecretPolicy = DhComputeSecretPolicy::CheckPublicKey;
  const NODE24: DhComputeSecretPolicy =
    DhComputeSecretPolicy::CheckRangeThenCompute;

  #[derive(Debug, PartialEq)]
  enum Outcome {
    Secret(usize),
    TooSmall,
    TooLarge,
    InvalidKeyType,
    Unspecified,
    ComputeFailed,
  }

  fn outcome(
    policy: DhComputeSecretPolicy,
    prime: &BigUint,
    generator: u32,
    private_key: &BigUint,
    public_key: &BigUint,
  ) -> Outcome {
    match compute_secret(
      policy,
      prime,
      &BigUint::from(generator),
      private_key,
      public_key,
    ) {
      Ok(secret) => Outcome::Secret(secret.len()),
      Err(DhComputeSecretError::KeyTooSmall) => Outcome::TooSmall,
      Err(DhComputeSecretError::KeyTooLarge) => Outcome::TooLarge,
      Err(DhComputeSecretError::InvalidKeyType) => Outcome::InvalidKeyType,
      Err(DhComputeSecretError::UnspecifiedValidationError) => {
        Outcome::Unspecified
      }
      Err(DhComputeSecretError::ComputeFailed) => Outcome::ComputeFailed,
    }
  }

  fn modp1536() -> BigUint {
    biguint_from_words(Modp1536::MODULUS)
  }

  fn private_key() -> BigUint {
    BigUint::from(0x1234_5678_9abc_def1u64)
  }

  /// The smallest `y >= 2` outside the subgroup of order `(p - 1) / 2`.
  fn non_residue(prime: &BigUint) -> BigUint {
    let q = (prime - 1u32) >> 1;
    let mut y = BigUint::from(2u32);
    while y.modpow(&q, prime) != prime - 1u32 {
      y += 1u32;
    }
    y
  }

  #[test]
  fn key_range_boundaries_match_each_release() {
    let p = modp1536();
    let len = 192;
    let huge = BigUint::from_bytes_be(&[0xff; 200]);
    let cases = [
      // (key, generator, node20, node22, node24)
      (
        BigUint::zero(),
        5,
        Outcome::TooSmall,
        Outcome::TooSmall,
        Outcome::TooSmall,
      ),
      (
        BigUint::one(),
        5,
        Outcome::TooSmall,
        Outcome::TooSmall,
        Outcome::TooSmall,
      ),
      (
        BigUint::from(2u32),
        5,
        Outcome::Secret(len),
        Outcome::Secret(len),
        Outcome::Secret(len),
      ),
      (
        &p - 2u32,
        5,
        Outcome::Secret(len),
        Outcome::Secret(len),
        Outcome::Secret(len),
      ),
      (
        &p - 1u32,
        5,
        Outcome::TooLarge,
        Outcome::Unspecified,
        Outcome::TooLarge,
      ),
      (
        p.clone(),
        5,
        Outcome::TooLarge,
        Outcome::Unspecified,
        Outcome::TooLarge,
      ),
      (
        &p + 1u32,
        5,
        Outcome::TooLarge,
        Outcome::Unspecified,
        Outcome::TooLarge,
      ),
      (
        huge.clone(),
        5,
        Outcome::Secret(len),
        Outcome::Unspecified,
        Outcome::TooLarge,
      ),
      (
        &p - 2u32,
        2,
        Outcome::Secret(len),
        Outcome::Unspecified,
        Outcome::Secret(len),
      ),
      (
        huge,
        2,
        Outcome::Secret(len),
        Outcome::Unspecified,
        Outcome::TooLarge,
      ),
    ];
    for (key, g, node20, node22, node24) in cases {
      let x = private_key();
      assert_eq!(
        outcome(NODE20, &p, g, &x, &key),
        node20,
        "node20 {key:x} g{g}"
      );
      assert_eq!(
        outcome(NODE22, &p, g, &x, &key),
        node22,
        "node22 {key:x} g{g}"
      );
      assert_eq!(
        outcome(NODE24, &p, g, &x, &key),
        node24,
        "node24 {key:x} g{g}"
      );
    }
  }

  #[test]
  fn node22_checks_the_subgroup_of_every_named_group() {
    for words in [
      FFDHE2048,
      FFDHE3072,
      FFDHE4096,
      FFDHE6144,
      FFDHE8192,
      Modp1536::MODULUS,
      Modp2048::MODULUS,
      Modp3072::MODULUS,
      Modp4096::MODULUS,
      Modp6144::MODULUS,
      Modp8192::MODULUS,
    ] {
      let p = biguint_from_words(words);
      let len = words.len() * 4;
      let y = non_residue(&p);
      let x = private_key();
      assert_eq!(outcome(NODE22, &p, 2, &x, &y), Outcome::Unspecified);
      assert_eq!(outcome(NODE22, &p, 5, &x, &y), Outcome::Secret(len));
      assert_eq!(outcome(NODE20, &p, 2, &x, &y), Outcome::Secret(len));
      assert_eq!(outcome(NODE24, &p, 2, &x, &y), Outcome::Secret(len));
      let subgroup_key = BigUint::from(4u32);
      assert_eq!(
        outcome(NODE22, &p, 2, &x, &subgroup_key),
        Outcome::Secret(len)
      );
    }
  }

  #[test]
  fn rejected_secret_is_reported_per_release() {
    let p = modp1536();
    // x = p - 1 gives z = 1 for every key.
    let x = &p - 1u32;
    let y = BigUint::from(2u32);
    assert_eq!(outcome(NODE20, &p, 5, &x, &y), Outcome::InvalidKeyType);
    assert_eq!(outcome(NODE22, &p, 5, &x, &y), Outcome::Secret(0));
    assert_eq!(outcome(NODE24, &p, 5, &x, &y), Outcome::ComputeFailed);
    // x = q and a non-residue key give z = p - 1.
    let q = (&p - 1u32) >> 1;
    let y = non_residue(&p);
    assert_eq!(outcome(NODE20, &p, 5, &q, &y), Outcome::InvalidKeyType);
    assert_eq!(outcome(NODE22, &p, 5, &q, &y), Outcome::Secret(0));
    assert_eq!(outcome(NODE24, &p, 5, &q, &y), Outcome::ComputeFailed);
  }

  #[test]
  fn modulus_above_openssl_compute_limit_is_rejected() {
    let mut bytes = vec![0xff; 1256];
    bytes[0] = 0xc0;
    let p = BigUint::from_bytes_be(&bytes);
    let x = BigUint::from(3u32);
    let two = BigUint::from(2u32);
    assert_eq!(outcome(NODE20, &p, 2, &x, &two), Outcome::InvalidKeyType);
    assert_eq!(outcome(NODE22, &p, 2, &x, &two), Outcome::Secret(0));
    assert_eq!(outcome(NODE24, &p, 2, &x, &two), Outcome::ComputeFailed);
    let one = BigUint::one();
    for policy in [NODE20, NODE22, NODE24] {
      assert_eq!(outcome(policy, &p, 2, &x, &one), Outcome::TooSmall);
    }
  }

  #[test]
  fn secret_is_left_padded_to_the_prime_length() {
    let p = modp1536();
    let secret = compute_secret(
      NODE24,
      &p,
      &BigUint::from(5u32),
      &BigUint::one(),
      &BigUint::from(2u32),
    )
    .unwrap();
    let mut expected = vec![0u8; 192];
    expected[191] = 2;
    assert_eq!(secret, expected);
  }

  #[test]
  fn ffdhe_constants_have_the_rfc7919_shape() {
    for (words, bits) in [
      (FFDHE2048, 2048),
      (FFDHE3072, 3072),
      (FFDHE4096, 4096),
      (FFDHE6144, 6144),
      (FFDHE8192, 8192),
    ] {
      let p = biguint_from_words(words);
      assert_eq!(p.bits(), bits);
      // RFC 7919: every FFDHE prime starts and ends with 64 one bits.
      assert_eq!(words[..2], [0xFFFF_FFFF; 2]);
      assert_eq!(words[words.len() - 2..], [0xFFFF_FFFF; 2]);
    }
  }
}
