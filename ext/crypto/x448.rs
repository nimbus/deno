// Copyright 2018-2026 the Deno authors. MIT license.

use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use crypto_bigint::Encoding;
use crypto_bigint::U448;
use deno_core::convert::Uint8Array;
use deno_core::op2;
use ed448_goldilocks::subtle::Choice;
use ed448_goldilocks::subtle::ConditionallySelectable;
use ed448_goldilocks::subtle::ConstantTimeEq;
use elliptic_curve::pkcs8::PrivateKeyInfo;
use rand::RngCore;
use rand::rngs::OsRng;
use spki::der::Decode;
use spki::der::Encode;
use spki::der::asn1::BitString;

use crate::key_store::CryptoKeyHandle;

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum X448Error {
  #[class("DOMExceptionOperationError")]
  #[error("Failed to export key")]
  FailedExport,
  #[class("DOMExceptionDataError")]
  #[error("Invalid key data")]
  InvalidKeyLength,
  #[class(generic)]
  #[error(transparent)]
  Der(#[from] spki::der::Error),
}

const X448_FIELD_MODULUS: U448 = U448::from_be_hex(
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);
const X448_A24: U448 = U448::from_u64(39081);
const X448_GENERATOR: [u8; 56] = {
  let mut generator = [0u8; 56];
  generator[0] = 5;
  generator
};
const X448_IDENTITY: [u8; 56] = [0; 56];

fn x448_field_from_le(bytes: &[u8; 56]) -> U448 {
  U448::from_le_slice(bytes).const_rem(&X448_FIELD_MODULUS).0
}

fn x448_clamp_scalar(private_key: &[u8; 56]) -> [u8; 56] {
  let mut scalar = *private_key;
  scalar[0] &= 0xfc;
  scalar[55] |= 0x80;
  scalar
}

fn x448_mod_mul(lhs: &U448, rhs: &U448) -> U448 {
  let (reduced, ok) =
    U448::const_rem_wide(lhs.mul_wide(rhs), &X448_FIELD_MODULUS);
  debug_assert!(bool::from(ok));
  reduced
}

fn x448_mod_square(value: &U448) -> U448 {
  let (reduced, ok) =
    U448::const_rem_wide(value.square_wide(), &X448_FIELD_MODULUS);
  debug_assert!(bool::from(ok));
  reduced
}

fn x448_cswap(lhs: &mut U448, rhs: &mut U448, swap: Choice) {
  let new_lhs = U448::conditional_select(lhs, rhs, swap);
  let new_rhs = U448::conditional_select(rhs, lhs, swap);
  *lhs = new_lhs;
  *rhs = new_rhs;
}

fn x448_scalar_mult(private_key: &[u8; 56], public_key: &[u8; 56]) -> [u8; 56] {
  let scalar = x448_clamp_scalar(private_key);
  let x1 = x448_field_from_le(public_key);
  let mut x2 = U448::ONE;
  let mut z2 = U448::ZERO;
  let mut x3 = x1;
  let mut z3 = U448::ONE;
  let mut swap = 0;

  for bit_index in (0..448).rev() {
    let bit = (scalar[bit_index / 8] >> (bit_index & 7)) & 1;
    let swap_choice = Choice::from(swap ^ bit);
    x448_cswap(&mut x2, &mut x3, swap_choice);
    x448_cswap(&mut z2, &mut z3, swap_choice);
    swap = bit;

    let a = x2.add_mod(&z2, &X448_FIELD_MODULUS);
    let aa = x448_mod_square(&a);
    let b = x2.sub_mod(&z2, &X448_FIELD_MODULUS);
    let bb = x448_mod_square(&b);
    let e = aa.sub_mod(&bb, &X448_FIELD_MODULUS);
    let c = x3.add_mod(&z3, &X448_FIELD_MODULUS);
    let d = x3.sub_mod(&z3, &X448_FIELD_MODULUS);
    let da = x448_mod_mul(&d, &a);
    let cb = x448_mod_mul(&c, &b);
    let da_plus_cb = da.add_mod(&cb, &X448_FIELD_MODULUS);
    let da_minus_cb = da.sub_mod(&cb, &X448_FIELD_MODULUS);
    x3 = x448_mod_square(&da_plus_cb);
    z3 = x448_mod_mul(&x1, &x448_mod_square(&da_minus_cb));
    x2 = x448_mod_mul(&aa, &bb);
    let a24_e = x448_mod_mul(&X448_A24, &e);
    let aa_plus_a24_e = aa.add_mod(&a24_e, &X448_FIELD_MODULUS);
    z2 = x448_mod_mul(&e, &aa_plus_a24_e);
  }

  let swap_choice = Choice::from(swap);
  x448_cswap(&mut x2, &mut x3, swap_choice);
  x448_cswap(&mut z2, &mut z3, swap_choice);

  let (z2_inv, invertible) = z2.inv_odd_mod(&X448_FIELD_MODULUS);
  let result = x448_mod_mul(&x2, &z2_inv);
  U448::conditional_select(&U448::ZERO, &result, invertible.into())
    .to_le_bytes()
}

#[op2(fast)]
pub fn op_crypto_generate_x448_keypair(
  #[buffer] pkey: &mut [u8],
  #[buffer] pubkey: &mut [u8],
) {
  let mut rng = OsRng;
  rng.fill_bytes(pkey);

  // x448(pkey, 5)
  let mut private_key = [0u8; 56];
  private_key.copy_from_slice(pkey);
  pubkey.copy_from_slice(&x448_scalar_mult(&private_key, &X448_GENERATOR));
}

#[op2(fast)]
pub fn op_crypto_derive_bits_x448(
  #[cppgc] k: &CryptoKeyHandle,
  #[cppgc] u: &CryptoKeyHandle,
  #[buffer] secret: &mut [u8],
) -> Result<bool, X448Error> {
  let k: [u8; 56] = k
    .data()
    .bytes()
    .try_into()
    .map_err(|_| X448Error::InvalidKeyLength)?;
  let u: [u8; 56] = u
    .data()
    .bytes()
    .try_into()
    .map_err(|_| X448Error::InvalidKeyLength)?;

  // x448(k, u)
  let shared_secret = x448_scalar_mult(&k, &u);
  if shared_secret.ct_eq(&X448_IDENTITY).unwrap_u8() == 1 {
    return Ok(true);
  }

  secret.copy_from_slice(&shared_secret);
  Ok(false)
}

// id-X448 OBJECT IDENTIFIER ::= { 1 3 101 111 }
const X448_OID: const_oid::ObjectIdentifier =
  const_oid::ObjectIdentifier::new_unwrap("1.3.101.111");

#[op2]
#[string]
pub fn op_crypto_x448_public_key(
  #[buffer] private_key: &[u8],
) -> Result<String, X448Error> {
  use base64::Engine;

  let private_key: [u8; 56] = private_key
    .try_into()
    .map_err(|_| X448Error::InvalidKeyLength)?;
  // x448(pkey, 5), identical derivation to op_crypto_generate_x448_keypair.
  Ok(
    BASE64_URL_SAFE_NO_PAD
      .encode(x448_scalar_mult(&private_key, &X448_GENERATOR)),
  )
}

#[op2]
pub fn op_crypto_export_spki_x448(
  #[buffer] pubkey: &[u8],
) -> Result<Uint8Array, X448Error> {
  let key_info = spki::SubjectPublicKeyInfo {
    algorithm: spki::AlgorithmIdentifierRef {
      oid: X448_OID,
      parameters: None,
    },
    subject_public_key: BitString::from_bytes(pubkey)?,
  };
  Ok(
    key_info
      .to_der()
      .map_err(|_| X448Error::FailedExport)?
      .into(),
  )
}

#[op2]
pub fn op_crypto_export_pkcs8_x448(
  #[buffer] pkey: &[u8],
) -> Result<Uint8Array, X448Error> {
  use rsa::pkcs1::der::Encode;

  let pk_info = rsa::pkcs8::PrivateKeyInfo {
    public_key: None,
    algorithm: rsa::pkcs8::AlgorithmIdentifierRef {
      oid: X448_OID,
      parameters: None,
    },
    private_key: pkey, // OCTET STRING
  };

  let mut buf = Vec::new();
  pk_info.encode_to_vec(&mut buf)?;
  Ok(buf.into())
}

#[op2(fast)]
pub fn op_crypto_import_spki_x448(
  #[buffer] key_data: &[u8],
  #[buffer] out: &mut [u8],
) -> bool {
  // 2-3.
  let pk_info = match spki::SubjectPublicKeyInfoRef::try_from(key_data) {
    Ok(pk_info) => pk_info,
    Err(_) => return false,
  };
  // 4.
  let alg = pk_info.algorithm.oid;
  if alg != X448_OID {
    return false;
  }
  // 5.
  if pk_info.algorithm.parameters.is_some() {
    return false;
  }
  out.copy_from_slice(pk_info.subject_public_key.raw_bytes());
  true
}

#[op2(fast)]
pub fn op_crypto_import_pkcs8_x448(
  #[buffer] key_data: &[u8],
  #[buffer] out: &mut [u8],
) -> bool {
  // 2-3.
  let pk_info = match PrivateKeyInfo::from_der(key_data) {
    Ok(pk_info) => pk_info,
    Err(_) => return false,
  };
  // 4.
  let alg = pk_info.algorithm.oid;
  if alg != X448_OID {
    return false;
  }
  // 5.
  if pk_info.algorithm.parameters.is_some() {
    return false;
  }
  // 6.
  // CurvePrivateKey ::= OCTET STRING
  if pk_info.private_key.len() != 58 {
    return false;
  }
  out.copy_from_slice(&pk_info.private_key[2..]);
  true
}

#[cfg(test)]
mod tests {
  use super::*;
  use base64::Engine;

  #[test]
  fn x448_scalar_mult_matches_node_cfrg_vector() {
    let private_key = BASE64_URL_SAFE_NO_PAD
      .decode(
        "_IGPZUaoH5Y8J3ZdwcBb_bFpZn5eDPRTGO0cuThyIXqw2QBODH3Q3LABkvcgOcwaHf91DsMcivs",
      )
      .unwrap();
    let private_key: [u8; 56] = private_key.try_into().unwrap();

    assert_eq!(
      BASE64_URL_SAFE_NO_PAD
        .encode(x448_scalar_mult(&private_key, &X448_GENERATOR)),
      "HUUcjAw2mkLq38KHXNRJU8rrRsRm3IZWgoC_27sB9HCaGwseDdZs97EchBGd3JiJDbcokSnjDaQ"
    );
  }
}
