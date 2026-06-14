// Copyright 2018-2026 the Deno authors. MIT license.

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use deno_core::convert::Uint8Array;
use deno_core::op2;
use ed448_goldilocks::SecretKey;
use ed448_goldilocks::SigningKey;
use ed448_goldilocks::VerifyingKey;
use elliptic_curve::pkcs8::PrivateKeyInfo;
use rand::RngCore;
use rand::rngs::OsRng;
use spki::der::Decode;
use spki::der::Encode;
use spki::der::asn1::BitString;

use crate::key_store::CryptoKeyHandle;

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum Ed448Error {
  #[class("DOMExceptionOperationError")]
  #[error("Failed to export key")]
  FailedExport,
  #[class("DOMExceptionDataError")]
  #[error("Invalid key data")]
  InvalidKeyData,
  #[class(generic)]
  #[error(transparent)]
  Der(#[from] spki::der::Error),
}

// id-Ed448 OBJECT IDENTIFIER ::= { 1 3 101 113 }
pub const ED448_OID: const_oid::ObjectIdentifier =
  const_oid::ObjectIdentifier::new_unwrap("1.3.101.113");

#[op2(fast)]
pub fn op_crypto_generate_ed448_keypair(
  #[buffer] pkey: &mut [u8],
  #[buffer] pubkey: &mut [u8],
) -> bool {
  if pkey.len() != 57 || pubkey.len() != 57 {
    return false;
  }

  let mut rng = OsRng;
  rng.fill_bytes(pkey);

  let secret = match SecretKey::try_from(&pkey[..]) {
    Ok(secret) => secret,
    Err(_) => return false,
  };
  let pair = SigningKey::from(secret);
  let public_key = pair.verifying_key().to_bytes();
  pubkey.copy_from_slice(&public_key);
  true
}

#[op2(fast)]
pub fn op_crypto_sign_ed448(
  #[cppgc] key: &CryptoKeyHandle,
  #[buffer] data: &[u8],
  #[buffer] signature: &mut [u8],
) -> bool {
  if signature.len() != 114 {
    return false;
  }

  let key = key.data().bytes();
  let secret = match SecretKey::try_from(key) {
    Ok(secret) => secret,
    Err(_) => return false,
  };
  let pair = SigningKey::from(secret);
  let sig = pair.sign_raw(data);
  signature.copy_from_slice(&sig.to_bytes());
  true
}

#[op2(fast)]
pub fn op_crypto_verify_ed448(
  #[cppgc] pubkey: &CryptoKeyHandle,
  #[buffer] data: &[u8],
  #[buffer] signature: &[u8],
) -> bool {
  let pubkey = pubkey.data().bytes();
  let bytes: [u8; 57] = match pubkey.try_into() {
    Ok(bytes) => bytes,
    Err(_) => return false,
  };
  let verifying_key = match VerifyingKey::from_bytes(&bytes) {
    Ok(verifying_key) => verifying_key,
    Err(_) => return false,
  };
  let signature = match ed448_goldilocks::Signature::from_slice(signature) {
    Ok(signature) => signature,
    Err(_) => return false,
  };
  verifying_key.verify_raw(&signature, data).is_ok()
}

#[op2(fast)]
pub fn op_crypto_import_spki_ed448(
  #[buffer] key_data: &[u8],
  #[buffer] out: &mut [u8],
) -> bool {
  let pk_info = match spki::SubjectPublicKeyInfoRef::try_from(key_data) {
    Ok(pk_info) => pk_info,
    Err(_) => return false,
  };
  let alg = pk_info.algorithm.oid;
  if alg != ED448_OID {
    return false;
  }
  if pk_info.algorithm.parameters.is_some() {
    return false;
  }

  let raw = pk_info.subject_public_key.raw_bytes();
  let bytes: [u8; 57] = match raw.try_into() {
    Ok(bytes) => bytes,
    Err(_) => return false,
  };
  if VerifyingKey::from_bytes(&bytes).is_err() {
    return false;
  }

  out.copy_from_slice(raw);
  true
}

#[op2(fast)]
pub fn op_crypto_import_pkcs8_ed448(
  #[buffer] key_data: &[u8],
  #[buffer] out: &mut [u8],
) -> bool {
  let pk_info = match PrivateKeyInfo::from_der(key_data) {
    Ok(pk_info) => pk_info,
    Err(_) => return false,
  };
  let alg = pk_info.algorithm.oid;
  if alg != ED448_OID {
    return false;
  }
  if pk_info.algorithm.parameters.is_some() {
    return false;
  }

  // CurvePrivateKey ::= OCTET STRING
  if pk_info.private_key.len() != 59
    || pk_info.private_key[0] != 0x04
    || pk_info.private_key[1] != 0x39
  {
    return false;
  }

  out.copy_from_slice(&pk_info.private_key[2..]);
  true
}

#[op2]
pub fn op_crypto_export_spki_ed448(
  #[buffer] pubkey: &[u8],
) -> Result<Uint8Array, Ed448Error> {
  let bytes: [u8; 57] =
    pubkey.try_into().map_err(|_| Ed448Error::InvalidKeyData)?;
  VerifyingKey::from_bytes(&bytes).map_err(|_| Ed448Error::InvalidKeyData)?;

  let key_info = spki::SubjectPublicKeyInfo {
    algorithm: spki::AlgorithmIdentifierRef {
      oid: ED448_OID,
      parameters: None,
    },
    subject_public_key: BitString::from_bytes(pubkey)?,
  };
  Ok(
    key_info
      .to_der()
      .map_err(|_| Ed448Error::FailedExport)?
      .into(),
  )
}

#[op2]
pub fn op_crypto_export_pkcs8_ed448(
  #[buffer] pkey: &[u8],
) -> Result<Uint8Array, Ed448Error> {
  use rsa::pkcs1::der::Encode;

  if pkey.len() != 59 || pkey[0] != 0x04 || pkey[1] != 0x39 {
    return Err(Ed448Error::InvalidKeyData);
  }

  let pk_info = rsa::pkcs8::PrivateKeyInfo {
    public_key: None,
    algorithm: rsa::pkcs8::AlgorithmIdentifierRef {
      oid: ED448_OID,
      parameters: None,
    },
    private_key: pkey,
  };

  let mut buf = Vec::new();
  pk_info.encode_to_vec(&mut buf)?;
  Ok(buf.into())
}

#[op2]
#[string]
pub fn op_crypto_jwk_x_ed448(
  #[buffer] pkey: &[u8],
) -> Result<String, Ed448Error> {
  let secret =
    SecretKey::try_from(pkey).map_err(|_| Ed448Error::InvalidKeyData)?;
  let pair = SigningKey::from(secret);
  Ok(BASE64_URL_SAFE_NO_PAD.encode(pair.verifying_key().to_bytes()))
}
