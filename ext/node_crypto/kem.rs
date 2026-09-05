// Copyright 2018-2026 the Deno authors. MIT license.

use deno_core::ToJsBuffer;
use deno_core::op2;
use rand::RngCore;
use rsa::BigUint;
use rsa::hazmat::rsa_decrypt_and_check;
use rsa::hazmat::rsa_encrypt;
use rsa::traits::PublicKeyParts;

use crate::keys::AsymmetricPrivateKey;
use crate::keys::AsymmetricPublicKey;
use crate::keys::KeyObjectHandle;

#[derive(Debug, thiserror::Error, deno_error::JsError)]
#[class(generic)]
pub enum KemError {
  #[error("KEM is not supported for this key type")]
  UnsupportedKey,
  #[error("Encapsulation failed")]
  EncapsulationFailed,
  #[error("Decapsulation failed")]
  DecapsulationFailed,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncapsulationResult {
  shared_key: ToJsBuffer,
  ciphertext: ToJsBuffer,
}

fn left_pad(mut bytes: Vec<u8>, len: usize) -> Result<Vec<u8>, KemError> {
  if bytes.len() > len {
    return Err(KemError::EncapsulationFailed);
  }
  if bytes.len() == len {
    return Ok(bytes);
  }
  let mut padded = vec![0; len - bytes.len()];
  padded.append(&mut bytes);
  Ok(padded)
}

fn rsa_encapsulate(
  public: &rsa::RsaPublicKey,
) -> Result<(Vec<u8>, Vec<u8>), KemError> {
  let len = public.size();
  let mut rng = rand::thread_rng();
  let shared_key = loop {
    let mut candidate = vec![0; len];
    rng.fill_bytes(&mut candidate);
    let value = BigUint::from_bytes_be(&candidate);
    if value != BigUint::from(0u8) && value < *public.n() {
      break (candidate, value);
    }
  };
  let ciphertext = rsa_encrypt(public, &shared_key.1)
    .map_err(|_| KemError::EncapsulationFailed)?
    .to_bytes_be();
  Ok((shared_key.0, left_pad(ciphertext, len)?))
}

fn rsa_decapsulate(
  private: &rsa::RsaPrivateKey,
  ciphertext: &[u8],
) -> Result<Vec<u8>, KemError> {
  let len = private.size();
  if ciphertext.len() != len {
    return Err(KemError::DecapsulationFailed);
  }
  let ciphertext = BigUint::from_bytes_be(ciphertext);
  if ciphertext == BigUint::from(0u8) || ciphertext >= *private.n() {
    return Err(KemError::DecapsulationFailed);
  }
  let mut rng = rand::thread_rng();
  let shared_key = rsa_decrypt_and_check(private, Some(&mut rng), &ciphertext)
    .map_err(|_| KemError::DecapsulationFailed)?
    .to_bytes_be();
  left_pad(shared_key, len).map_err(|_| KemError::DecapsulationFailed)
}

#[op2]
#[serde]
pub fn op_node_kem_encapsulate(
  #[cppgc] handle: &KeyObjectHandle,
) -> Result<EncapsulationResult, KemError> {
  let public = handle.as_public_key().ok_or(KemError::UnsupportedKey)?;
  let (shared_key, ciphertext) = match &*public {
    AsymmetricPublicKey::Rsa(public) => rsa_encapsulate(public)?,
    AsymmetricPublicKey::PostQuantum(public) => public
      .encapsulate()
      .map_err(|_| KemError::EncapsulationFailed)?,
    _ => return Err(KemError::UnsupportedKey),
  };
  Ok(EncapsulationResult {
    shared_key: shared_key.into(),
    ciphertext: ciphertext.into(),
  })
}

#[op2]
#[buffer]
pub fn op_node_kem_decapsulate(
  #[cppgc] handle: &KeyObjectHandle,
  #[buffer] ciphertext: &[u8],
) -> Result<Box<[u8]>, KemError> {
  let private = handle.as_private_key().ok_or(KemError::UnsupportedKey)?;
  let shared_key = match private {
    AsymmetricPrivateKey::Rsa(private) => rsa_decapsulate(private, ciphertext)?,
    AsymmetricPrivateKey::PostQuantum(private) => private
      .decapsulate(ciphertext)
      .map_err(|_| KemError::DecapsulationFailed)?,
    _ => return Err(KemError::UnsupportedKey),
  };
  Ok(shared_key.into_boxed_slice())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rsa_kem_round_trip() {
    let mut rng = rand::thread_rng();
    let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let public = rsa::RsaPublicKey::from(&private);

    let (shared_key, ciphertext) = rsa_encapsulate(&public).unwrap();

    assert_eq!(ciphertext.len(), public.size());
    assert_eq!(shared_key.len(), public.size());
    assert_eq!(rsa_decapsulate(&private, &ciphertext).unwrap(), shared_key);
  }

  #[test]
  fn rsa_kem_rejects_invalid_ciphertexts() {
    let mut rng = rand::thread_rng();
    let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();

    assert!(matches!(
      rsa_decapsulate(&private, &[0; 1]),
      Err(KemError::DecapsulationFailed)
    ));
    assert!(matches!(
      rsa_decapsulate(&private, &vec![0; private.size()]),
      Err(KemError::DecapsulationFailed)
    ));
    assert!(matches!(
      rsa_decapsulate(&private, &private.n().to_bytes_be()),
      Err(KemError::DecapsulationFailed)
    ));
  }
}
