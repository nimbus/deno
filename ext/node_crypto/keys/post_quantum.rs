// Copyright 2018-2026 the Deno authors. MIT license.

use base64::Engine;
use deno_core::op2;
use deno_core::unsync::spawn_blocking;
use deno_error::JsErrorBox;
use rand::RngCore;

use super::AsymmetricPrivateKey;
use super::AsymmetricPublicKey;
use super::KeyObjectHandle;
use super::KeyObjectHandlePair;

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum PqJwkError {
  #[class(generic)]
  #[property("code" = "ERR_CRYPTO_INVALID_JWK")]
  #[error("{0}")]
  Invalid(&'static str),
  #[class(inherit)]
  #[error(transparent)]
  Unsupported(
    #[from]
    #[inherit]
    UnsupportedPostQuantumAlgorithmError,
  ),
}

impl PqJwkError {
  fn invalid() -> Self {
    Self::Invalid("Invalid JWK")
  }

  fn missing_private() -> Self {
    Self::Invalid("JWK does not contain private key material")
  }
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
#[class(generic)]
#[error("unsupported post-quantum algorithm")]
#[property("code" = "ERR_OSSL_EVP_UNSUPPORTED_ALGORITHM")]
pub struct UnsupportedPostQuantumAlgorithmError;

pub(super) fn ensure_node_algorithm_supported(
  algorithm: deno_crypto::pq_interop::Algorithm,
) -> Result<(), UnsupportedPostQuantumAlgorithmError> {
  if algorithm == deno_crypto::pq_interop::Algorithm::MlKem512 {
    Err(UnsupportedPostQuantumAlgorithmError)
  } else {
    Ok(())
  }
}

pub(super) fn new_jwk(
  jwk: &deno_core::serde_json::Value,
  is_public: bool,
) -> Result<KeyObjectHandle, PqJwkError> {
  use base64::prelude::BASE64_URL_SAFE_NO_PAD;

  let object = jwk.as_object().ok_or_else(PqJwkError::invalid)?;
  if object.get("kty").and_then(|value| value.as_str()) != Some("AKP") {
    return Err(PqJwkError::invalid());
  }
  let algorithm_name = object
    .get("alg")
    .and_then(|value| value.as_str())
    .ok_or_else(PqJwkError::invalid)?;
  let algorithm = deno_crypto::pq_interop::Algorithm::from_name(algorithm_name)
    .filter(|algorithm| algorithm.name() == algorithm_name)
    .ok_or_else(PqJwkError::invalid)?;
  ensure_node_algorithm_supported(algorithm)?;
  let public_bytes = object
    .get("pub")
    .and_then(|value| value.as_str())
    .ok_or_else(PqJwkError::invalid)
    .and_then(|value| {
      BASE64_URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PqJwkError::invalid())
    })?;
  let public =
    deno_crypto::pq_interop::import_public_raw(algorithm, &public_bytes)
      .map_err(|_| PqJwkError::invalid())?;
  if is_public {
    return Ok(KeyObjectHandle::AsymmetricPublic(
      AsymmetricPublicKey::PostQuantum(public),
    ));
  }

  let private_bytes = object
    .get("priv")
    .and_then(|value| value.as_str())
    .ok_or_else(PqJwkError::missing_private)
    .and_then(|value| {
      BASE64_URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PqJwkError::invalid())
    })?;
  let private =
    deno_crypto::pq_interop::import_private_seed(algorithm, &private_bytes)
      .map_err(|_| PqJwkError::invalid())?;
  if private.public_key() != public {
    return Err(PqJwkError::invalid());
  }
  Ok(KeyObjectHandle::AsymmetricPrivate(
    AsymmetricPrivateKey::PostQuantum(private),
  ))
}

fn generate(algorithm_name: &str) -> Result<KeyObjectHandlePair, JsErrorBox> {
  let algorithm = deno_crypto::pq_interop::Algorithm::from_name(algorithm_name)
    .ok_or_else(|| JsErrorBox::type_error("Invalid post-quantum algorithm"))?;
  ensure_node_algorithm_supported(algorithm).map_err(JsErrorBox::from_err)?;
  let seed_len = match algorithm {
    deno_crypto::pq_interop::Algorithm::MlDsa44
    | deno_crypto::pq_interop::Algorithm::MlDsa65
    | deno_crypto::pq_interop::Algorithm::MlDsa87 => 32,
    deno_crypto::pq_interop::Algorithm::MlKem768
    | deno_crypto::pq_interop::Algorithm::MlKem1024 => 64,
    deno_crypto::pq_interop::Algorithm::MlKem512 => unreachable!(),
  };
  let mut seed = vec![0u8; seed_len];
  rand::thread_rng().fill_bytes(&mut seed);
  let private = deno_crypto::pq_interop::import_private_seed(algorithm, &seed)
    .map_err(|error| JsErrorBox::generic(error.to_string()))?;
  let public = private.public_key();
  Ok(KeyObjectHandlePair::new(
    AsymmetricPrivateKey::PostQuantum(private),
    AsymmetricPublicKey::PostQuantum(public),
  ))
}

#[op2]
#[cppgc]
pub fn op_node_generate_post_quantum_key(
  #[string] algorithm_name: &str,
) -> Result<KeyObjectHandlePair, JsErrorBox> {
  generate(algorithm_name)
}

#[op2]
#[cppgc]
pub async fn op_node_generate_post_quantum_key_async(
  #[string] algorithm_name: String,
) -> Result<KeyObjectHandlePair, JsErrorBox> {
  spawn_blocking(move || generate(&algorithm_name))
    .await
    .unwrap()
}
