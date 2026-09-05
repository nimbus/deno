// Copyright 2018-2026 the Deno authors. MIT license.

use deno_core::convert::Uint8Array;
use deno_core::op2;
use deno_error::JsErrorBox;

use super::AsymmetricPrivateKey;
use super::AsymmetricPrivateKeyError;
use super::AsymmetricPublicKey;
use super::AsymmetricPublicKeyError;
use super::EcPrivateKey;
use super::EcPublicKey;
use super::EdRawError;
use super::KeyObjectHandle;
use super::post_quantum;

pub(super) fn private_key_from_js(
  key: &[u8],
  format: &str,
  typ: &str,
  named_curve: Option<&str>,
) -> Option<Result<KeyObjectHandle, AsymmetricPrivateKeyError>> {
  match format {
    "raw-private" => Some(raw_private_key_from_js(key, typ, named_curve)),
    "raw-seed" => Some(raw_seed_from_js(key, typ)),
    _ => None,
  }
}

fn raw_private_key_from_js(
  key: &[u8],
  typ: &str,
  named_curve: Option<&str>,
) -> Result<KeyObjectHandle, AsymmetricPrivateKeyError> {
  let private_key = match typ {
    "ec" => {
      let key = match named_curve {
        Some("P-224" | "secp224r1") if key.len() == 28 => {
          p224::SecretKey::from_slice(key).map(EcPrivateKey::P224)
        }
        Some("P-256" | "prime256v1" | "secp256r1") if key.len() == 32 => {
          p256::SecretKey::from_slice(key).map(EcPrivateKey::P256)
        }
        Some("P-384" | "secp384r1") if key.len() == 48 => {
          p384::SecretKey::from_slice(key).map(EcPrivateKey::P384)
        }
        Some("P-521" | "secp521r1") if key.len() == 66 => {
          p521::SecretKey::from_slice(key).map(EcPrivateKey::P521)
        }
        Some("secp256k1") if key.len() == 32 => {
          k256::SecretKey::from_slice(key).map(EcPrivateKey::Secp256k1)
        }
        _ => return Err(AsymmetricPrivateKeyError::InvalidRawPrivateKey),
      }
      .map_err(|_| AsymmetricPrivateKeyError::InvalidRawPrivateKey)?;
      AsymmetricPrivateKey::Ec(key)
    }
    "ed25519" => {
      let bytes: &[u8; 32] = key
        .try_into()
        .map_err(|_| AsymmetricPrivateKeyError::InvalidRawPrivateKey)?;
      AsymmetricPrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
        bytes,
      ))
    }
    "x25519" => {
      let bytes: [u8; 32] = key
        .try_into()
        .map_err(|_| AsymmetricPrivateKeyError::InvalidRawPrivateKey)?;
      AsymmetricPrivateKey::X25519(x25519_dalek::StaticSecret::from(bytes))
    }
    "ed448" => {
      let bytes: [u8; 57] = key
        .try_into()
        .map_err(|_| AsymmetricPrivateKeyError::InvalidRawPrivateKey)?;
      AsymmetricPrivateKey::Ed448(ed448_goldilocks::SigningKey::from(
        ed448_goldilocks::EdwardsScalarBytes::from(bytes),
      ))
    }
    "x448" => {
      let bytes: [u8; 56] = key
        .try_into()
        .map_err(|_| AsymmetricPrivateKeyError::InvalidRawPrivateKey)?;
      AsymmetricPrivateKey::X448(bytes)
    }
    _ => {
      return Err(AsymmetricPrivateKeyError::UnsupportedKeyType(
        typ.to_string(),
      ));
    }
  };

  Ok(KeyObjectHandle::AsymmetricPrivate(private_key))
}

fn raw_seed_from_js(
  key: &[u8],
  typ: &str,
) -> Result<KeyObjectHandle, AsymmetricPrivateKeyError> {
  let algorithm = deno_crypto::pq_interop::Algorithm::from_name(typ)
    .ok_or_else(|| {
      AsymmetricPrivateKeyError::UnsupportedKeyType(typ.to_string())
    })?;
  post_quantum::ensure_node_algorithm_supported(algorithm)?;
  let key = deno_crypto::pq_interop::import_private_seed(algorithm, key)
    .map_err(|_| AsymmetricPrivateKeyError::InvalidPrivateKey)?;
  Ok(KeyObjectHandle::AsymmetricPrivate(
    AsymmetricPrivateKey::PostQuantum(key),
  ))
}

pub(super) fn public_key_from_js(
  key: &[u8],
  format: &str,
  typ: &str,
  named_curve: Option<&str>,
) -> Option<Result<KeyObjectHandle, AsymmetricPublicKeyError>> {
  if format != "raw-public" {
    return None;
  }
  Some(raw_public_key_from_js(key, typ, named_curve))
}

fn raw_public_key_from_js(
  key: &[u8],
  typ: &str,
  named_curve: Option<&str>,
) -> Result<KeyObjectHandle, AsymmetricPublicKeyError> {
  let public_key = if let Some(algorithm) =
    deno_crypto::pq_interop::Algorithm::from_name(typ)
  {
    post_quantum::ensure_node_algorithm_supported(algorithm)?;
    let key = deno_crypto::pq_interop::import_public_raw(algorithm, key)
      .map_err(|_| AsymmetricPublicKeyError::InvalidRawPublicKey)?;
    AsymmetricPublicKey::PostQuantum(key)
  } else {
    match typ {
      "ec" => {
        let key = match named_curve {
          Some("P-224" | "secp224r1") => {
            p224::PublicKey::from_sec1_bytes(key).map(EcPublicKey::P224)
          }
          Some("P-256" | "prime256v1" | "secp256r1") => {
            p256::PublicKey::from_sec1_bytes(key).map(EcPublicKey::P256)
          }
          Some("P-384" | "secp384r1") => {
            p384::PublicKey::from_sec1_bytes(key).map(EcPublicKey::P384)
          }
          Some("P-521" | "secp521r1") => {
            p521::PublicKey::from_sec1_bytes(key).map(EcPublicKey::P521)
          }
          Some("secp256k1") => {
            k256::PublicKey::from_sec1_bytes(key).map(EcPublicKey::Secp256k1)
          }
          _ => return Err(AsymmetricPublicKeyError::InvalidRawPublicKey),
        }
        .map_err(|_| AsymmetricPublicKeyError::InvalidRawPublicKey)?;
        AsymmetricPublicKey::Ec(key)
      }
      "ed25519" => {
        let bytes: &[u8; 32] = key
          .try_into()
          .map_err(|_| AsymmetricPublicKeyError::InvalidRawPublicKey)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
          .map_err(|_| AsymmetricPublicKeyError::InvalidRawPublicKey)?;
        AsymmetricPublicKey::Ed25519(key)
      }
      "x25519" => {
        let bytes: [u8; 32] = key
          .try_into()
          .map_err(|_| AsymmetricPublicKeyError::InvalidRawPublicKey)?;
        AsymmetricPublicKey::X25519(x25519_dalek::PublicKey::from(bytes))
      }
      "ed448" => {
        let bytes: &[u8; 57] = key
          .try_into()
          .map_err(|_| AsymmetricPublicKeyError::InvalidRawPublicKey)?;
        let key = ed448_goldilocks::VerifyingKey::from_bytes(bytes)
          .map_err(|_| AsymmetricPublicKeyError::InvalidRawPublicKey)?;
        AsymmetricPublicKey::Ed448(key)
      }
      "x448" => {
        let bytes: [u8; 56] = key
          .try_into()
          .map_err(|_| AsymmetricPublicKeyError::InvalidRawPublicKey)?;
        AsymmetricPublicKey::X448(bytes)
      }
      _ => {
        return Err(AsymmetricPublicKeyError::UnsupportedKeyType(
          typ.to_string(),
        ));
      }
    }
  };
  Ok(KeyObjectHandle::AsymmetricPublic(public_key))
}

pub(super) fn ed_key_from_raw(
  curve: &str,
  data: &[u8],
  is_public: bool,
) -> Result<KeyObjectHandle, EdRawError> {
  match curve {
    "Ed25519" => {
      let data = data.try_into().map_err(|_| EdRawError::InvalidEd25519Key)?;
      if !is_public {
        Ok(KeyObjectHandle::AsymmetricPrivate(
          AsymmetricPrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
            data,
          )),
        ))
      } else {
        Ok(KeyObjectHandle::AsymmetricPublic(
          AsymmetricPublicKey::Ed25519(
            ed25519_dalek::VerifyingKey::from_bytes(data)?,
          ),
        ))
      }
    }
    "X25519" => {
      let data: [u8; 32] =
        data.try_into().map_err(|_| EdRawError::InvalidEd25519Key)?;
      if !is_public {
        Ok(KeyObjectHandle::AsymmetricPrivate(
          AsymmetricPrivateKey::X25519(x25519_dalek::StaticSecret::from(data)),
        ))
      } else {
        Ok(KeyObjectHandle::AsymmetricPublic(
          AsymmetricPublicKey::X25519(x25519_dalek::PublicKey::from(data)),
        ))
      }
    }
    "Ed448" => {
      if !is_public {
        let key_bytes: [u8; 57] =
          data.try_into().map_err(|_| EdRawError::InvalidEd448Key)?;
        let seed = ed448_goldilocks::EdwardsScalarBytes::from(key_bytes);
        Ok(KeyObjectHandle::AsymmetricPrivate(
          AsymmetricPrivateKey::Ed448(ed448_goldilocks::SigningKey::from(seed)),
        ))
      } else {
        let point_bytes: &[u8; 57] =
          data.try_into().map_err(|_| EdRawError::InvalidEd448Key)?;
        let key = ed448_goldilocks::VerifyingKey::from_bytes(point_bytes)
          .map_err(|_| EdRawError::InvalidEd448Key)?;
        Ok(KeyObjectHandle::AsymmetricPublic(
          AsymmetricPublicKey::Ed448(key),
        ))
      }
    }
    "X448" => {
      let data: [u8; 56] =
        data.try_into().map_err(|_| EdRawError::InvalidX448Key)?;
      if !is_public {
        Ok(KeyObjectHandle::AsymmetricPrivate(
          AsymmetricPrivateKey::X448(data),
        ))
      } else {
        Ok(KeyObjectHandle::AsymmetricPublic(
          AsymmetricPublicKey::X448(data),
        ))
      }
    }
    _ => Err(EdRawError::UnsupportedCurve),
  }
}

#[op2]
pub fn op_node_export_public_key_raw(
  #[cppgc] handle: &KeyObjectHandle,
  #[string] point_format: Option<String>,
) -> Result<Uint8Array, JsErrorBox> {
  let key = handle.as_public_key().ok_or_else(|| {
    JsErrorBox::type_error("raw-public export requires a public key")
  })?;
  match key.as_ref() {
    AsymmetricPublicKey::Ec(key) => {
      use elliptic_curve::sec1::ToEncodedPoint;
      let compressed = point_format.as_deref() == Some("compressed");
      let bytes = match key {
        EcPublicKey::P224(key) => {
          key.to_encoded_point(compressed).as_bytes().to_vec()
        }
        EcPublicKey::P256(key) => {
          key.to_encoded_point(compressed).as_bytes().to_vec()
        }
        EcPublicKey::P384(key) => {
          key.to_encoded_point(compressed).as_bytes().to_vec()
        }
        EcPublicKey::P521(key) => {
          key.to_encoded_point(compressed).as_bytes().to_vec()
        }
        EcPublicKey::Secp256k1(key) => {
          key.to_encoded_point(compressed).as_bytes().to_vec()
        }
      };
      Ok(bytes.into())
    }
    AsymmetricPublicKey::X25519(key) => Ok(key.as_bytes().to_vec().into()),
    AsymmetricPublicKey::Ed25519(key) => Ok(key.to_bytes().to_vec().into()),
    AsymmetricPublicKey::X448(key) => Ok(key.to_vec().into()),
    AsymmetricPublicKey::Ed448(key) => Ok(key.to_bytes().to_vec().into()),
    AsymmetricPublicKey::PostQuantum(key) => Ok(key.raw().to_vec().into()),
    _ => Err(JsErrorBox::type_error(
      "raw-public export is not supported for this key type",
    )),
  }
}

#[op2]
pub fn op_node_export_private_key_raw(
  #[cppgc] handle: &KeyObjectHandle,
) -> Result<Uint8Array, JsErrorBox> {
  let key = handle.as_private_key().ok_or_else(|| {
    JsErrorBox::type_error("raw-private export requires a private key")
  })?;
  let bytes = match key {
    AsymmetricPrivateKey::Ec(key) => match key {
      EcPrivateKey::P224(key) => key.to_bytes().to_vec(),
      EcPrivateKey::P256(key) => key.to_bytes().to_vec(),
      EcPrivateKey::P384(key) => key.to_bytes().to_vec(),
      EcPrivateKey::P521(key) => key.to_bytes().to_vec(),
      EcPrivateKey::Secp256k1(key) => key.to_bytes().to_vec(),
    },
    AsymmetricPrivateKey::X25519(key) => key.to_bytes().to_vec(),
    AsymmetricPrivateKey::Ed25519(key) => key.to_bytes().to_vec(),
    AsymmetricPrivateKey::X448(key) => key.to_vec(),
    AsymmetricPrivateKey::Ed448(key) => key.to_bytes().to_vec(),
    _ => {
      return Err(JsErrorBox::type_error(
        "raw-private export is not supported for this key type",
      ));
    }
  };
  Ok(bytes.into())
}

#[op2]
pub fn op_node_export_private_key_seed(
  #[cppgc] handle: &KeyObjectHandle,
) -> Result<Uint8Array, JsErrorBox> {
  match handle.as_private_key() {
    Some(AsymmetricPrivateKey::PostQuantum(key)) => {
      key.seed().map(|seed| seed.to_vec().into()).ok_or_else(|| {
        JsErrorBox::generic("key does not have an available seed")
      })
    }
    _ => Err(JsErrorBox::type_error(
      "raw-seed export requires a post-quantum private key",
    )),
  }
}
