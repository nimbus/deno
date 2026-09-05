// Copyright 2018-2026 the Deno authors. MIT license.

//! Shared post-quantum key material for the WebCrypto and Node compatibility
//! extensions.

use spki::der::Decode;

use crate::mldsa;
use crate::mlkem;
use crate::mlkem::MlKemVariant;

const ML_DSA_44_OID: const_oid::ObjectIdentifier =
  const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const ML_DSA_65_OID: const_oid::ObjectIdentifier =
  const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const ML_DSA_87_OID: const_oid::ObjectIdentifier =
  const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
  MlDsa44,
  MlDsa65,
  MlDsa87,
  MlKem512,
  MlKem768,
  MlKem1024,
}

impl Algorithm {
  pub fn name(self) -> &'static str {
    match self {
      Self::MlDsa44 => "ML-DSA-44",
      Self::MlDsa65 => "ML-DSA-65",
      Self::MlDsa87 => "ML-DSA-87",
      Self::MlKem512 => "ML-KEM-512",
      Self::MlKem768 => "ML-KEM-768",
      Self::MlKem1024 => "ML-KEM-1024",
    }
  }

  pub fn node_name(self) -> &'static str {
    match self {
      Self::MlDsa44 => "ml-dsa-44",
      Self::MlDsa65 => "ml-dsa-65",
      Self::MlDsa87 => "ml-dsa-87",
      Self::MlKem512 => "ml-kem-512",
      Self::MlKem768 => "ml-kem-768",
      Self::MlKem1024 => "ml-kem-1024",
    }
  }

  pub fn from_name(name: &str) -> Option<Self> {
    match name {
      "ML-DSA-44" | "ml-dsa-44" => Some(Self::MlDsa44),
      "ML-DSA-65" | "ml-dsa-65" => Some(Self::MlDsa65),
      "ML-DSA-87" | "ml-dsa-87" => Some(Self::MlDsa87),
      "ML-KEM-512" | "ml-kem-512" => Some(Self::MlKem512),
      "ML-KEM-768" | "ml-kem-768" => Some(Self::MlKem768),
      "ML-KEM-1024" | "ml-kem-1024" => Some(Self::MlKem1024),
      _ => None,
    }
  }

  fn mldsa_variant(self) -> Option<u8> {
    match self {
      Self::MlDsa44 => Some(0),
      Self::MlDsa65 => Some(1),
      Self::MlDsa87 => Some(2),
      _ => None,
    }
  }

  fn mlkem_variant(self) -> Option<MlKemVariant> {
    match self {
      Self::MlKem512 => Some(MlKemVariant::MlKem512),
      Self::MlKem768 => Some(MlKemVariant::MlKem768),
      Self::MlKem1024 => Some(MlKemVariant::MlKem1024),
      _ => None,
    }
  }

  pub fn from_oid(oid: const_oid::ObjectIdentifier) -> Option<Self> {
    match oid {
      ML_DSA_44_OID => Some(Self::MlDsa44),
      ML_DSA_65_OID => Some(Self::MlDsa65),
      ML_DSA_87_OID => Some(Self::MlDsa87),
      mlkem::ML_KEM_512_OID => Some(Self::MlKem512),
      mlkem::ML_KEM_768_OID => Some(Self::MlKem768),
      mlkem::ML_KEM_1024_OID => Some(Self::MlKem1024),
      _ => None,
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
  algorithm: Algorithm,
  raw: Box<[u8]>,
  spki: Box<[u8]>,
}

impl PublicKey {
  pub fn algorithm(&self) -> Algorithm {
    self.algorithm
  }

  pub fn raw(&self) -> &[u8] {
    &self.raw
  }

  pub fn spki(&self) -> &[u8] {
    &self.spki
  }

  pub fn verify(
    &self,
    data: &[u8],
    signature: &[u8],
    context: Option<&[u8]>,
  ) -> bool {
    self.algorithm.mldsa_variant().is_some_and(|variant| {
      mldsa::mldsa_verify(variant, &self.raw, data, signature, context)
    })
  }

  pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), ImportError> {
    let variant = self
      .algorithm
      .mlkem_variant()
      .ok_or(ImportError::UnsupportedKeyFormat)?;
    let key =
      aws_lc_rs::kem::EncapsulationKey::new(variant.algorithm(), &self.raw)
        .map_err(|_| ImportError::InvalidKeyData)?;
    let (ciphertext, shared_key) =
      key.encapsulate().map_err(|_| ImportError::InvalidKeyData)?;
    Ok((shared_key.as_ref().to_vec(), ciphertext.as_ref().to_vec()))
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateKey {
  algorithm: Algorithm,
  raw: Box<[u8]>,
  seed: Option<Box<[u8]>>,
  pkcs8: Box<[u8]>,
  public: PublicKey,
}

impl PrivateKey {
  pub fn algorithm(&self) -> Algorithm {
    self.algorithm
  }

  pub fn raw(&self) -> &[u8] {
    &self.raw
  }

  pub fn seed(&self) -> Option<&[u8]> {
    self.seed.as_deref()
  }

  pub fn pkcs8(&self) -> &[u8] {
    &self.pkcs8
  }

  pub fn public_key(&self) -> PublicKey {
    self.public.clone()
  }

  pub fn sign(
    &self,
    data: &[u8],
    context: Option<&[u8]>,
  ) -> Result<Vec<u8>, ImportError> {
    let variant = self
      .algorithm
      .mldsa_variant()
      .ok_or(ImportError::UnsupportedKeyFormat)?;
    mldsa::mldsa_sign(variant, &self.raw, data, context)
      .map_err(|_| ImportError::InvalidKeyData)
  }

  pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ImportError> {
    let variant = self
      .algorithm
      .mlkem_variant()
      .ok_or(ImportError::UnsupportedKeyFormat)?;
    if ciphertext.len() != variant.ciphertext_size() {
      return Err(ImportError::InvalidKeyData);
    }
    let key =
      aws_lc_rs::kem::DecapsulationKey::new(variant.algorithm(), &self.raw)
        .map_err(|_| ImportError::InvalidKeyData)?;
    let ciphertext = aws_lc_rs::kem::Ciphertext::from(ciphertext);
    let shared_key = key
      .decapsulate(ciphertext)
      .map_err(|_| ImportError::InvalidKeyData)?;
    Ok(shared_key.as_ref().to_vec())
  }
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
  #[error("invalid post-quantum key data")]
  InvalidKeyData,
  #[error("unsupported post-quantum key format")]
  UnsupportedKeyFormat,
}

fn export_spki(
  algorithm: Algorithm,
  raw: &[u8],
) -> Result<Vec<u8>, ImportError> {
  if let Some(variant) = algorithm.mldsa_variant() {
    mldsa::mldsa_export_spki(variant, raw)
      .map_err(|_| ImportError::InvalidKeyData)
  } else if let Some(variant) = algorithm.mlkem_variant() {
    mlkem::ml_kem_export_spki(variant, raw)
      .map_err(|_| ImportError::InvalidKeyData)
  } else {
    Err(ImportError::UnsupportedKeyFormat)
  }
}

pub fn import_public_spki(data: &[u8]) -> Result<PublicKey, ImportError> {
  let info = spki::SubjectPublicKeyInfoRef::try_from(data)
    .map_err(|_| ImportError::InvalidKeyData)?;
  if info.algorithm.parameters.is_some() {
    return Err(ImportError::InvalidKeyData);
  }
  let algorithm = Algorithm::from_oid(info.algorithm.oid)
    .ok_or(ImportError::InvalidKeyData)?;
  let raw = if let Some(variant) = algorithm.mldsa_variant() {
    mldsa::from_spki(variant, data).map_err(|_| ImportError::InvalidKeyData)?
  } else {
    let imported =
      mlkem::import_spki(data).map_err(|_| ImportError::InvalidKeyData)?;
    if Some(imported.variant) != algorithm.mlkem_variant() {
      return Err(ImportError::InvalidKeyData);
    }
    imported.public_key
  };
  Ok(PublicKey {
    algorithm,
    raw: raw.into_boxed_slice(),
    spki: data.to_vec().into_boxed_slice(),
  })
}

pub fn import_public_raw(
  algorithm: Algorithm,
  raw: &[u8],
) -> Result<PublicKey, ImportError> {
  let spki = export_spki(algorithm, raw)?;
  import_public_spki(&spki)
}

pub fn import_private_seed(
  algorithm: Algorithm,
  seed: &[u8],
) -> Result<PrivateKey, ImportError> {
  let (raw, public_raw, pkcs8) =
    if let Some(variant) = algorithm.mldsa_variant() {
      let (raw, public) = mldsa::mldsa_from_seed(variant, seed)
        .map_err(|_| ImportError::InvalidKeyData)?;
      let pkcs8 = mldsa::mldsa_export_pkcs8(variant, seed)
        .map_err(|_| ImportError::InvalidKeyData)?;
      (raw, public, pkcs8)
    } else if let Some(variant) = algorithm.mlkem_variant() {
      let expanded = mlkem::from_seed(variant, seed)
        .map_err(|_| ImportError::InvalidKeyData)?;
      let pkcs8 = mlkem::ml_kem_export_pkcs8(variant, seed)
        .map_err(|_| ImportError::InvalidKeyData)?;
      (expanded.private_key, expanded.public_key, pkcs8)
    } else {
      return Err(ImportError::UnsupportedKeyFormat);
    };
  let public = import_public_raw(algorithm, &public_raw)?;
  Ok(PrivateKey {
    algorithm,
    raw: raw.into_boxed_slice(),
    seed: Some(seed.to_vec().into_boxed_slice()),
    pkcs8: pkcs8.into_boxed_slice(),
    public,
  })
}

pub fn import_private_pkcs8(data: &[u8]) -> Result<PrivateKey, ImportError> {
  let info = rsa::pkcs8::PrivateKeyInfo::from_der(data)
    .map_err(|_| ImportError::InvalidKeyData)?;
  if info.algorithm.parameters.is_some() {
    return Err(ImportError::InvalidKeyData);
  }
  let algorithm = Algorithm::from_oid(info.algorithm.oid)
    .ok_or(ImportError::InvalidKeyData)?;
  let (raw, public_raw, seed) = if let Some(variant) = algorithm.mldsa_variant()
  {
    let imported = mldsa::from_pkcs8_native(variant, data)
      .map_err(|_| ImportError::InvalidKeyData)?;
    (imported.private_key, imported.public_key, imported.seed)
  } else if let Some(variant) = algorithm.mlkem_variant() {
    let imported = mlkem::import_pkcs8_native(data)
      .map_err(|_| ImportError::InvalidKeyData)?;
    let public = mlkem::public_from_expanded(variant, &imported.private_key)
      .map_err(|_| ImportError::InvalidKeyData)?;
    (imported.private_key, public, Some(imported.seed))
  } else {
    return Err(ImportError::UnsupportedKeyFormat);
  };
  let public = PublicKey {
    algorithm,
    spki: export_spki(algorithm, &public_raw)?.into_boxed_slice(),
    raw: public_raw.into_boxed_slice(),
  };
  Ok(PrivateKey {
    algorithm,
    raw: raw.into_boxed_slice(),
    seed: seed.map(Vec::into_boxed_slice),
    pkcs8: data.to_vec().into_boxed_slice(),
    public,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ml_kem_encapsulation_round_trip() {
    let private =
      import_private_seed(Algorithm::MlKem768, &[0x42; 64]).unwrap();
    let (shared_key, ciphertext) = private.public_key().encapsulate().unwrap();

    assert_eq!(private.decapsulate(&ciphertext).unwrap(), shared_key);
  }

  #[test]
  fn ml_kem_decapsulation_rejects_wrong_ciphertext_length() {
    let private =
      import_private_seed(Algorithm::MlKem768, &[0x42; 64]).unwrap();

    assert!(matches!(
      private.decapsulate(&[0; 1]),
      Err(ImportError::InvalidKeyData)
    ));
  }

  #[test]
  fn ml_dsa_keys_reject_kem_operations() {
    let private = import_private_seed(Algorithm::MlDsa44, &[0x42; 32]).unwrap();

    assert!(matches!(
      private.public_key().encapsulate(),
      Err(ImportError::UnsupportedKeyFormat)
    ));
    assert!(matches!(
      private.decapsulate(&[]),
      Err(ImportError::UnsupportedKeyFormat)
    ));
  }

  #[test]
  fn ml_dsa_context_separates_signatures() {
    let private = import_private_seed(Algorithm::MlDsa44, &[0x42; 32]).unwrap();
    let public = private.public_key();
    let signature = private.sign(b"message", Some(b"context-a")).unwrap();

    assert!(public.verify(b"message", &signature, Some(b"context-a")));
    assert!(!public.verify(b"message", &signature, Some(b"context-b")));
    assert!(!public.verify(b"message", &signature, None));
  }
}
