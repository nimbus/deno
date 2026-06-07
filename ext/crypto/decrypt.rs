// Copyright 2018-2026 the Deno authors. MIT license.

use aes::cipher::BlockDecryptMut;
use aes::cipher::KeyIvInit;
use aes::cipher::block_padding::Pkcs7;
use aes_gcm::AeadInPlace;
use aes_gcm::KeyInit;
use aes_gcm::Nonce;
use aes_gcm::aead::generic_array::ArrayLength;
use aes_gcm::aes::Aes128;
use aes_gcm::aes::Aes192;
use aes_gcm::aes::Aes256;
use aws_lc_rs::aead::Aad;
use aws_lc_rs::aead::CHACHA20_POLY1305;
use aws_lc_rs::aead::LessSafeKey;
use aws_lc_rs::aead::Nonce as AwsNonce;
use aws_lc_rs::aead::UnboundKey;
use ctr::Ctr32BE;
use ctr::Ctr64BE;
use ctr::Ctr128BE;
use ctr::cipher::StreamCipher;
use deno_core::JsBuffer;
use deno_core::convert::Uint8Array;
use deno_core::op2;
use deno_core::unsync::spawn_blocking;
use rsa::pkcs1::DecodeRsaPrivateKey;
use serde::Deserialize;
use sha1::Sha1;
use sha2::Sha256;
use sha2::Sha384;
use sha2::Sha512;
use sha3::Sha3_256;
use sha3::Sha3_384;
use sha3::Sha3_512;

use crate::shared::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptOptions {
  key: V8RawKeyData,
  #[serde(flatten)]
  algorithm: DecryptAlgorithm,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", tag = "algorithm")]
pub enum DecryptAlgorithm {
  #[serde(rename = "RSA-OAEP")]
  RsaOaep {
    hash: ShaHash,
    #[serde(with = "serde_bytes")]
    label: Vec<u8>,
  },
  #[serde(rename = "AES-CBC", rename_all = "camelCase")]
  AesCbc {
    #[serde(with = "serde_bytes")]
    iv: Vec<u8>,
    length: usize,
  },
  #[serde(rename = "AES-CTR", rename_all = "camelCase")]
  AesCtr {
    #[serde(with = "serde_bytes")]
    counter: Vec<u8>,
    ctr_length: usize,
    key_length: usize,
  },
  #[serde(rename = "AES-GCM", rename_all = "camelCase")]
  AesGcm {
    #[serde(with = "serde_bytes")]
    iv: Vec<u8>,
    #[serde(with = "serde_bytes")]
    additional_data: Option<Vec<u8>>,
    length: usize,
    tag_length: usize,
  },
  #[serde(rename = "AES-OCB", rename_all = "camelCase")]
  AesOcb {
    #[serde(with = "serde_bytes")]
    iv: Vec<u8>,
    #[serde(with = "serde_bytes")]
    additional_data: Option<Vec<u8>>,
    length: usize,
    tag_length: usize,
  },
  #[serde(rename = "ChaCha20-Poly1305", rename_all = "camelCase")]
  ChaCha20Poly1305 {
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    additional_data: Option<Vec<u8>>,
  },
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum DecryptError {
  #[class(inherit)]
  #[error(transparent)]
  General(
    #[from]
    #[inherit]
    SharedError,
  ),
  #[class(generic)]
  #[error(transparent)]
  Pkcs1(#[from] rsa::pkcs1::Error),
  #[class("DOMExceptionOperationError")]
  #[error("Decryption failed")]
  Failed,
  #[class(type)]
  #[error("invalid length")]
  InvalidLength,
  #[class(type)]
  #[error("invalid counter length. Currently supported 32/64/128 bits")]
  InvalidCounterLength,
  #[class(type)]
  #[error("tag length not equal to 128")]
  InvalidTagLength,
  #[class("DOMExceptionOperationError")]
  #[error("invalid key or iv")]
  InvalidKeyOrIv,
  #[class("DOMExceptionOperationError")]
  #[error("tried to decrypt too much data")]
  TooMuchData,
  #[class(type)]
  #[error("iv length not equal to 12 or 16")]
  InvalidIvLength,
  #[class(type)]
  #[error("invalid ChaCha20-Poly1305 nonce length: expected 12 bytes")]
  InvalidChaChaNonceLength,
  #[class(type)]
  #[error("invalid ChaCha20-Poly1305 key length: expected 32 bytes")]
  InvalidChaChaKeyLength,
  #[class("DOMExceptionOperationError")]
  #[error("{0}")]
  Rsa(rsa::Error),
}

#[op2]
pub async fn op_crypto_decrypt(
  #[serde] opts: DecryptOptions,
  #[buffer] data: JsBuffer,
) -> Result<Uint8Array, DecryptError> {
  let key = opts.key;
  let fun = move || match opts.algorithm {
    DecryptAlgorithm::RsaOaep { hash, label } => {
      decrypt_rsa_oaep(key, hash, label, &data)
    }
    DecryptAlgorithm::AesCbc { iv, length } => {
      decrypt_aes_cbc(key, length, iv, &data)
    }
    DecryptAlgorithm::AesCtr {
      counter,
      ctr_length,
      key_length,
    } => decrypt_aes_ctr(key, key_length, &counter, ctr_length, &data),
    DecryptAlgorithm::AesGcm {
      iv,
      additional_data,
      length,
      tag_length,
    } => decrypt_aes_gcm(key, length, tag_length, iv, additional_data, &data),
    DecryptAlgorithm::AesOcb {
      iv,
      additional_data,
      length,
      tag_length,
    } => decrypt_aes_ocb(key, length, tag_length, iv, additional_data, &data),
    DecryptAlgorithm::ChaCha20Poly1305 {
      nonce,
      additional_data,
    } => decrypt_chacha20_poly1305(key, &nonce, additional_data, &data),
  };
  let buf = spawn_blocking(fun).await.unwrap()?;
  Ok(buf.into())
}

fn decrypt_rsa_oaep(
  key: V8RawKeyData,
  hash: ShaHash,
  label: Vec<u8>,
  data: &[u8],
) -> Result<Vec<u8>, DecryptError> {
  let key = key.as_rsa_private_key()?;

  let private_key = rsa::RsaPrivateKey::from_pkcs1_der(key)?;
  let label = Some(String::from_utf8_lossy(&label).to_string());

  let padding = match hash {
    ShaHash::Sha1 => rsa::Oaep {
      digest: Box::<Sha1>::default(),
      mgf_digest: Box::<Sha1>::default(),
      label,
    },
    ShaHash::Sha256 => rsa::Oaep {
      digest: Box::<Sha256>::default(),
      mgf_digest: Box::<Sha256>::default(),
      label,
    },
    ShaHash::Sha384 => rsa::Oaep {
      digest: Box::<Sha384>::default(),
      mgf_digest: Box::<Sha384>::default(),
      label,
    },
    ShaHash::Sha512 => rsa::Oaep {
      digest: Box::<Sha512>::default(),
      mgf_digest: Box::<Sha512>::default(),
      label,
    },
    ShaHash::Sha3_256 => rsa::Oaep {
      digest: Box::<Sha3_256>::default(),
      mgf_digest: Box::<Sha3_256>::default(),
      label,
    },
    ShaHash::Sha3_384 => rsa::Oaep {
      digest: Box::<Sha3_384>::default(),
      mgf_digest: Box::<Sha3_384>::default(),
      label,
    },
    ShaHash::Sha3_512 => rsa::Oaep {
      digest: Box::<Sha3_512>::default(),
      mgf_digest: Box::<Sha3_512>::default(),
      label,
    },
  };

  private_key
    .decrypt(padding, data)
    .map_err(DecryptError::Rsa)
}

fn decrypt_aes_cbc(
  key: V8RawKeyData,
  length: usize,
  iv: Vec<u8>,
  data: &[u8],
) -> Result<Vec<u8>, DecryptError> {
  let key = key.as_secret_key()?;

  // 2.
  let plaintext = match length {
    128 => {
      // Section 10.3 Step 2 of RFC 2315 https://www.rfc-editor.org/rfc/rfc2315
      type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
      let cipher = Aes128CbcDec::new_from_slices(key, &iv)
        .map_err(|_| DecryptError::InvalidKeyOrIv)?;

      cipher
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| DecryptError::Failed)?
    }
    192 => {
      // Section 10.3 Step 2 of RFC 2315 https://www.rfc-editor.org/rfc/rfc2315
      type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
      let cipher = Aes192CbcDec::new_from_slices(key, &iv)
        .map_err(|_| DecryptError::InvalidKeyOrIv)?;

      cipher
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| DecryptError::Failed)?
    }
    256 => {
      // Section 10.3 Step 2 of RFC 2315 https://www.rfc-editor.org/rfc/rfc2315
      type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
      let cipher = Aes256CbcDec::new_from_slices(key, &iv)
        .map_err(|_| DecryptError::InvalidKeyOrIv)?;

      cipher
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| DecryptError::Failed)?
    }
    _ => unreachable!(),
  };

  // 6.
  Ok(plaintext)
}

fn decrypt_aes_ctr_gen<B>(
  key: &[u8],
  counter: &[u8],
  data: &[u8],
) -> Result<Vec<u8>, DecryptError>
where
  B: KeyIvInit + StreamCipher,
{
  let mut cipher = B::new(key.into(), counter.into());

  let mut plaintext = data.to_vec();
  cipher
    .try_apply_keystream(&mut plaintext)
    .map_err(|_| DecryptError::TooMuchData)?;

  Ok(plaintext)
}

/// Authenticate and decrypt an AES-GCM ciphertext in place, supporting the
/// truncated authentication tags that Web Crypto permits (32/64/96/104/112/120
/// bits in addition to the full 128). The `aes-gcm` crate only verifies a full
/// 16-byte tag, so for a truncated tag we reconstruct the real full tag and let
/// the crate authenticate the spliced candidate in constant time.
fn aes_gcm_open_in_place<A>(
  cipher: &A,
  nonce: &aes_gcm::aead::Nonce<A>,
  additional_data: &[u8],
  buffer: &mut [u8],
  provided_tag: &[u8],
) -> Result<(), DecryptError>
where
  A: AeadInPlace
    + aes_gcm::aead::AeadCore<
      TagSize = aes_gcm::aead::generic_array::typenum::U16,
    >,
{
  let tag_len = provided_tag.len();

  // Full 16-byte tag: the crate's native constant-time verification path.
  if tag_len == 16 {
    let tag = aes_gcm::aead::Tag::<A>::from_slice(provided_tag);
    return cipher
      .decrypt_in_place_detached(nonce, additional_data, buffer, tag)
      .map_err(|_| DecryptError::Failed);
  }

  // Truncated tag. GCM's CTR keystream depends only on key+nonce, so it is
  // symmetric: encrypting the ciphertext recovers the plaintext, and
  // re-encrypting that plaintext both restores the ciphertext and produces the
  // real 16-byte tag (GHASH is computed over the ciphertext). We never expose
  // the recovered plaintext: the buffer is only written below, gated on the
  // crate's constant-time authentication of the real ciphertext.
  let mut scratch = buffer.to_vec();
  cipher
    .encrypt_in_place_detached(nonce, additional_data, &mut scratch)
    .map_err(|_| DecryptError::Failed)?; // scratch == plaintext (tag discarded)
  let full_tag = cipher
    .encrypt_in_place_detached(nonce, additional_data, &mut scratch)
    .map_err(|_| DecryptError::Failed)?; // scratch == ciphertext again

  // Splice the caller's truncated prefix over the real tag. The suffix matches
  // by construction, so the crate's constant-time comparison reduces to checking
  // the truncated prefix - exactly GCM truncated-tag semantics.
  let mut candidate = full_tag;
  candidate[..tag_len].copy_from_slice(provided_tag);

  cipher
    .decrypt_in_place_detached(nonce, additional_data, buffer, &candidate)
    .map_err(|_| DecryptError::Failed)
}

fn decrypt_aes_gcm_gen<N: ArrayLength<u8>>(
  key: &[u8],
  provided_tag: &[u8],
  nonce: &[u8],
  length: usize,
  additional_data: Vec<u8>,
  buffer: &mut [u8],
) -> Result<(), DecryptError> {
  let nonce = Nonce::<N>::from_slice(nonce);
  match length {
    128 => {
      let cipher = aes_gcm::AesGcm::<Aes128, N>::new_from_slice(key)
        .map_err(|_| DecryptError::Failed)?;
      aes_gcm_open_in_place(
        &cipher,
        nonce,
        additional_data.as_slice(),
        buffer,
        provided_tag,
      )
    }
    192 => {
      let cipher = aes_gcm::AesGcm::<Aes192, N>::new_from_slice(key)
        .map_err(|_| DecryptError::Failed)?;
      aes_gcm_open_in_place(
        &cipher,
        nonce,
        additional_data.as_slice(),
        buffer,
        provided_tag,
      )
    }
    256 => {
      let cipher = aes_gcm::AesGcm::<Aes256, N>::new_from_slice(key)
        .map_err(|_| DecryptError::Failed)?;
      aes_gcm_open_in_place(
        &cipher,
        nonce,
        additional_data.as_slice(),
        buffer,
        provided_tag,
      )
    }
    _ => Err(DecryptError::InvalidLength),
  }
}

fn decrypt_aes_ctr(
  key: V8RawKeyData,
  key_length: usize,
  counter: &[u8],
  ctr_length: usize,
  data: &[u8],
) -> Result<Vec<u8>, DecryptError> {
  let key = key.as_secret_key()?;

  match ctr_length {
    32 => match key_length {
      128 => decrypt_aes_ctr_gen::<Ctr32BE<aes::Aes128>>(key, counter, data),
      192 => decrypt_aes_ctr_gen::<Ctr32BE<aes::Aes192>>(key, counter, data),
      256 => decrypt_aes_ctr_gen::<Ctr32BE<aes::Aes256>>(key, counter, data),
      _ => Err(DecryptError::InvalidLength),
    },
    64 => match key_length {
      128 => decrypt_aes_ctr_gen::<Ctr64BE<aes::Aes128>>(key, counter, data),
      192 => decrypt_aes_ctr_gen::<Ctr64BE<aes::Aes192>>(key, counter, data),
      256 => decrypt_aes_ctr_gen::<Ctr64BE<aes::Aes256>>(key, counter, data),
      _ => Err(DecryptError::InvalidLength),
    },
    128 => match key_length {
      128 => decrypt_aes_ctr_gen::<Ctr128BE<aes::Aes128>>(key, counter, data),
      192 => decrypt_aes_ctr_gen::<Ctr128BE<aes::Aes192>>(key, counter, data),
      256 => decrypt_aes_ctr_gen::<Ctr128BE<aes::Aes256>>(key, counter, data),
      _ => Err(DecryptError::InvalidLength),
    },
    _ => Err(DecryptError::InvalidCounterLength),
  }
}

fn decrypt_aes_gcm(
  key: V8RawKeyData,
  length: usize,
  tag_length: usize,
  iv: Vec<u8>,
  additional_data: Option<Vec<u8>>,
  data: &[u8],
) -> Result<Vec<u8>, DecryptError> {
  let key = key.as_secret_key()?;
  let additional_data = additional_data.unwrap_or_default();

  // Web Crypto permits these AES-GCM tag lengths (bits). The JS layer already
  // validates `tagLength` before reaching this op, so this guard is defensive.
  // Unlike the previous 128-only restriction, the decrypt path now mirrors the
  // encrypt path, which already truncates the 16-byte tag to any of these
  // lengths (`aes_gcm_open_in_place` reconstructs the full tag to verify a
  // truncated one in constant time).
  if !matches!(tag_length, 32 | 64 | 96 | 104 | 112 | 120 | 128) {
    return Err(DecryptError::InvalidTagLength);
  }

  let tag_byte_len = tag_length / 8;
  if data.len() < tag_byte_len {
    return Err(DecryptError::InvalidLength);
  }

  let sep = data.len() - tag_byte_len;
  let provided_tag = &data[sep..];

  // The actual ciphertext, called plaintext because it is reused in place.
  let mut plaintext = data[..sep].to_vec();

  // AES-GCM accepts any IV length; map the runtime length to the compile-time
  // nonce size the `aes-gcm` API requires (see `aes_gcm_nonce_dispatch!`).
  aes_gcm_nonce_dispatch!(
    iv.len(),
    return Err(DecryptError::InvalidIvLength),
    decrypt_aes_gcm_gen(
      key,
      provided_tag,
      &iv,
      length,
      additional_data,
      &mut plaintext
    )
  )?;

  Ok(plaintext)
}

fn decrypt_chacha20_poly1305(
  key: V8RawKeyData,
  nonce: &[u8],
  additional_data: Option<Vec<u8>>,
  data: &[u8],
) -> Result<Vec<u8>, DecryptError> {
  let key_bytes = key.as_secret_key()?;
  if key_bytes.len() != 32 {
    return Err(DecryptError::InvalidChaChaKeyLength);
  }
  if nonce.len() != 12 {
    return Err(DecryptError::InvalidChaChaNonceLength);
  }
  // 16-byte Poly1305 tag is appended.
  if data.len() < 16 {
    return Err(DecryptError::Failed);
  }

  let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes)
    .map_err(|_| DecryptError::Failed)?;
  let opening_key = LessSafeKey::new(unbound_key);
  let aws_nonce = AwsNonce::try_assume_unique_for_key(nonce)
    .map_err(|_| DecryptError::Failed)?;
  let aad = additional_data.unwrap_or_default();

  let mut in_out = data.to_vec();
  let plaintext = opening_key
    .open_in_place(aws_nonce, Aad::from(&aad), &mut in_out)
    .map_err(|_| DecryptError::Failed)?;

  Ok(plaintext.to_vec())
}

fn decrypt_aes_ocb(
  key: V8RawKeyData,
  length: usize,
  tag_length: usize,
  iv: Vec<u8>,
  additional_data: Option<Vec<u8>>,
  data: &[u8],
) -> Result<Vec<u8>, DecryptError> {
  use aes_gcm::aead::generic_array::GenericArray;
  use ocb3::Ocb3;
  use ocb3::aead::AeadInPlace as Ocb3AeadInPlace;
  use ocb3::aead::KeyInit as Ocb3KeyInit;

  let key = key.as_secret_key()?;
  let additional_data = additional_data.unwrap_or_default();

  // The `ocb3` crate only supports 128 bits tag length.
  //
  // Note that encryption won't fail, it instead truncates the tag
  // to the specified tag length as specified in the spec.
  if tag_length != 128 {
    return Err(DecryptError::InvalidTagLength);
  }

  // OCB supports nonce sizes from 1 to 15 bytes (recommended: 12 bytes)
  if iv.is_empty() || iv.len() > 15 {
    return Err(DecryptError::InvalidIvLength);
  }

  let sep = data.len() - (tag_length / 8);
  let tag_bytes = &data[sep..];

  // The actual ciphertext, called plaintext because it is reused in place.
  let mut plaintext = data[..sep].to_vec();

  let nonce = GenericArray::from_slice(&iv);
  let tag = GenericArray::from_slice(tag_bytes);

  match length {
    128 => {
      let cipher = Ocb3::<aes::Aes128>::new_from_slice(key)
        .map_err(|_| DecryptError::Failed)?;
      cipher
        .decrypt_in_place_detached(nonce, &additional_data, &mut plaintext, tag)
        .map_err(|_| DecryptError::Failed)?;
    }
    192 => {
      let cipher = Ocb3::<aes::Aes192>::new_from_slice(key)
        .map_err(|_| DecryptError::Failed)?;
      cipher
        .decrypt_in_place_detached(nonce, &additional_data, &mut plaintext, tag)
        .map_err(|_| DecryptError::Failed)?;
    }
    256 => {
      let cipher = Ocb3::<aes::Aes256>::new_from_slice(key)
        .map_err(|_| DecryptError::Failed)?;
      cipher
        .decrypt_in_place_detached(nonce, &additional_data, &mut plaintext, tag)
        .map_err(|_| DecryptError::Failed)?;
    }
    _ => return Err(DecryptError::InvalidLength),
  }

  Ok(plaintext)
}
