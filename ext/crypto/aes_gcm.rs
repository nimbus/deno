// Copyright 2018-2026 the Deno authors. MIT license.

use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U16;
use ghash::GHash;
use ghash::universal_hash::KeyInit as UniversalHashKeyInit;
use ghash::universal_hash::UniversalHash;
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AesGcmError {
  AuthenticationFailed,
  InvalidIvLength,
  InvalidKeyLength,
  InvalidTagLength,
  TooMuchData,
}

enum AesCipher {
  Aes128(aes::Aes128),
  Aes192(aes::Aes192),
  Aes256(aes::Aes256),
}

impl AesCipher {
  fn new(key: &[u8]) -> Result<Self, AesGcmError> {
    match key.len() {
      16 => aes::Aes128::new_from_slice(key)
        .map(Self::Aes128)
        .map_err(|_| AesGcmError::InvalidKeyLength),
      24 => aes::Aes192::new_from_slice(key)
        .map(Self::Aes192)
        .map_err(|_| AesGcmError::InvalidKeyLength),
      32 => aes::Aes256::new_from_slice(key)
        .map(Self::Aes256)
        .map_err(|_| AesGcmError::InvalidKeyLength),
      _ => Err(AesGcmError::InvalidKeyLength),
    }
  }

  fn encrypt_block(&self, block: &mut [u8; 16]) {
    let mut encrypted = GenericArray::<u8, U16>::clone_from_slice(block);
    match self {
      Self::Aes128(cipher) => cipher.encrypt_block(&mut encrypted),
      Self::Aes192(cipher) => cipher.encrypt_block(&mut encrypted),
      Self::Aes256(cipher) => cipher.encrypt_block(&mut encrypted),
    }
    block.copy_from_slice(&encrypted);
  }
}

fn bit_length(len: usize) -> Result<u64, AesGcmError> {
  u64::try_from(len)
    .ok()
    .and_then(|len| len.checked_mul(8))
    .ok_or(AesGcmError::TooMuchData)
}

fn new_ghash(cipher: &AesCipher) -> GHash {
  let mut hash_key = [0_u8; 16];
  cipher.encrypt_block(&mut hash_key);
  let hash_key = ghash::Key::clone_from_slice(&hash_key);
  <GHash as UniversalHashKeyInit>::new(&hash_key)
}

fn initial_counter(
  cipher: &AesCipher,
  iv: &[u8],
) -> Result<[u8; 16], AesGcmError> {
  if iv.is_empty() {
    return Err(AesGcmError::InvalidIvLength);
  }

  if iv.len() == 12 {
    let mut counter = [0_u8; 16];
    counter[..12].copy_from_slice(iv);
    counter[15] = 1;
    return Ok(counter);
  }

  let mut ghash = new_ghash(cipher);
  ghash.update_padded(iv);
  let mut length_block = ghash::Block::default();
  length_block[8..].copy_from_slice(&bit_length(iv.len())?.to_be_bytes());
  ghash.update(&[length_block]);
  Ok(ghash.finalize().into())
}

fn authentication_tag(
  cipher: &AesCipher,
  initial_counter: &[u8; 16],
  additional_data: &[u8],
  ciphertext: &[u8],
) -> Result<[u8; 16], AesGcmError> {
  let mut ghash = new_ghash(cipher);
  ghash.update_padded(additional_data);
  ghash.update_padded(ciphertext);

  let mut length_block = ghash::Block::default();
  length_block[..8]
    .copy_from_slice(&bit_length(additional_data.len())?.to_be_bytes());
  length_block[8..]
    .copy_from_slice(&bit_length(ciphertext.len())?.to_be_bytes());
  ghash.update(&[length_block]);

  let mut tag: [u8; 16] = ghash.finalize().into();
  let mut mask = *initial_counter;
  cipher.encrypt_block(&mut mask);
  for (tag_byte, mask_byte) in tag.iter_mut().zip(mask) {
    *tag_byte ^= mask_byte;
  }
  Ok(tag)
}

fn apply_counter_mode(
  cipher: &AesCipher,
  initial_counter: &[u8; 16],
  data: &mut [u8],
) -> Result<(), AesGcmError> {
  let block_count = data.len().div_ceil(16);
  if block_count > (u32::MAX as usize - 1) {
    return Err(AesGcmError::TooMuchData);
  }

  let mut counter = *initial_counter;
  for chunk in data.chunks_mut(16) {
    let next =
      u32::from_be_bytes(counter[12..].try_into().unwrap()).wrapping_add(1);
    counter[12..].copy_from_slice(&next.to_be_bytes());
    let mut key_stream = counter;
    cipher.encrypt_block(&mut key_stream);
    for (byte, key_byte) in chunk.iter_mut().zip(key_stream) {
      *byte ^= key_byte;
    }
  }
  Ok(())
}

fn tag_size(tag_length: usize) -> Result<usize, AesGcmError> {
  match tag_length {
    32 | 64 | 96 | 104 | 112 | 120 | 128 => Ok(tag_length / 8),
    _ => Err(AesGcmError::InvalidTagLength),
  }
}

pub(crate) fn encrypt(
  key: &[u8],
  tag_length: usize,
  iv: &[u8],
  additional_data: &[u8],
  plaintext: &[u8],
) -> Result<Vec<u8>, AesGcmError> {
  let tag_size = tag_size(tag_length)?;
  let cipher = AesCipher::new(key)?;
  let initial_counter = initial_counter(&cipher, iv)?;
  let mut ciphertext = plaintext.to_vec();
  apply_counter_mode(&cipher, &initial_counter, &mut ciphertext)?;
  let tag = authentication_tag(
    &cipher,
    &initial_counter,
    additional_data,
    &ciphertext,
  )?;
  ciphertext.extend_from_slice(&tag[..tag_size]);
  Ok(ciphertext)
}

pub(crate) fn decrypt(
  key: &[u8],
  tag_length: usize,
  iv: &[u8],
  additional_data: &[u8],
  data: &[u8],
) -> Result<Vec<u8>, AesGcmError> {
  let tag_size = tag_size(tag_length)?;
  let split = data
    .len()
    .checked_sub(tag_size)
    .ok_or(AesGcmError::AuthenticationFailed)?;
  let (ciphertext, tag) = data.split_at(split);
  let cipher = AesCipher::new(key)?;
  let initial_counter = initial_counter(&cipher, iv)?;
  let expected_tag =
    authentication_tag(&cipher, &initial_counter, additional_data, ciphertext)?;
  if expected_tag[..tag_size].ct_eq(tag).unwrap_u8() != 1 {
    return Err(AesGcmError::AuthenticationFailed);
  }

  let mut plaintext = ciphertext.to_vec();
  apply_counter_mode(&cipher, &initial_counter, &mut plaintext)?;
  Ok(plaintext)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn nist_zero_key_vector() {
    let key = [0_u8; 16];
    let iv = [0_u8; 12];
    let plaintext = [0_u8; 16];
    let encrypted = encrypt(&key, 128, &iv, &[], &plaintext).unwrap();
    assert_eq!(
      encrypted,
      [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9,
        0x71, 0xb2, 0xfe, 0x78, 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
      ]
    );
    assert_eq!(decrypt(&key, 128, &iv, &[], &encrypted).unwrap(), plaintext);
  }

  #[test]
  fn arbitrary_iv_and_truncated_tag_round_trip() {
    let key = [0x42_u8; 24];
    let iv = [0x24_u8; 31];
    let additional_data = b"authenticated";
    let plaintext = b"Nimbus WebCrypto";
    let encrypted = encrypt(&key, 64, &iv, additional_data, plaintext).unwrap();
    assert_eq!(
      decrypt(&key, 64, &iv, additional_data, &encrypted).unwrap(),
      plaintext
    );
  }

  #[test]
  fn rejects_empty_iv() {
    let key = [0_u8; 16];
    assert_eq!(
      encrypt(&key, 128, &[], &[], b"plaintext"),
      Err(AesGcmError::InvalidIvLength)
    );
    assert_eq!(
      decrypt(&key, 128, &[], &[], &[0_u8; 16]),
      Err(AesGcmError::InvalidIvLength)
    );
  }

  #[test]
  fn rejects_modified_truncated_tag() {
    let key = [0x42_u8; 32];
    let mut encrypted = encrypt(&key, 32, b"iv", b"aad", b"value").unwrap();
    *encrypted.last_mut().unwrap() ^= 1;
    assert_eq!(
      decrypt(&key, 32, b"iv", b"aad", &encrypted),
      Err(AesGcmError::AuthenticationFailed)
    );
  }
}
