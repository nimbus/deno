// Copyright 2018-2026 the Deno authors. MIT license.

//! The AES block function that the CCM and OCB modes use.

use aes::cipher::BlockDecrypt;
use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit;
use aes::cipher::generic_array::GenericArray;

pub(super) type Block = [u8; 16];

pub(super) enum AesBlock {
  Aes128(Box<aes::Aes128>),
  Aes192(Box<aes::Aes192>),
  Aes256(Box<aes::Aes256>),
}

impl AesBlock {
  /// Returns `None` when the key length is not 16, 24 or 32 bytes.
  pub(super) fn new(key: &[u8]) -> Option<Self> {
    Some(match key.len() {
      16 => Self::Aes128(Box::new(aes::Aes128::new_from_slice(key).ok()?)),
      24 => Self::Aes192(Box::new(aes::Aes192::new_from_slice(key).ok()?)),
      32 => Self::Aes256(Box::new(aes::Aes256::new_from_slice(key).ok()?)),
      _ => return None,
    })
  }

  pub(super) fn encrypt(&self, block: &Block) -> Block {
    let mut out = *block;
    let b = GenericArray::from_mut_slice(&mut out);
    match self {
      Self::Aes128(c) => c.encrypt_block(b),
      Self::Aes192(c) => c.encrypt_block(b),
      Self::Aes256(c) => c.encrypt_block(b),
    }
    out
  }

  pub(super) fn decrypt(&self, block: &Block) -> Block {
    let mut out = *block;
    let b = GenericArray::from_mut_slice(&mut out);
    match self {
      Self::Aes128(c) => c.decrypt_block(b),
      Self::Aes192(c) => c.decrypt_block(b),
      Self::Aes256(c) => c.decrypt_block(b),
    }
    out
  }
}

pub(super) fn xor_block(a: &Block, b: &Block) -> Block {
  let mut out = [0u8; 16];
  for i in 0..16 {
    out[i] = a[i] ^ b[i];
  }
  out
}
