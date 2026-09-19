// Copyright 2018-2026 the Deno authors. MIT license.

//! AES-CCM with the OpenSSL 3.0 provider state machine.
//!
//! Node.js drives CCM through `EVP_CipherUpdate` calls whose results depend
//! on provider state (`iv_set`, `len_set`, `tag_set`) and on the CCM128
//! nonce block, which OpenSSL also uses to hold the message length. This
//! module follows `providers/implementations/ciphers/ciphercommon_ccm.c` and
//! `crypto/modes/ccm128.c` step by step, so a call sequence that OpenSSL
//! accepts, rejects or authenticates gives the same result here.

use subtle::ConstantTimeEq;

use super::aes_block::AesBlock;
use super::aes_block::Block;
use super::aes_block::xor_block;

/// The failures of `EVP_CTRL_AEAD_GET_TAG`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CcmGetTagError {
  /// OpenSSL raises `PROV_R_TAG_NOT_SET` to the error queue.
  TagNotSet,
  /// `CRYPTO_ccm128_tag` rejected the length. Nothing is raised.
  Failed,
}

/// `CCM128_CONTEXT`.
struct Ccm128 {
  nonce: Block,
  cmac: Block,
  blocks: u64,
}

impl Ccm128 {
  /// `CRYPTO_ccm128_init`.
  fn new(m: usize, l: usize) -> Self {
    let mut nonce = [0u8; 16];
    nonce[0] = ((l.wrapping_sub(1) as u8) & 7)
      | ((((m.wrapping_sub(2)) / 2) as u8 & 7) << 3);
    Self {
      nonce,
      cmac: [0u8; 16],
      blocks: 0,
    }
  }

  /// `CRYPTO_ccm128_setiv`.
  fn set_iv(&mut self, iv: &[u8], mlen: u64) -> bool {
    let l = (self.nonce[0] & 7) as usize;
    if iv.len() < 14 - l {
      return false;
    }
    if l >= 3 {
      self.nonce[8] = (mlen >> 56) as u8;
      self.nonce[9] = (mlen >> 48) as u8;
      self.nonce[10] = (mlen >> 40) as u8;
      self.nonce[11] = (mlen >> 32) as u8;
    } else {
      self.nonce[8..16].fill(0);
    }
    self.nonce[12] = (mlen >> 24) as u8;
    self.nonce[13] = (mlen >> 16) as u8;
    self.nonce[14] = (mlen >> 8) as u8;
    self.nonce[15] = mlen as u8;
    self.nonce[0] &= !0x40;
    self.nonce[1..15 - l].copy_from_slice(&iv[..14 - l]);
    true
  }

  /// `CRYPTO_ccm128_aad`.
  fn aad(&mut self, block: &AesBlock, aad: &[u8]) {
    let mut alen = aad.len() as u64;
    if alen == 0 {
      return;
    }
    self.nonce[0] |= 0x40;
    self.cmac = block.encrypt(&self.nonce);
    self.blocks = self.blocks.wrapping_add(1);
    let mut i;
    if alen < 0x10000 - 0x100 {
      self.cmac[0] ^= (alen >> 8) as u8;
      self.cmac[1] ^= alen as u8;
      i = 2;
    } else if alen >= 1 << 32 {
      self.cmac[0] ^= 0xFF;
      self.cmac[1] ^= 0xFF;
      for (k, shift) in (2..10).zip((0..8).rev()) {
        self.cmac[k] ^= (alen >> (shift * 8)) as u8;
      }
      i = 10;
    } else {
      self.cmac[0] ^= 0xFF;
      self.cmac[1] ^= 0xFE;
      for (k, shift) in (2..6).zip((0..4).rev()) {
        self.cmac[k] ^= (alen >> (shift * 8)) as u8;
      }
      i = 6;
    }
    let mut pos = 0;
    loop {
      while i < 16 && alen > 0 {
        self.cmac[i] ^= aad[pos];
        i += 1;
        pos += 1;
        alen -= 1;
      }
      self.cmac = block.encrypt(&self.cmac);
      self.blocks = self.blocks.wrapping_add(1);
      i = 0;
      if alen == 0 {
        break;
      }
    }
  }

  /// The shared start of `CRYPTO_ccm128_encrypt` and `_decrypt`. Returns
  /// `flags0` and the reconstructed message length.
  fn begin(&mut self, block: &AesBlock, count_block: bool) -> (u8, u64) {
    let flags0 = self.nonce[0];
    if flags0 & 0x40 == 0 {
      self.cmac = block.encrypt(&self.nonce);
      if count_block {
        self.blocks = self.blocks.wrapping_add(1);
      }
    }
    let l = flags0 & 7;
    self.nonce[0] = l;
    let mut n: u64 = 0;
    for i in (15 - l as usize)..15 {
      n |= self.nonce[i] as u64;
      self.nonce[i] = 0;
      n <<= 8;
    }
    n |= self.nonce[15] as u64;
    self.nonce[15] = 1;
    (flags0, n)
  }

  /// The shared end of `CRYPTO_ccm128_encrypt` and `_decrypt`.
  fn finish(&mut self, block: &AesBlock, flags0: u8) {
    let l = (flags0 & 7) as usize;
    self.nonce[15 - l..16].fill(0);
    let scratch = block.encrypt(&self.nonce);
    self.cmac = xor_block(&self.cmac, &scratch);
    self.nonce[0] = flags0;
  }

  /// `ctr64_inc`.
  fn ctr64_inc(&mut self) {
    for i in (8..16).rev() {
      self.nonce[i] = self.nonce[i].wrapping_add(1);
      if self.nonce[i] != 0 {
        return;
      }
    }
  }

  /// `CRYPTO_ccm128_encrypt`.
  fn encrypt(
    &mut self,
    block: &AesBlock,
    input: &[u8],
    out: &mut [u8],
  ) -> bool {
    let (flags0, n) = self.begin(block, true);
    let len = input.len();
    if n != len as u64 {
      return false;
    }
    self.blocks = self.blocks.wrapping_add((((len as u64) + 15) >> 3) | 1);
    if self.blocks > 1 << 61 {
      return false;
    }
    let mut pos = 0;
    while len - pos >= 16 {
      for i in 0..16 {
        self.cmac[i] ^= input[pos + i];
      }
      self.cmac = block.encrypt(&self.cmac);
      let scratch = block.encrypt(&self.nonce);
      self.ctr64_inc();
      for i in 0..16 {
        out[pos + i] = input[pos + i] ^ scratch[i];
      }
      pos += 16;
    }
    let rest = len - pos;
    if rest > 0 {
      for i in 0..rest {
        self.cmac[i] ^= input[pos + i];
      }
      self.cmac = block.encrypt(&self.cmac);
      let scratch = block.encrypt(&self.nonce);
      for i in 0..rest {
        out[pos + i] = scratch[i] ^ input[pos + i];
      }
    }
    self.finish(block, flags0);
    true
  }

  /// `CRYPTO_ccm128_decrypt`.
  fn decrypt(
    &mut self,
    block: &AesBlock,
    input: &[u8],
    out: &mut [u8],
  ) -> bool {
    let (flags0, n) = self.begin(block, false);
    let len = input.len();
    if n != len as u64 {
      return false;
    }
    let mut pos = 0;
    while len - pos >= 16 {
      let scratch = block.encrypt(&self.nonce);
      self.ctr64_inc();
      for i in 0..16 {
        out[pos + i] = scratch[i] ^ input[pos + i];
        self.cmac[i] ^= out[pos + i];
      }
      self.cmac = block.encrypt(&self.cmac);
      pos += 16;
    }
    let rest = len - pos;
    if rest > 0 {
      let scratch = block.encrypt(&self.nonce);
      for i in 0..rest {
        out[pos + i] = scratch[i] ^ input[pos + i];
        self.cmac[i] ^= out[pos + i];
      }
      self.cmac = block.encrypt(&self.cmac);
    }
    self.finish(block, flags0);
    true
  }

  /// `CRYPTO_ccm128_tag`.
  fn tag(&self, len: usize) -> Option<&[u8]> {
    let m = (((self.nonce[0] >> 3) & 7) as usize) * 2 + 2;
    if len != m {
      return None;
    }
    Some(&self.cmac[..m])
  }
}

/// `PROV_CCM_CTX` with the key set.
pub(super) struct CcmProvider {
  block: AesBlock,
  enc: bool,
  l: usize,
  m: usize,
  iv: [u8; 15],
  buf: [u8; 16],
  iv_set: bool,
  tag_set: bool,
  len_set: bool,
  ccm: Ccm128,
}

impl CcmProvider {
  /// The Node.js `CipherBase::CommonInit` sequence: set the IV length, set
  /// the tag length, then set the key and IV. Returns the step that failed.
  pub(super) fn new(
    block: AesBlock,
    enc: bool,
    iv: &[u8],
    tag_len: usize,
  ) -> Result<Self, CcmInitError> {
    // OSSL_CIPHER_PARAM_AEAD_IVLEN: L = 15 - ivlen, and L must be 2..8.
    let l = 15usize.wrapping_sub(iv.len());
    if !(2..=8).contains(&l) {
      return Err(CcmInitError::IvLength);
    }
    // OSSL_CIPHER_PARAM_AEAD_TAG without data.
    if tag_len & 1 != 0 || !(4..=16).contains(&tag_len) {
      return Err(CcmInitError::TagLength);
    }
    let mut stored_iv = [0u8; 15];
    stored_iv[..iv.len()].copy_from_slice(iv);
    Ok(Self {
      block,
      enc,
      l,
      m: tag_len,
      iv: stored_iv,
      buf: [0u8; 16],
      iv_set: true,
      tag_set: false,
      len_set: false,
      ccm: Ccm128::new(tag_len, l),
    })
  }

  fn iv_len(&self) -> usize {
    15 - self.l
  }

  /// `ccm_set_iv`.
  fn set_message_len(&mut self, mlen: u64) -> bool {
    let iv_len = self.iv_len();
    if !self.ccm.set_iv(&self.iv[..iv_len], mlen) {
      return false;
    }
    self.len_set = true;
    true
  }

  /// `OSSL_CIPHER_PARAM_AEAD_TAG` with data (decryption only).
  pub(super) fn set_tag(&mut self, tag: &[u8]) -> bool {
    if tag.len() & 1 != 0 || !(4..=16).contains(&tag.len()) {
      return false;
    }
    if self.enc {
      return false;
    }
    self.buf[..tag.len()].copy_from_slice(tag);
    self.tag_set = true;
    self.m = tag.len();
    true
  }

  /// `EVP_CipherUpdate(ctx, NULL, &outl, NULL, len)`.
  pub(super) fn update_message_len(&mut self, mlen: u64) -> bool {
    if !self.iv_set {
      return false;
    }
    self.set_message_len(mlen)
  }

  /// `EVP_CipherUpdate(ctx, NULL, &outl, aad, len)`.
  pub(super) fn update_aad(&mut self, aad: &[u8]) -> bool {
    if !self.iv_set {
      return false;
    }
    if !self.len_set && !aad.is_empty() {
      return false;
    }
    self.ccm.aad(&self.block, aad);
    true
  }

  /// `EVP_CipherUpdate(ctx, out, &outl, in, len)`. On failure the output is
  /// empty.
  pub(super) fn update_data(&mut self, input: &[u8]) -> Option<Vec<u8>> {
    if !self.iv_set {
      return None;
    }
    if !self.len_set && !self.set_message_len(input.len() as u64) {
      return None;
    }
    let mut out = vec![0u8; input.len()];
    if self.enc {
      if !self.ccm.encrypt(&self.block, input, &mut out) {
        return None;
      }
      self.tag_set = true;
    } else {
      if !self.tag_set {
        return None;
      }
      let authenticated = self.ccm.decrypt(&self.block, input, &mut out)
        && self
          .ccm
          .tag(self.m)
          .is_some_and(|tag| bool::from(tag.ct_eq(&self.buf[..self.m])));
      if !authenticated {
        out.fill(0);
        return None;
      }
      self.iv_set = false;
      self.tag_set = false;
      self.len_set = false;
    }
    Some(out)
  }

  /// `EVP_CipherFinal_ex`. CCM gives no output at final.
  pub(super) fn finalize(&mut self) -> bool {
    true
  }

  /// `EVP_CTRL_AEAD_GET_TAG`.
  pub(super) fn get_tag(
    &mut self,
    len: usize,
  ) -> Result<Vec<u8>, CcmGetTagError> {
    if !self.enc || !self.tag_set {
      return Err(CcmGetTagError::TagNotSet);
    }
    let tag = self.ccm.tag(len).ok_or(CcmGetTagError::Failed)?.to_vec();
    self.tag_set = false;
    self.iv_set = false;
    self.len_set = false;
    Ok(tag)
  }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CcmInitError {
  IvLength,
  TagLength,
}

#[cfg(test)]
mod tests {
  use super::*;

  fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
  }

  fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
      .step_by(2)
      .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
      .collect()
  }

  fn provider(key: &[u8], iv: &[u8], tag_len: usize, enc: bool) -> CcmProvider {
    CcmProvider::new(AesBlock::new(key).unwrap(), enc, iv, tag_len).unwrap()
  }

  // RFC 3610 packet vector #1.
  #[test]
  fn rfc3610_packet_vector_1() {
    let key = unhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    let nonce = unhex("00000003020100a0a1a2a3a4a5");
    let aad = unhex("0001020304050607");
    let pt = unhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    let mut p = provider(&key, &nonce, 8, true);
    assert!(p.update_message_len(pt.len() as u64));
    assert!(p.update_aad(&aad));
    let ct = p.update_data(&pt).unwrap();
    assert!(p.finalize());
    let tag = p.get_tag(8).unwrap();
    assert_eq!(hex(&ct), "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384");
    assert_eq!(hex(&tag), "17e8d12cfdf926e0");

    let mut d = provider(&key, &nonce, 8, false);
    assert!(d.set_tag(&tag));
    assert!(d.update_message_len(ct.len() as u64));
    assert!(d.update_aad(&aad));
    assert_eq!(d.update_data(&ct).unwrap(), pt);
  }

  // Node.js v20.20.2: aes-128-ccm, IV of 7 bytes of 5, tag of 16 bytes.
  #[test]
  fn node20_ccm_iv7_tag16() {
    let key = [1u8; 16];
    let iv = [5u8; 7];
    let pt = b"ccm message 21 bytes!";
    let mut p = provider(&key, &iv, 16, true);
    assert!(p.update_message_len(pt.len() as u64));
    assert!(p.update_aad(b"header"));
    let ct = p.update_data(pt).unwrap();
    assert_eq!(hex(&ct), "03c670bcb1ea09e6a444bebf9b526e3eda6d337884");
    assert_eq!(
      hex(&p.get_tag(16).unwrap()),
      "7364c94f763f89f7ab43e13ddc929c02"
    );
  }

  // Node.js v20.20.2: a second data update fails because the length field
  // of the nonce was consumed, and GET_TAG then fails with no error raised.
  #[test]
  fn node20_second_update_corrupts_state() {
    let mut p = provider(&[1u8; 16], &[0u8; 12], 8, true);
    assert_eq!(hex(&p.update_data(b"abc").unwrap()), "6ed004");
    assert_eq!(p.update_data(b"de"), None);
    assert_eq!(p.get_tag(8), Err(CcmGetTagError::Failed));
  }

  // Node.js v20.20.2: AAD after the data restarts the MAC.
  #[test]
  fn node20_late_aad() {
    let mut p = provider(&[1u8; 16], &[0u8; 12], 8, true);
    assert_eq!(hex(&p.update_data(b"abc").unwrap()), "6ed004");
    assert!(p.update_message_len(3));
    assert!(p.update_aad(b"x"));
    assert!(p.finalize());
    assert_eq!(hex(&p.get_tag(8).unwrap()), "3607f1f59c4bf657");

    let mut p = provider(&[1u8; 16], &[0u8; 12], 8, true);
    assert_eq!(hex(&p.update_data(b"abc").unwrap()), "6ed004");
    assert!(p.update_message_len(3));
    assert!(p.update_aad(b"x"));
    assert_eq!(hex(&p.update_data(b"def").unwrap()), "6bd701");
    assert_eq!(hex(&p.get_tag(8).unwrap()), "43b766e5e1634fb0");
  }

  // Node.js v20.20.2: an empty data update sets the length to zero.
  #[test]
  fn node20_empty_update() {
    let mut p = provider(&[1u8; 16], &[0u8; 12], 8, true);
    assert_eq!(p.update_data(b"").unwrap(), Vec::<u8>::new());
    assert_eq!(hex(&p.get_tag(8).unwrap()), "07f9cc3d59a9caa6");
    let mut p = provider(&[1u8; 16], &[0u8; 12], 8, true);
    assert_eq!(p.update_data(b"").unwrap(), Vec::<u8>::new());
    assert_eq!(p.update_data(b"abc"), None);
  }

  // Node.js v20.20.2: GET_TAG without data raises PROV_R_TAG_NOT_SET.
  #[test]
  fn node20_tag_not_set() {
    let mut p = provider(&[1u8; 16], &[0u8; 12], 8, true);
    assert_eq!(p.get_tag(8), Err(CcmGetTagError::TagNotSet));
  }

  // Node.js v20.20.2: AAD of 0xff00 bytes uses the 6-byte length prefix.
  #[test]
  fn node20_long_aad() {
    let mut p = provider(&[1u8; 16], &[0u8; 12], 8, true);
    assert!(p.update_message_len(3));
    assert!(p.update_aad(&vec![7u8; 0xff00]));
    assert_eq!(hex(&p.update_data(b"abc").unwrap()), "6ed004");
    assert_eq!(hex(&p.get_tag(8).unwrap()), "1c4734ae0d7e0b01");
  }

  // Node.js v20.20.2: 40 bytes cross two full blocks and a partial block.
  #[test]
  fn node20_multi_block() {
    let mut p = provider(&[1u8; 16], &[0u8; 12], 8, true);
    assert!(p.update_message_len(40));
    assert!(p.update_aad(b"hdr"));
    let ct = p.update_data(&[9u8; 40]).unwrap();
    assert_eq!(
      hex(&ct),
      "06bb6e5c8b2756118ed7c82d63b1d0c6ad53f44db7cb373f625e07c6dd03ed4d663ed1824f0d02c8"
    );
    assert_eq!(hex(&p.get_tag(8).unwrap()), "76aa539eac89b333");
    let mut d = provider(&[1u8; 16], &[0u8; 12], 8, false);
    assert!(d.set_tag(&unhex("76aa539eac89b333")));
    assert!(d.update_message_len(40));
    assert!(d.update_aad(b"hdr"));
    assert_eq!(d.update_data(&ct).unwrap(), vec![9u8; 40]);
  }

  #[test]
  fn decrypt_rejects_wrong_tag_and_clears_output() {
    let mut d = provider(&[1u8; 16], &[0u8; 12], 8, false);
    assert!(d.set_tag(&[0u8; 8]));
    assert_eq!(d.update_data(&unhex("6ed004")), None);
  }

  #[test]
  fn decrypt_requires_tag() {
    let mut d = provider(&[1u8; 16], &[0u8; 12], 8, false);
    assert_eq!(d.update_data(b"abc"), None);
  }

  #[test]
  fn init_validates_lengths() {
    let block = || AesBlock::new(&[1u8; 16]).unwrap();
    assert!(CcmProvider::new(block(), true, &[0u8; 6], 8).is_err());
    assert!(CcmProvider::new(block(), true, &[0u8; 14], 8).is_err());
    assert!(CcmProvider::new(block(), true, &[0u8; 7], 8).is_ok());
    assert!(CcmProvider::new(block(), true, &[0u8; 13], 8).is_ok());
    assert!(CcmProvider::new(block(), true, &[0u8; 12], 5).is_err());
    assert!(CcmProvider::new(block(), true, &[0u8; 12], 2).is_err());
    assert!(CcmProvider::new(block(), true, &[0u8; 12], 18).is_err());
  }
}
