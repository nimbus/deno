// Copyright 2018-2026 the Deno authors. MIT license.

//! AES-OCB (RFC 7253) with the OpenSSL 3.0 provider state machine.
//!
//! This module follows `providers/implementations/ciphers/cipher_aes_ocb.c`
//! and `crypto/modes/ocb128.c`: the provider buffers partial blocks of AAD
//! and data, sets the nonce on the first update, and computes or verifies
//! the tag at final.

use subtle::ConstantTimeEq;

use super::aes_block::AesBlock;
use super::aes_block::Block;
use super::aes_block::xor_block;

const MAX_TAG_LEN: usize = 16;

/// `ocb_block_lshift`.
fn block_lshift(input: &[u8], shift: u32) -> Block {
  let mut out = [0u8; 16];
  let mut carry = 0u8;
  for i in (0..16).rev() {
    let carry_next = ((input[i] as u16) >> (8 - shift)) as u8;
    out[i] = ((input[i] as u16) << shift) as u8 | carry;
    carry = carry_next;
  }
  out
}

/// `ocb_double`.
fn double(input: &Block) -> Block {
  let mask = (0u8.wrapping_sub(input[0] >> 7)) & 0x87;
  let mut out = block_lshift(input, 1);
  out[15] ^= mask;
  out
}

#[derive(Default)]
struct Session {
  blocks_hashed: u64,
  blocks_processed: u64,
  offset_aad: Block,
  offset: Block,
  sum: Block,
  checksum: Block,
}

/// `OCB128_CONTEXT`.
struct Ocb128 {
  l_star: Block,
  l_dollar: Block,
  l: Vec<Block>,
  sess: Session,
}

impl Ocb128 {
  /// `CRYPTO_ocb128_init`.
  fn new(block: &AesBlock) -> Self {
    let l_star = block.encrypt(&[0u8; 16]);
    let l_dollar = double(&l_star);
    let l = vec![double(&l_dollar)];
    Self {
      l_star,
      l_dollar,
      l,
      sess: Session::default(),
    }
  }

  /// `ocb_lookup_l`.
  fn lookup_l(&mut self, idx: usize) -> Block {
    while self.l.len() <= idx {
      let next = double(self.l.last().unwrap());
      self.l.push(next);
    }
    self.l[idx]
  }

  /// `CRYPTO_ocb128_setiv`.
  fn set_iv(&mut self, block: &AesBlock, iv: &[u8], taglen: usize) -> bool {
    let len = iv.len();
    if !(1..=15).contains(&len) || !(1..=16).contains(&taglen) {
      return false;
    }
    self.sess = Session::default();
    let mut nonce = [0u8; 16];
    nonce[0] = (((taglen * 8) % 128) << 1) as u8;
    nonce[16 - len..].copy_from_slice(iv);
    nonce[15 - len] |= 1;
    let mut tmp = nonce;
    tmp[15] &= 0xc0;
    let ktop = block.encrypt(&tmp);
    let mut stretch = [0u8; 24];
    stretch[..16].copy_from_slice(&ktop);
    for i in 0..8 {
      stretch[16 + i] = ktop[i] ^ ktop[i + 1];
    }
    let bottom = (nonce[15] & 0x3f) as usize;
    let shift = (bottom % 8) as u32;
    let start = bottom / 8;
    self.sess.offset = block_lshift(&stretch[start..start + 16], shift);
    if shift != 0 {
      let mask = 0xffu8 << (8 - shift);
      self.sess.offset[15] |= (stretch[start + 16] & mask) >> (8 - shift);
    }
    true
  }

  /// `CRYPTO_ocb128_aad`.
  fn aad(&mut self, block: &AesBlock, aad: &[u8]) {
    let num_blocks = (aad.len() / 16) as u64;
    let all_num_blocks = num_blocks + self.sess.blocks_hashed;
    let mut pos = 0;
    for i in (self.sess.blocks_hashed + 1)..=all_num_blocks {
      let l = self.lookup_l(i.trailing_zeros() as usize);
      self.sess.offset_aad = xor_block(&self.sess.offset_aad, &l);
      let mut tmp = [0u8; 16];
      tmp.copy_from_slice(&aad[pos..pos + 16]);
      pos += 16;
      let tmp = block.encrypt(&xor_block(&self.sess.offset_aad, &tmp));
      self.sess.sum = xor_block(&tmp, &self.sess.sum);
    }
    let last_len = aad.len() % 16;
    if last_len > 0 {
      self.sess.offset_aad = xor_block(&self.sess.offset_aad, &self.l_star);
      let mut tmp = [0u8; 16];
      tmp[..last_len].copy_from_slice(&aad[pos..]);
      tmp[last_len] = 0x80;
      let tmp = block.encrypt(&xor_block(&self.sess.offset_aad, &tmp));
      self.sess.sum = xor_block(&tmp, &self.sess.sum);
    }
    self.sess.blocks_hashed = all_num_blocks;
  }

  /// `CRYPTO_ocb128_encrypt` and `CRYPTO_ocb128_decrypt`.
  fn crypt(
    &mut self,
    block: &AesBlock,
    enc: bool,
    input: &[u8],
    out: &mut [u8],
  ) {
    let num_blocks = (input.len() / 16) as u64;
    let all_num_blocks = num_blocks + self.sess.blocks_processed;
    let mut pos = 0;
    for i in (self.sess.blocks_processed + 1)..=all_num_blocks {
      let l = self.lookup_l(i.trailing_zeros() as usize);
      self.sess.offset = xor_block(&self.sess.offset, &l);
      let mut tmp = [0u8; 16];
      tmp.copy_from_slice(&input[pos..pos + 16]);
      if enc {
        self.sess.checksum = xor_block(&tmp, &self.sess.checksum);
      }
      let tmp = xor_block(&self.sess.offset, &tmp);
      let tmp = if enc {
        block.encrypt(&tmp)
      } else {
        block.decrypt(&tmp)
      };
      let tmp = xor_block(&self.sess.offset, &tmp);
      if !enc {
        self.sess.checksum = xor_block(&tmp, &self.sess.checksum);
      }
      out[pos..pos + 16].copy_from_slice(&tmp);
      pos += 16;
    }
    let last_len = input.len() % 16;
    if last_len > 0 {
      self.sess.offset = xor_block(&self.sess.offset, &self.l_star);
      let pad = block.encrypt(&self.sess.offset);
      for i in 0..last_len {
        out[pos + i] = input[pos + i] ^ pad[i];
      }
      let plaintext = if enc { &input[pos..] } else { &out[pos..] };
      let mut tmp = [0u8; 16];
      tmp[..last_len].copy_from_slice(&plaintext[..last_len]);
      tmp[last_len] = 0x80;
      self.sess.checksum = xor_block(&tmp, &self.sess.checksum);
    }
    self.sess.blocks_processed = all_num_blocks;
  }

  /// `ocb_finish`: the full 16-byte tag.
  fn tag(&self, block: &AesBlock) -> Block {
    let tmp = xor_block(&self.sess.checksum, &self.sess.offset);
    let tmp = xor_block(&self.l_dollar, &tmp);
    xor_block(&block.encrypt(&tmp), &self.sess.sum)
  }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IvState {
  Buffered,
  Copied,
  Finished,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum OcbInitError {
  IvLength,
  TagLength,
}

/// `PROV_AES_OCB_CTX` with the key and IV set.
pub(super) struct OcbProvider {
  block: AesBlock,
  enc: bool,
  iv: [u8; 15],
  iv_len: usize,
  taglen: usize,
  tag: [u8; MAX_TAG_LEN],
  iv_state: IvState,
  aad_buf: Block,
  aad_buf_len: usize,
  data_buf: Block,
  data_buf_len: usize,
  ocb: Ocb128,
}

impl OcbProvider {
  /// The Node.js `CipherBase::CommonInit` sequence: set the IV length, set
  /// the tag length, then set the key and IV.
  pub(super) fn new(
    block: AesBlock,
    enc: bool,
    iv: &[u8],
    tag_len: usize,
  ) -> Result<Self, OcbInitError> {
    if !(1..=15).contains(&iv.len()) {
      return Err(OcbInitError::IvLength);
    }
    if tag_len > MAX_TAG_LEN {
      return Err(OcbInitError::TagLength);
    }
    let mut stored_iv = [0u8; 15];
    stored_iv[..iv.len()].copy_from_slice(iv);
    let ocb = Ocb128::new(&block);
    Ok(Self {
      block,
      enc,
      iv: stored_iv,
      iv_len: iv.len(),
      taglen: tag_len,
      tag: [0u8; MAX_TAG_LEN],
      iv_state: IvState::Buffered,
      aad_buf: [0u8; 16],
      aad_buf_len: 0,
      data_buf: [0u8; 16],
      data_buf_len: 0,
      ocb,
    })
  }

  /// `update_iv`.
  fn update_iv(&mut self) -> bool {
    match self.iv_state {
      IvState::Finished => false,
      IvState::Copied => true,
      IvState::Buffered => {
        let iv = self.iv;
        if !self
          .ocb
          .set_iv(&self.block, &iv[..self.iv_len], self.taglen)
        {
          return false;
        }
        self.iv_state = IvState::Copied;
        true
      }
    }
  }

  fn process(&mut self, is_aad: bool, input: &[u8], out: &mut Vec<u8>) {
    if is_aad {
      self.ocb.aad(&self.block, input);
    } else {
      let start = out.len();
      out.resize(start + input.len(), 0);
      self
        .ocb
        .crypt(&self.block, self.enc, input, &mut out[start..]);
    }
  }

  /// `aes_ocb_block_update` and `aes_ocb_block_update_internal`.
  fn block_update(
    &mut self,
    is_aad: bool,
    mut input: &[u8],
  ) -> Option<Vec<u8>> {
    if !self.update_iv() {
      return None;
    }
    let mut out = Vec::new();
    if input.is_empty() {
      return Some(out);
    }
    let (mut buf, mut buf_len) = if is_aad {
      (self.aad_buf, self.aad_buf_len)
    } else {
      (self.data_buf, self.data_buf_len)
    };
    let next_blocks = if buf_len != 0 {
      // ossl_cipher_fillblock
      let take = (16 - buf_len).min(input.len());
      buf[buf_len..buf_len + take].copy_from_slice(&input[..take]);
      buf_len += take;
      input = &input[take..];
      input.len() & !15
    } else {
      input.len() & !15
    };
    if buf_len == 16 {
      self.process(is_aad, &buf, &mut out);
      buf_len = 0;
    }
    if next_blocks > 0 {
      self.process(is_aad, &input[..next_blocks], &mut out);
      input = &input[next_blocks..];
    }
    // ossl_cipher_trailingdata: the buffer is empty here or the input is.
    buf[buf_len..buf_len + input.len()].copy_from_slice(input);
    buf_len += input.len();
    if is_aad {
      self.aad_buf = buf;
      self.aad_buf_len = buf_len;
    } else {
      self.data_buf = buf;
      self.data_buf_len = buf_len;
    }
    Some(out)
  }

  /// `EVP_CipherUpdate(ctx, NULL, &outl, aad, len)`.
  pub(super) fn update_aad(&mut self, aad: &[u8]) -> bool {
    self.block_update(true, aad).is_some()
  }

  /// `EVP_CipherUpdate(ctx, out, &outl, in, len)`.
  pub(super) fn update_data(&mut self, input: &[u8]) -> Option<Vec<u8>> {
    self.block_update(false, input)
  }

  /// `OSSL_CIPHER_PARAM_AEAD_TAG` with data (decryption only).
  pub(super) fn set_tag(&mut self, tag: &[u8]) -> bool {
    if self.enc || tag.len() != self.taglen {
      return false;
    }
    self.tag[..tag.len()].copy_from_slice(tag);
    true
  }

  /// `aes_ocb_block_final`.
  pub(super) fn finalize(&mut self) -> Option<Vec<u8>> {
    if !self.update_iv() {
      return None;
    }
    let mut out = Vec::new();
    if self.data_buf_len > 0 {
      let data = self.data_buf;
      self.process(false, &data[..self.data_buf_len], &mut out);
      self.data_buf_len = 0;
    }
    if self.aad_buf_len > 0 {
      let aad = self.aad_buf;
      self.process(true, &aad[..self.aad_buf_len], &mut out);
      self.aad_buf_len = 0;
    }
    if self.taglen == 0 {
      // CRYPTO_ocb128_tag and CRYPTO_ocb128_finish reject a zero length.
      return None;
    }
    let tag = self.ocb.tag(&self.block);
    if self.enc {
      self.tag[..self.taglen].copy_from_slice(&tag[..self.taglen]);
    } else if !bool::from(tag[..self.taglen].ct_eq(&self.tag[..self.taglen])) {
      return None;
    }
    self.iv_state = IvState::Finished;
    Some(out)
  }

  /// `EVP_CTRL_AEAD_GET_TAG`.
  pub(super) fn get_tag(&self, len: usize) -> Option<Vec<u8>> {
    if !self.enc || len != self.taglen {
      return None;
    }
    Some(self.tag[..len].to_vec())
  }
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

  fn provider(key: &[u8], iv: &[u8], tag_len: usize, enc: bool) -> OcbProvider {
    OcbProvider::new(AesBlock::new(key).unwrap(), enc, iv, tag_len).unwrap()
  }

  fn seal(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    pt: &[u8],
    tag_len: usize,
  ) -> Vec<u8> {
    let mut p = provider(key, iv, tag_len, true);
    assert!(p.update_aad(aad));
    let mut out = p.update_data(pt).unwrap();
    out.extend(p.finalize().unwrap());
    out.extend(p.get_tag(tag_len).unwrap());
    out
  }

  // RFC 7253 appendix A, key 000102...0f.
  #[test]
  fn rfc7253_sample_results() {
    let key = unhex("000102030405060708090a0b0c0d0e0f");
    let cases: &[(&str, &str, &str, &str)] = &[
      (
        "bbaa99887766554433221100",
        "",
        "",
        "785407bfffc8ad9edcc5520ac9111ee6",
      ),
      (
        "bbaa99887766554433221101",
        "0001020304050607",
        "0001020304050607",
        "6820b3657b6f615a5725bda0d3b4eb3a257c9af1f8f03009",
      ),
      (
        "bbaa99887766554433221103",
        "",
        "0001020304050607",
        "45dd69f8f5aae72414054cd1f35d82760b2cd00d2f99bfa9",
      ),
      (
        "bbaa99887766554433221104",
        "000102030405060708090a0b0c0d0e0f",
        "000102030405060708090a0b0c0d0e0f",
        "571d535b60b277188be5147170a9a22c3ad7a4ff3835b8c5701c1ccec8fc3358",
      ),
      (
        "bbaa99887766554433221107",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "1ca2207308c87c010756104d8840ce1952f09673a448a122c92c62241051f57356d7f3c90bb0e07f",
      ),
      (
        "bbaa9988776655443322110d",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
        "d5ca91748410c1751ff8a2f618255b68a0a12e093ff454606e59f9c1d0ddc54b65e8628e568bad7aed07ba06a4a69483a7035490c5769e60",
      ),
    ];
    for (nonce, aad, pt, expected) in cases {
      let out = seal(&key, &unhex(nonce), &unhex(aad), &unhex(pt), 16);
      assert_eq!(hex(&out), *expected, "nonce {nonce}");
    }
  }

  // RFC 7253 appendix A, the 96-bit tag case.
  #[test]
  fn rfc7253_taglen_96() {
    let key = unhex("0f0e0d0c0b0a09080706050403020100");
    let out = seal(
      &key,
      &unhex("bbaa9988776655443322110d"),
      &unhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
      ),
      &unhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
      ),
      12,
    );
    assert_eq!(
      hex(&out),
      "1792a4e31e0755fb03e31b22116e6c2ddf9efd6e33d536f1a0124b0a55bae884ed93481529c76b6ad0c515f4d1cdd4fdac4f02aa"
    );
  }

  // Node.js v20.20.2: aes-128-ocb with no input.
  #[test]
  fn node20_empty() {
    let out = seal(&[1u8; 16], &[0u8; 12], b"", b"", 16);
    assert_eq!(hex(&out), "bb531ab2d6691f115def97826bacbc2e");
  }

  // Node.js v20.20.2: 600 bytes of AAD and data exercise L_i for i > 0.
  #[test]
  fn node20_600_bytes() {
    let out = seal(&[3u8; 32], &[1u8; 12], &[4u8; 600], &[5u8; 600], 16);
    assert_eq!(hex(&out[600..]), "b2c39d5c0448abb3bd8a8e8d5e59adb4");
  }

  // Chunked updates give the same result as one update.
  #[test]
  fn chunked_updates() {
    let key = [2u8; 24];
    let iv = [6u8; 12];
    let aad = b"associated data 21 by";
    let mut pt = vec![1u8; 5];
    pt.extend([2u8; 20]);
    pt.extend([3u8; 40]);
    let whole = seal(&key, &iv, aad, &pt, 16);
    let mut p = provider(&key, &iv, 16, true);
    assert!(p.update_aad(&aad[..7]));
    assert!(p.update_aad(&aad[7..]));
    let mut out = p.update_data(&pt[..5]).unwrap();
    assert!(out.is_empty());
    out.extend(p.update_data(&pt[5..25]).unwrap());
    assert_eq!(out.len(), 16);
    out.extend(p.update_data(&pt[25..]).unwrap());
    out.extend(p.finalize().unwrap());
    out.extend(p.get_tag(16).unwrap());
    assert_eq!(out, whole);

    let mut d = provider(&key, &iv, 16, false);
    assert!(d.update_aad(aad));
    let mut plain = d.update_data(&whole[..pt.len()]).unwrap();
    assert!(d.set_tag(&whole[pt.len()..]));
    plain.extend(d.finalize().unwrap());
    assert_eq!(plain, pt);
  }

  #[test]
  fn decrypt_rejects_wrong_tag() {
    let sealed = seal(&[1u8; 16], &[0u8; 12], b"a", b"message", 8);
    let mut d = provider(&[1u8; 16], &[0u8; 12], 8, false);
    assert!(d.update_aad(b"a"));
    d.update_data(&sealed[..7]).unwrap();
    let mut tag = sealed[7..].to_vec();
    tag[0] ^= 1;
    assert!(d.set_tag(&tag));
    assert_eq!(d.finalize(), None);
  }

  // Node.js v20.20.2: a zero tag length fails at the first update.
  #[test]
  fn zero_tag_length() {
    let mut p = provider(&[1u8; 16], &[0u8; 12], 0, true);
    assert_eq!(p.update_data(b"abc"), None);
    let mut p = provider(&[1u8; 16], &[0u8; 12], 0, true);
    assert!(!p.update_aad(b"x"));
    let mut p = provider(&[1u8; 16], &[0u8; 12], 0, true);
    assert_eq!(p.finalize(), None);
    let mut d = provider(&[1u8; 16], &[0u8; 12], 0, false);
    assert!(d.set_tag(&[]));
  }

  #[test]
  fn finished_state_rejects_updates() {
    let mut p = provider(&[1u8; 16], &[0u8; 12], 16, true);
    assert!(p.finalize().is_some());
    assert!(!p.update_aad(b"x"));
    assert_eq!(p.update_data(b"x"), None);
  }

  #[test]
  fn init_validates_lengths() {
    let block = || AesBlock::new(&[1u8; 16]).unwrap();
    assert!(OcbProvider::new(block(), true, &[], 16).is_err());
    assert!(OcbProvider::new(block(), true, &[0u8; 16], 16).is_err());
    assert!(OcbProvider::new(block(), true, &[0u8; 1], 16).is_ok());
    assert!(OcbProvider::new(block(), true, &[0u8; 15], 16).is_ok());
    assert!(OcbProvider::new(block(), true, &[0u8; 12], 17).is_err());
  }
}
