// Copyright 2018-2026 the Deno authors. MIT license.

//! Rust-side `constructKey()` analogue.
//!
//! Builds a `CryptoKey` cppgc instance plus the `{ cppgc: CryptoKeyHandle }`
//! handle wrapper object, the algorithm dictionary object, and the frozen
//! `usages` array. It connects the cppgc instance prototype to the public
//! `CryptoKey.prototype` and installs inherited WebIDL and structured-clone
//! hooks without exposing own properties. Used by every `SubtleCrypto`
//! method (import/generate/derive
//! /wrap/unwrap/encapsulate/decapsulate/getPublicKey) now that those bodies
//! live in Rust.

use deno_core::cppgc::make_cppgc_object;
use deno_core::v8;

use crate::crypto_key::CryptoKey;
use crate::crypto_key::CryptoKeyType;
use crate::key_store::CryptoKeyHandle;
use crate::shared::RawKeyData;

/// Per-isolate values needed to connect native `CryptoKey` instances to the
/// JavaScript interface and structured-clone machinery.
pub struct CryptoKeyIsolateState {
  pub crypto_key_internal_prototype: v8::Global<v8::Object>,
}

/// Register the values used by native `CryptoKey` construction. Called once
/// per isolate from JS when the lazy `SubtleCrypto` singleton is initialized.
fn set_isolate_state(
  scope: &mut v8::PinScope<'_, '_>,
  state: CryptoKeyIsolateState,
) {
  scope.set_slot(state);
}

/// Lend the registered isolate values to `f`. Returns `None` if
/// [`set_isolate_state`] has not run for this isolate.
fn with_isolate_state<F, R>(scope: &mut v8::PinScope<'_, '_>, f: F) -> Option<R>
where
  F: FnOnce(&CryptoKeyIsolateState) -> R,
{
  scope.get_slot::<CryptoKeyIsolateState>().map(f)
}

/// Per-algorithm dictionary slots that get baked into the `CryptoKey`'s
/// `algorithm` v8 object. The set of slots is intentionally minimal: the
/// WebCrypto spec mandates that only `name` is universal; the rest
/// (`length`, `hash`, `namedCurve`, `modulusLength`, `publicExponent`) are
/// per-algorithm.
#[derive(Default)]
pub struct AlgorithmDict {
  pub name: String,
  pub length: Option<u32>,
  pub hash_name: Option<String>,
  pub named_curve: Option<String>,
  pub modulus_length: Option<u32>,
  pub public_exponent: Option<Vec<u8>>,
}

impl AlgorithmDict {
  pub fn new(name: impl Into<String>) -> Self {
    AlgorithmDict {
      name: name.into(),
      ..Default::default()
    }
  }

  pub fn with_length(mut self, length: u32) -> Self {
    self.length = Some(length);
    self
  }

  pub fn with_hash(mut self, hash_name: impl Into<String>) -> Self {
    self.hash_name = Some(hash_name.into());
    self
  }

  pub fn with_named_curve(mut self, curve: impl Into<String>) -> Self {
    self.named_curve = Some(curve.into());
    self
  }

  pub fn with_modulus_length(mut self, modulus_length: u32) -> Self {
    self.modulus_length = Some(modulus_length);
    self
  }

  pub fn with_public_exponent(mut self, e: Vec<u8>) -> Self {
    self.public_exponent = Some(e);
    self
  }
}

pub fn build_algorithm_object<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  dict: &AlgorithmDict,
) -> v8::Local<'s, v8::Object> {
  build_algorithm_object_with_integrity(scope, dict, true)
}

fn build_public_algorithm_object<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  dict: &AlgorithmDict,
) -> v8::Local<'s, v8::Object> {
  build_algorithm_object_with_integrity(scope, dict, false)
}

fn build_algorithm_object_with_integrity<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  dict: &AlgorithmDict,
  freeze: bool,
) -> v8::Local<'s, v8::Object> {
  let obj = v8::Object::new(scope);
  set_string(scope, obj, b"name", &dict.name);
  if let Some(length) = dict.length {
    set_u32(scope, obj, b"length", length);
  }
  if let Some(modulus_length) = dict.modulus_length {
    set_u32(scope, obj, b"modulusLength", modulus_length);
  }
  if let Some(ref hash_name) = dict.hash_name {
    let hash_obj = v8::Object::new(scope);
    set_string(scope, hash_obj, b"name", hash_name);
    if freeze {
      hash_obj
        .set_integrity_level(scope, v8::IntegrityLevel::Frozen)
        .unwrap();
    }
    let key = one_byte_internalized(scope, b"hash");
    obj
      .create_data_property(scope, key.into(), hash_obj.into())
      .unwrap();
  }
  if let Some(ref curve) = dict.named_curve {
    set_string(scope, obj, b"namedCurve", curve);
  }
  if let Some(ref pe) = dict.public_exponent {
    let backing = if pe.is_empty() {
      v8::ArrayBuffer::new(scope, 0)
    } else {
      let bs = v8::ArrayBuffer::new_backing_store_from_bytes(
        pe.clone().into_boxed_slice(),
      )
      .make_shared();
      v8::ArrayBuffer::with_backing_store(scope, &bs)
    };
    let u8 = v8::Uint8Array::new(scope, backing, 0, pe.len()).unwrap();
    let key = one_byte_internalized(scope, b"publicExponent");
    obj
      .create_data_property(scope, key.into(), u8.into())
      .unwrap();
  }
  if freeze {
    obj
      .set_integrity_level(scope, v8::IntegrityLevel::Frozen)
      .unwrap();
  }
  obj
}

pub fn build_usages_array<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  usages: &[&str],
) -> v8::Local<'s, v8::Array> {
  build_usages_array_with_integrity(scope, usages, true)
}

fn build_public_usages_array<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  usages: &[&str],
) -> v8::Local<'s, v8::Array> {
  build_usages_array_with_integrity(scope, usages, false)
}

fn build_usages_array_with_integrity<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  usages: &[&str],
  freeze: bool,
) -> v8::Local<'s, v8::Array> {
  let len = usages.len();
  let arr = v8::Array::new(scope, len as i32);
  for (i, u) in usages.iter().enumerate() {
    let s = v8::String::new(scope, u).unwrap();
    arr.set_index(scope, i as u32, s.into());
  }
  if freeze {
    let obj: v8::Local<v8::Object> = arr.into();
    obj
      .set_integrity_level(scope, v8::IntegrityLevel::Frozen)
      .unwrap();
  }
  arr
}

pub fn build_handle_object<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  data: RawKeyData,
) -> v8::Local<'s, v8::Object> {
  let handle = make_cppgc_object(scope, CryptoKeyHandle::from_raw(data));
  let wrapper = v8::Object::new(scope);
  let key = one_byte_internalized(scope, b"cppgc");
  wrapper
    .create_data_property(scope, key.into(), handle.into())
    .unwrap();
  wrapper
}

/// Construct a fully-stamped CryptoKey cppgc instance reachable from JS.
/// Mirrors the legacy JS `constructKey` helper.
#[allow(
  clippy::too_many_arguments,
  reason = "dictionary-style key construction"
)]
pub fn make_crypto_key<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  key_type: CryptoKeyType,
  extractable: bool,
  usages: &[&str],
  alg: AlgorithmDict,
  data: RawKeyData,
) -> v8::Local<'s, v8::Object> {
  let usages = canonicalize_usages(usages);
  let handle = build_handle_object(scope, data);
  let algorithm_obj = build_algorithm_object(scope, &alg);
  let usages_arr = build_usages_array(scope, &usages);
  let public_algorithm_obj = build_public_algorithm_object(scope, &alg);
  let public_usages_arr = build_public_usages_array(scope, &usages);

  let crypto_key = CryptoKey::from_parts(
    scope,
    key_type,
    extractable,
    usages_arr.into(),
    algorithm_obj.into(),
    public_usages_arr.into(),
    public_algorithm_obj.into(),
    handle.into(),
  );
  let obj = make_cppgc_object(scope, crypto_key);
  stamp_prototype(scope, obj);
  obj
}

fn canonicalize_usages<'a>(usages: &[&'a str]) -> Vec<&'a str> {
  const ORDER: &[&str] = &[
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "deriveKey",
    "deriveBits",
    "wrapKey",
    "unwrapKey",
    "encapsulateKey",
    "decapsulateKey",
    "encapsulateBits",
    "decapsulateBits",
  ];
  ORDER
    .iter()
    .filter_map(|candidate| {
      usages.iter().find(|usage| *usage == candidate).copied()
    })
    .collect()
}

fn stamp_prototype<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  key: v8::Local<'s, v8::Object>,
) {
  let Some(internal_prototype_g) = with_isolate_state(scope, |state| {
    state.crypto_key_internal_prototype.clone()
  }) else {
    return;
  };
  let internal_prototype = v8::Local::new(scope, &internal_prototype_g);
  let _ = key.set_prototype(scope, internal_prototype.into());
}

fn host_object_thunk(
  scope: &mut v8::PinScope,
  args: v8::FunctionCallbackArguments,
  mut rv: v8::ReturnValue,
) {
  let Some(key) = deno_core::cppgc::try_unwrap_cppgc_object::<CryptoKey>(
    scope,
    args.this().into(),
  ) else {
    return;
  };
  if let Some(snapshot) = build_host_object_snapshot(scope, &key) {
    rv.set(snapshot);
  }
}

/// Build the structured-clone snapshot from immutable native slots.
fn build_host_object_snapshot<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  key: &CryptoKey,
) -> Option<v8::Local<'s, v8::Value>> {
  let obj = v8::Object::new(scope);
  let type_key = one_byte_internalized(scope, b"type");
  let type_val = v8::String::new(scope, "CryptoKey").unwrap();
  obj
    .create_data_property(scope, type_key.into(), type_val.into())
    .unwrap();

  let key_type_key = one_byte_internalized(scope, b"keyType");
  let key_type_val =
    v8::String::new(scope, key_type_str(key.key_type())).unwrap();
  obj
    .create_data_property(scope, key_type_key.into(), key_type_val.into())
    .unwrap();

  let ext_key = one_byte_internalized(scope, b"extractable");
  let ext_val = v8::Boolean::new(scope, key.extractable_());
  obj
    .create_data_property(scope, ext_key.into(), ext_val.into())
    .unwrap();

  let usages_key = one_byte_internalized(scope, b"usages");
  let usages = key.usages_as_vec(scope)?;
  let usages = usages.iter().map(String::as_str).collect::<Vec<_>>();
  let usages_val = build_usages_array(scope, &usages);
  obj
    .create_data_property(scope, usages_key.into(), usages_val.into())
    .unwrap();

  let alg_key = one_byte_internalized(scope, b"algorithm");
  let alg_val = key.algorithm_local(scope)?;
  obj
    .create_data_property(scope, alg_key.into(), alg_val.into())
    .unwrap();

  let kd_key = one_byte_internalized(scope, b"keyData");
  let handle = key.key_handle(scope)?;
  let kd_val = key_data_to_jsval(scope, handle.data());
  obj
    .create_data_property(scope, kd_key.into(), kd_val)
    .unwrap();

  Some(obj.into())
}

fn key_type_str(t: CryptoKeyType) -> &'static str {
  match t {
    CryptoKeyType::Public => "public",
    CryptoKeyType::Private => "private",
    CryptoKeyType::Secret => "secret",
  }
}

/// Reconstruct the `getKeyData(handle)` JS shape from raw key data.
/// `RawKeyData::Raw` returns a bare `Uint8Array`; `Secret`/`Private`/
/// `Public` return `{ type, data }`; `SeededPrivate` returns
/// `{ seed, privateKey }`.
fn key_data_to_jsval<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  data: &RawKeyData,
) -> v8::Local<'s, v8::Value> {
  fn u8a<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    bytes: &[u8],
  ) -> v8::Local<'s, v8::Uint8Array> {
    let backing = if bytes.is_empty() {
      v8::ArrayBuffer::new(scope, 0)
    } else {
      let bs = v8::ArrayBuffer::new_backing_store_from_bytes(
        bytes.to_vec().into_boxed_slice(),
      )
      .make_shared();
      v8::ArrayBuffer::with_backing_store(scope, &bs)
    };
    v8::Uint8Array::new(scope, backing, 0, bytes.len()).unwrap()
  }
  match data {
    RawKeyData::Raw(b) => u8a(scope, b).into(),
    RawKeyData::Secret(b) => tagged(scope, "secret", b),
    RawKeyData::Private(b) => tagged(scope, "private", b),
    RawKeyData::Public(b) => tagged(scope, "public", b),
    RawKeyData::SeededPrivate { seed, private_key } => {
      let obj = v8::Object::new(scope);
      let pk_key = one_byte_internalized(scope, b"privateKey");
      let pk_arr = u8a(scope, private_key);
      obj
        .create_data_property(scope, pk_key.into(), pk_arr.into())
        .unwrap();
      if let Some(seed) = seed {
        let seed_key = one_byte_internalized(scope, b"seed");
        let seed_arr = u8a(scope, seed);
        obj
          .create_data_property(scope, seed_key.into(), seed_arr.into())
          .unwrap();
      }
      obj.into()
    }
  }
}

fn tagged<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  kind: &str,
  bytes: &[u8],
) -> v8::Local<'s, v8::Value> {
  let obj = v8::Object::new(scope);
  let type_key = one_byte_internalized(scope, b"type");
  let type_val = v8::String::new(scope, kind).unwrap();
  obj
    .create_data_property(scope, type_key.into(), type_val.into())
    .unwrap();
  let data_key = one_byte_internalized(scope, b"data");
  let backing = if bytes.is_empty() {
    v8::ArrayBuffer::new(scope, 0)
  } else {
    let bs = v8::ArrayBuffer::new_backing_store_from_bytes(
      bytes.to_vec().into_boxed_slice(),
    )
    .make_shared();
    v8::ArrayBuffer::with_backing_store(scope, &bs)
  };
  let data_arr = v8::Uint8Array::new(scope, backing, 0, bytes.len()).unwrap();
  obj
    .create_data_property(scope, data_key.into(), data_arr.into())
    .unwrap();
  obj.into()
}

fn set_string<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  obj: v8::Local<'s, v8::Object>,
  field: &[u8],
  value: &str,
) {
  let k = one_byte_internalized(scope, field);
  let v = v8::String::new(scope, value).unwrap();
  obj.create_data_property(scope, k.into(), v.into()).unwrap();
}

fn set_u32<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  obj: v8::Local<'s, v8::Object>,
  field: &[u8],
  value: u32,
) {
  let k = one_byte_internalized(scope, field);
  let n = v8::Number::new(scope, value as f64);
  obj.create_data_property(scope, k.into(), n.into()).unwrap();
}

fn one_byte_internalized<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  bytes: &[u8],
) -> v8::Local<'s, v8::String> {
  v8::String::new_from_one_byte(scope, bytes, v8::NewStringType::Internalized)
    .unwrap()
}

/// Register per-isolate values needed by native `CryptoKey` construction.
pub fn register_symbols<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  webidl_brand: v8::Local<'s, v8::Value>,
  crypto_key_prototype: v8::Local<'s, v8::Value>,
) -> bool {
  let Ok(webidl_brand) = v8::Local::<v8::Symbol>::try_from(webidl_brand) else {
    return false;
  };
  let Ok(crypto_key_prototype) =
    v8::Local::<v8::Object>::try_from(crypto_key_prototype)
  else {
    return false;
  };
  let host_obj = {
    let name = v8::String::new(scope, "Deno.core.hostObject").unwrap();
    v8::Symbol::for_key(scope, name)
  };
  let internal_prototype = v8::Object::new(scope);
  let _ = internal_prototype.set_prototype(scope, crypto_key_prototype.into());
  let _ = internal_prototype.define_own_property(
    scope,
    webidl_brand.into(),
    webidl_brand.into(),
    v8::PropertyAttribute::READ_ONLY
      | v8::PropertyAttribute::DONT_ENUM
      | v8::PropertyAttribute::DONT_DELETE,
  );
  // The serializer calls inherited host-object functions with the instance
  // as `this`, so one native function can serve every key without placing a
  // symbol on the instance.
  let ft = v8::FunctionTemplate::new(scope, host_object_thunk);
  let host_fn = ft.get_function(scope).unwrap();
  let _ = internal_prototype.define_own_property(
    scope,
    host_obj.into(),
    host_fn.into(),
    v8::PropertyAttribute::READ_ONLY
      | v8::PropertyAttribute::DONT_ENUM
      | v8::PropertyAttribute::DONT_DELETE,
  );
  set_isolate_state(
    scope,
    CryptoKeyIsolateState {
      crypto_key_internal_prototype: v8::Global::new(scope, internal_prototype),
    },
  );
  true
}
