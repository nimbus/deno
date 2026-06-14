// Copyright 2018-2026 the Deno authors. MIT license.

//! Helpers for the V8 `host_defined_options` PrimitiveArray attached to a
//! script's origin. Index 0 of the array stores a `Uint32` "kind" the
//! runtime can read back from the dynamic-import host callback to decide
//! how to handle `import()` calls originating from the script.

use v8::PinScope;

use crate::JsRuntime;

/// Index of the kind tag inside the host-defined-options PrimitiveArray.
pub const HOST_DEFINED_OPTIONS_KIND_INDEX: usize = 0;
pub const HOST_DEFINED_OPTIONS_KEY_INDEX: usize = 1;
const VM_DYNAMIC_IMPORT_CONTEXT_KIND_SLOT_INDEX: i32 = 5;
const VM_DYNAMIC_IMPORT_CONTEXT_KEY_SLOT_INDEX: i32 = 6;

/// Kind tags written at [`HOST_DEFINED_OPTIONS_KIND_INDEX`].
pub mod host_defined_options_kind {
  /// Script created by `node:vm` (`vm.Script`, `vm.runInThisContext`,
  /// `vm.compileFunction`, `vm.SourceTextModule`) without an
  /// `importModuleDynamically` callback. When the dynamic-import host
  /// callback sees this marker it rejects the import with
  /// `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING`.
  pub const VM_DYNAMIC_IMPORT_MISSING: u32 = 1;
  /// Script created by `node:vm` with a user-provided
  /// `importModuleDynamically` callback. Index 1 stores the per-runtime
  /// callback registry key.
  pub const VM_DYNAMIC_IMPORT_CALLBACK: u32 = 2;
}

pub(crate) struct VmModuleImportMetaInitializer {
  callback: Option<v8::Global<v8::Function>>,
  module_object: Option<v8::Global<v8::Object>>,
}

/// Build a host-defined-options PrimitiveArray with the given kind tag.
pub fn create_host_defined_options_with_kind<'s>(
  scope: &mut PinScope<'s, '_>,
  kind: u32,
) -> v8::Local<'s, v8::Data> {
  let arr = v8::PrimitiveArray::new(scope, 1);
  let value = v8::Integer::new_from_unsigned(scope, kind);
  arr.set(scope, HOST_DEFINED_OPTIONS_KIND_INDEX, value.into());
  arr.into()
}

/// Build a host-defined-options PrimitiveArray with a kind tag and registry key.
pub fn create_host_defined_options_with_kind_and_key<'s>(
  scope: &mut PinScope<'s, '_>,
  kind: u32,
  key: u32,
) -> v8::Local<'s, v8::Data> {
  let arr = v8::PrimitiveArray::new(scope, 2);
  let kind_value = v8::Integer::new_from_unsigned(scope, kind);
  arr.set(scope, HOST_DEFINED_OPTIONS_KIND_INDEX, kind_value.into());
  let key_value = v8::Integer::new_from_unsigned(scope, key);
  arr.set(scope, HOST_DEFINED_OPTIONS_KEY_INDEX, key_value.into());
  arr.into()
}

/// Read the kind tag from a host-defined-options value. Returns `None`
/// when the value isn't a non-empty PrimitiveArray whose first element
/// is a numeric primitive (matching what [`create_host_defined_options_with_kind`]
/// writes).
pub fn read_host_defined_options_kind(
  scope: &mut PinScope<'_, '_>,
  host_defined_options: v8::Local<v8::Data>,
) -> Option<u32> {
  // V8's HostImportModuleDynamicallyCallback contract is that
  // `host_defined_options` is always a `v8::PrimitiveArray` (V8 supplies an
  // empty one when the embedder didn't set any). rusty_v8 lacks a checked
  // `TryFrom<Data> for PrimitiveArray` impl, so we cast unchecked; the
  // resulting `length()` is 0 when V8 supplied the empty fallback, and the
  // `Uint32` check below safely returns `None` for the embedder's other
  // PrimitiveArray shapes (e.g. `[Boolean(true)]`).
  // SAFETY: `Local<PrimitiveArray>` is layout-compatible with `Local<Data>`
  // (see `impl_deref!` / `impl_from!` in the v8 crate), and V8 guarantees
  // the input is a PrimitiveArray.
  let arr: v8::Local<v8::PrimitiveArray> = unsafe {
    std::mem::transmute::<v8::Local<v8::Data>, v8::Local<v8::PrimitiveArray>>(
      host_defined_options,
    )
  };
  if arr.length() == HOST_DEFINED_OPTIONS_KIND_INDEX {
    return None;
  }
  let primitive = arr.get(scope, HOST_DEFINED_OPTIONS_KIND_INDEX);
  let value: v8::Local<v8::Value> = primitive.into();
  let int = v8::Local::<v8::Uint32>::try_from(value).ok()?;
  Some(int.value())
}

/// Read the registry key from a host-defined-options value.
pub fn read_host_defined_options_key(
  scope: &mut PinScope<'_, '_>,
  host_defined_options: v8::Local<v8::Data>,
) -> Option<u32> {
  let arr: v8::Local<v8::PrimitiveArray> = unsafe {
    std::mem::transmute::<v8::Local<v8::Data>, v8::Local<v8::PrimitiveArray>>(
      host_defined_options,
    )
  };
  if arr.length() <= HOST_DEFINED_OPTIONS_KEY_INDEX {
    return None;
  }
  let primitive = arr.get(scope, HOST_DEFINED_OPTIONS_KEY_INDEX);
  let value: v8::Local<v8::Value> = primitive.into();
  let int = v8::Local::<v8::Uint32>::try_from(value).ok()?;
  Some(int.value())
}

/// Store the context-level `node:vm` dynamic-import behavior used when V8
/// reports a dynamic import without script/module host-defined options and
/// without a concrete referrer.
pub fn set_context_vm_dynamic_import_options(
  scope: &mut PinScope<'_, '_>,
  context: v8::Local<v8::Context>,
  kind: u32,
  key: Option<u32>,
) {
  let kind_value = v8::Integer::new_from_unsigned(scope, kind);
  context.set_embedder_data(
    VM_DYNAMIC_IMPORT_CONTEXT_KIND_SLOT_INDEX,
    kind_value.into(),
  );
  let key_value = v8::Integer::new_from_unsigned(scope, key.unwrap_or(0));
  context.set_embedder_data(
    VM_DYNAMIC_IMPORT_CONTEXT_KEY_SLOT_INDEX,
    key_value.into(),
  );
}

/// Read the context-level `node:vm` dynamic-import behavior, if one was stored.
pub fn read_context_vm_dynamic_import_options(
  scope: &mut PinScope<'_, '_>,
  context: v8::Local<v8::Context>,
) -> Option<(u32, Option<u32>)> {
  let kind_value = context
    .get_embedder_data(scope, VM_DYNAMIC_IMPORT_CONTEXT_KIND_SLOT_INDEX)?;
  let kind = v8::Local::<v8::Uint32>::try_from(kind_value).ok()?.value();
  if kind == 0 {
    return None;
  }
  let key = context
    .get_embedder_data(scope, VM_DYNAMIC_IMPORT_CONTEXT_KEY_SLOT_INDEX)
    .and_then(|key_value| v8::Local::<v8::Uint32>::try_from(key_value).ok())
    .map(|key| key.value())
    .filter(|key| *key != 0);
  Some((kind, key))
}

/// Store a `node:vm` dynamic import trampoline in this runtime and return its
/// host-defined-options key.
pub fn register_vm_dynamic_import_callback(
  scope: &mut PinScope<'_, '_>,
  callback: v8::Local<v8::Function>,
) -> u32 {
  let state = JsRuntime::state_from(scope);
  let id = state.next_vm_dynamic_import_callback_id.get();
  state
    .next_vm_dynamic_import_callback_id
    .set(id.checked_add(1).unwrap_or(1));
  state
    .vm_dynamic_import_callbacks
    .borrow_mut()
    .insert(id, v8::Global::new(scope, callback));
  id
}

/// Register a `node:vm` SourceTextModule import.meta initializer.
///
/// VM modules are compiled directly through V8 rather than through
/// deno_core's module map. The normal host import-meta callback therefore
/// cannot look them up by module handle. `ext/node` registers these external
/// modules here while their evaluation is in flight so the core callback can
/// initialize their import.meta objects without treating them as ordinary Deno
/// modules.
pub fn register_vm_module_import_meta_initializer<'s>(
  scope: &mut PinScope<'s, '_>,
  module: v8::Local<'s, v8::Module>,
  callback: Option<v8::Local<'s, v8::Function>>,
  module_object: Option<v8::Local<'s, v8::Object>>,
) {
  let state = JsRuntime::state_from(scope);
  let entry = VmModuleImportMetaInitializer {
    callback: callback.map(|callback| v8::Global::new(scope, callback)),
    module_object: module_object
      .map(|module_object| v8::Global::new(scope, module_object)),
  };
  state
    .vm_module_import_meta_initializers
    .borrow_mut()
    .insert(module.get_identity_hash(), entry);
}

/// Clear a previously registered VM import.meta initializer if V8 did not use
/// it while evaluating the module graph.
pub fn unregister_vm_module_import_meta_initializer<'s>(
  scope: &mut PinScope<'s, '_>,
  module: v8::Local<'s, v8::Module>,
) {
  let state = JsRuntime::state_from(scope);
  state
    .vm_module_import_meta_initializers
    .borrow_mut()
    .remove(&module.get_identity_hash());
}

pub(crate) fn try_initialize_vm_module_import_meta<'s>(
  scope: &mut PinScope<'s, '_>,
  module: v8::Local<'s, v8::Module>,
  meta: v8::Local<'s, v8::Object>,
) -> bool {
  let entry = {
    let state = JsRuntime::state_from(scope);
    state
      .vm_module_import_meta_initializers
      .borrow_mut()
      .remove(&module.get_identity_hash())
  };

  let Some(entry) = entry else {
    return false;
  };

  let null = v8::null(scope);
  meta.set_prototype(scope, null.into());

  let Some(callback) = entry.callback else {
    return true;
  };
  let Some(module_object) = entry.module_object else {
    return true;
  };

  v8::tc_scope!(tc_scope, scope);
  let callback = v8::Local::new(tc_scope, callback);
  let module_object = v8::Local::new(tc_scope, module_object);
  let recv = v8::undefined(tc_scope).into();
  let args = [meta.into(), module_object.into()];
  let _ = callback.call(tc_scope, recv, &args);
  if tc_scope.has_caught() && !tc_scope.has_terminated() {
    tc_scope.rethrow();
  }

  true
}
