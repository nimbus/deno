// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

/// <reference path="../../core/internal.d.ts" />

// TODO(petamoriken): enable prefer-primordials for node polyfills
// deno-lint-ignore-file prefer-primordials

(function () {
const { core, primordials } = __bootstrap;
const {
  ArrayPrototypePush,
  ObjectFreeze,
  ObjectPrototypeToString,
  SymbolDispose,
  SymbolSpecies,
} = primordials;
const {
  op_v8_cached_data_version_tag,
  op_v8_get_heap_code_statistics,
  op_v8_get_heap_statistics,
  op_v8_get_wire_format_version,
  op_v8_new_deserializer,
  op_v8_new_serializer,
  op_v8_number_of_heap_spaces,
  op_v8_read_double,
  op_v8_read_header,
  op_v8_read_raw_bytes,
  op_v8_read_uint32,
  op_v8_read_uint64,
  op_v8_read_value,
  op_v8_release_buffer,
  op_v8_set_flags_from_string,
  op_v8_set_treat_array_buffer_views_as_host_objects,
  op_v8_query_objects_count,
  op_v8_take_heap_snapshot,
  op_v8_transfer_array_buffer,
  op_v8_transfer_array_buffer_de,
  op_v8_update_heap_space_statistics,
  op_v8_write_double,
  op_v8_write_header,
  op_v8_write_raw_bytes,
  op_v8_write_uint32,
  op_v8_write_uint64,
  op_v8_write_value,
  op_v8_gc_profiler_new,
  op_v8_gc_profiler_start,
  op_v8_gc_profiler_stop,
} = core.ops;

const { Buffer } = core.loadExtScript("ext:deno_node/internal/buffer.mjs");
const lazyFs = core.createLazyLoader("node:fs");
const lazyStream = core.createLazyLoader("node:stream");

const { notImplemented } = core.loadExtScript("ext:deno_node/_utils.ts");
const { isArrayBufferView, isAsyncFunction, isGeneratorFunction } = core
  .loadExtScript(
    "ext:deno_node/internal/util/types.ts",
  );
const { codes } = core.loadExtScript("ext:deno_node/internal/error_codes.ts");
const lazyFsUtils = core.createLazyLoader(
  "ext:deno_node/internal/fs/utils.mjs",
);
const { validateFunction, validateObject, validateOneOf, validateString } = core
  .loadExtScript(
    "ext:deno_node/internal/validators.mjs",
  );

const shadowV8Flags = new Set<string>();

function shadowV8FlagsHash() {
  let hash = 0;
  for (const flag of Array.from(shadowV8Flags).sort()) {
    for (let i = 0; i < flag.length; i++) {
      hash = ((hash << 5) - hash + flag.charCodeAt(i)) | 0;
    }
  }
  return hash >>> 0;
}

function normalizeShadowV8Flag(flag: string) {
  if (flag.startsWith("--no-")) {
    return { key: `--${flag.slice(5)}`, enabled: false };
  }
  if (flag.startsWith("--no")) {
    return { key: `--${flag.slice(4)}`, enabled: false };
  }
  return { key: flag, enabled: true };
}

function cachedDataVersionTag() {
  return (op_v8_cached_data_version_tag() ^ shadowV8FlagsHash()) >>> 0;
}
const heapCodeStatisticsBuffer = new Float64Array(4);

function getHeapCodeStatistics() {
  op_v8_get_heap_code_statistics(heapCodeStatisticsBuffer);
  return {
    code_and_metadata_size: heapCodeStatisticsBuffer[0],
    bytecode_and_metadata_size: heapCodeStatisticsBuffer[1],
    external_script_source_size: heapCodeStatisticsBuffer[2],
    cpu_profiler_metadata_size: heapCodeStatisticsBuffer[3],
  };
}
function getHeapSnapshot(options?: Record<string, unknown>) {
  if (options !== undefined) {
    validateObject(options, "options");
  }
  const data = op_v8_take_heap_snapshot();
  return lazyStream().Readable.from(Buffer.from(data));
}
const heapSpaceStatisticsBuffer = new Float64Array(4);

function currentNodeMajor() {
  return Number(globalThis.process?.versions?.node?.split(".")?.[0] ?? 0);
}

function shouldExposeHeapSpace(spaceName: string) {
  const nodeMajor = currentNodeMajor();
  if (nodeMajor < 22) {
    return !spaceName.startsWith("trusted_") &&
      !spaceName.startsWith("shared_trusted_");
  }
  if (nodeMajor < 24) {
    return !spaceName.startsWith("shared_trusted_");
  }
  return true;
}

function getHeapSpaceStatistics() {
  const numberOfHeapSpaces = op_v8_number_of_heap_spaces();
  const heapSpaceStatistics = [];
  for (let i = 0; i < numberOfHeapSpaces; i++) {
    const spaceName = op_v8_update_heap_space_statistics(
      heapSpaceStatisticsBuffer,
      i,
    );
    if (!shouldExposeHeapSpace(spaceName)) {
      continue;
    }
    ArrayPrototypePush(heapSpaceStatistics, {
      "space_name": spaceName,
      "space_size": heapSpaceStatisticsBuffer[0],
      "space_used_size": heapSpaceStatisticsBuffer[1],
      "space_available_size": heapSpaceStatisticsBuffer[2],
      "physical_space_size": heapSpaceStatisticsBuffer[3],
    });
  }
  return heapSpaceStatistics;
}

const buffer = new Float64Array(15);

function getHeapStatistics() {
  op_v8_get_heap_statistics(buffer);

  const statistics: Record<string, number> = {
    "total_heap_size": buffer[0],
    "total_heap_size_executable": buffer[1],
    "total_physical_size": buffer[2],
    "total_available_size": buffer[3],
    "used_heap_size": buffer[4],
    "heap_size_limit": buffer[5],
    "malloced_memory": buffer[6],
    "peak_malloced_memory": buffer[7],
    "does_zap_garbage": buffer[8],
    "number_of_native_contexts": buffer[9],
    "number_of_detached_contexts": buffer[10],
    "total_global_handles_size": buffer[11],
    "used_global_handles_size": buffer[12],
    "external_memory": buffer[13],
  };

  if (currentNodeMajor() >= 26) {
    statistics["total_allocated_bytes"] = buffer[14];
  }

  return statistics;
}

function setFlagsFromString(flags: string) {
  validateString(flags, "flags");
  // NOTE(bartlomieju): From Node.js docs:
  // The v8.setFlagsFromString() method can be used to programmatically set V8
  // command-line flags. This method should be used with care. Changing settings
  // after the VM has started may result in unpredictable behavior, including
  // crashes and data loss; or it may simply do nothing.
  //
  // Deno freezes V8 flags before user code runs. Calling the native V8 setter
  // after that point aborts the process, so the runtime keeps the documented
  // no-op behavior while updating the cache tag observable that Node uses to
  // invalidate cached bytecode after flag changes.
  op_v8_set_flags_from_string(flags);
  for (const token of flags.split(/\s+/)) {
    if (token.length === 0) {
      continue;
    }
    const { key, enabled } = normalizeShadowV8Flag(token);
    if (enabled) {
      shadowV8Flags.add(key);
    } else {
      shadowV8Flags.delete(key);
    }
  }
}
function stopCoverage() {
  notImplemented("v8.stopCoverage");
}
function takeCoverage() {
  notImplemented("v8.takeCoverage");
}

let heapSnapshotCounter = 0;

function writeHeapSnapshot(
  filename?: string,
  options?: Record<string, unknown>,
) {
  if (filename !== undefined) {
    filename = lazyFsUtils().getValidatedPath(filename) as string;
  } else {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, "0");
    const day = String(now.getDate()).padStart(2, "0");
    const hours = String(now.getHours()).padStart(2, "0");
    const minutes = String(now.getMinutes()).padStart(2, "0");
    const seconds = String(now.getSeconds()).padStart(2, "0");
    const pid = globalThis.process?.pid ?? 0;
    const thread = 0;
    const seq = ++heapSnapshotCounter;
    filename =
      `Heap.${year}${month}${day}.${hours}${minutes}${seconds}.${pid}.${thread}.${
        String(seq).padStart(3, "0")
      }.heapsnapshot`;
  }
  if (options !== undefined) {
    validateObject(options, "options");
  }
  const data = op_v8_take_heap_snapshot();
  lazyFs().writeFileSync(filename, data);
  return filename;
}

// https://nodejs.org/api/v8.html#v8queryobjectsctor-options
//
// Deno currently only supports `{ format: 'count' }`. Returning live instances
// would require V8's `HeapProfiler::QueryObjects`, which isn't exposed in the
// rusty_v8 bindings; the count form is what Node's leak tests rely on.
function queryObjects(
  ctor: { name?: string; prototype?: unknown },
  options:
    | { format?: "count" | "summary" }
    | undefined = undefined,
) {
  validateFunction(ctor, "constructor");
  if (options !== undefined) {
    validateObject(options, "options");
    if (options.format !== undefined) {
      validateOneOf(options.format, "options.format", ["count", "summary"]);
    }
  }
  const format = options?.format;

  const name = typeof ctor.name === "string" ? ctor.name : "";
  if (name === "") {
    return format === "summary" ? [] : 0;
  }
  const count = op_v8_query_objects_count(name);
  if (format === undefined || format === "count") {
    return count;
  }
  if (format === "summary") {
    if (count === 0) return [];
    return [`${count} instance(s) of ${name}`];
  }
  // Default format returns live object handles, which would require V8's
  // `HeapProfiler::QueryObjects` (not exposed in rusty_v8). Returning an
  // empty array keeps the signature sensible.
  return [];
}

// deno-lint-ignore no-explicit-any
function serialize(value: any) {
  const ser = new DefaultSerializer();
  ser.writeHeader();
  ser.writeValue(value);
  return ser.releaseBuffer();
}
function deserialize(buffer: Buffer | ArrayBufferView | DataView) {
  if (!isArrayBufferView(buffer)) {
    throw new TypeError(
      "buffer must be a TypedArray or a DataView",
    );
  }
  const der = new DefaultDeserializer(buffer);
  der.readHeader();
  return der.readValue();
}

const kHandle = Symbol("kHandle");

class SerializerImpl {
  [kHandle]: object;
  constructor() {
    this[kHandle] = op_v8_new_serializer(this);
  }

  _setTreatArrayBufferViewsAsHostObjects(value: boolean): void {
    op_v8_set_treat_array_buffer_views_as_host_objects(this[kHandle], value);
  }

  releaseBuffer(): Buffer {
    return Buffer.from(op_v8_release_buffer(this[kHandle]));
  }

  transferArrayBuffer(_id: number, _arrayBuffer: ArrayBuffer): void {
    op_v8_transfer_array_buffer(this[kHandle], _id, _arrayBuffer);
  }

  writeDouble(value: number): void {
    op_v8_write_double(this[kHandle], value);
  }

  writeHeader(): void {
    op_v8_write_header(this[kHandle]);
  }

  writeRawBytes(source: ArrayBufferView): void {
    if (!isArrayBufferView(source)) {
      throw new TypeError(
        "source must be a TypedArray or a DataView",
      );
    }
    op_v8_write_raw_bytes(this[kHandle], source);
  }

  writeUint32(value: number): void {
    op_v8_write_uint32(this[kHandle], value);
  }

  writeUint64(hi: number, lo: number): void {
    op_v8_write_uint64(this[kHandle], hi, lo);
  }

  // deno-lint-ignore no-explicit-any
  writeValue(value: any): void {
    op_v8_write_value(this[kHandle], value);
  }

  _getDataCloneError = Error;
}

const Serializer = function Serializer(this: SerializerImpl) {
  if (!new.target) {
    const error = new TypeError(
      "Class constructor Serializer cannot be invoked without 'new'",
    ) as TypeError & { code?: string };
    error.code = "ERR_CONSTRUCT_CALL_REQUIRED";
    throw error;
  }
  return Reflect.construct(SerializerImpl, [], new.target);
} as unknown as typeof SerializerImpl;

Object.setPrototypeOf(Serializer, SerializerImpl);
Serializer.prototype = SerializerImpl.prototype;
Object.defineProperty(Serializer.prototype, "constructor", {
  value: Serializer,
  configurable: true,
  enumerable: false,
  writable: true,
});

class DeserializerImpl {
  buffer: ArrayBufferView;
  [kHandle]: object;
  constructor(buffer: ArrayBufferView) {
    if (!isArrayBufferView(buffer)) {
      throw new TypeError(
        "buffer must be a TypedArray or a DataView",
      );
    }
    this.buffer = buffer;
    this[kHandle] = op_v8_new_deserializer(this, buffer);
  }
  readRawBytes(length: number): Buffer {
    const offset = this._readRawBytes(length);
    return Buffer.from(
      this.buffer.buffer,
      this.buffer.byteOffset + offset,
      length,
    );
  }
  _readRawBytes(length: number): number {
    return op_v8_read_raw_bytes(this[kHandle], length);
  }
  getWireFormatVersion(): number {
    return op_v8_get_wire_format_version(this[kHandle]);
  }
  readDouble(): number {
    return op_v8_read_double(this[kHandle]);
  }
  readHeader(): boolean {
    return op_v8_read_header(this[kHandle]);
  }

  readUint32(): number {
    return op_v8_read_uint32(this[kHandle]);
  }
  readUint64(): [hi: number, lo: number] {
    return op_v8_read_uint64(this[kHandle]);
  }
  readValue(): unknown {
    return op_v8_read_value(this[kHandle]);
  }
  transferArrayBuffer(
    id: number,
    arrayBuffer: ArrayBuffer | SharedArrayBuffer,
  ): void {
    return op_v8_transfer_array_buffer_de(this[kHandle], id, arrayBuffer);
  }
}

const Deserializer = function Deserializer(
  this: DeserializerImpl,
  buffer: ArrayBufferView,
) {
  if (!new.target) {
    const error = new TypeError(
      "Class constructor Deserializer cannot be invoked without 'new'",
    ) as TypeError & { code?: string };
    error.code = "ERR_CONSTRUCT_CALL_REQUIRED";
    throw error;
  }
  return Reflect.construct(DeserializerImpl, [buffer], new.target);
} as unknown as typeof DeserializerImpl;

Object.setPrototypeOf(Deserializer, DeserializerImpl);
Deserializer.prototype = DeserializerImpl.prototype;
Object.defineProperty(Deserializer.prototype, "constructor", {
  value: Deserializer,
  configurable: true,
  enumerable: false,
  writable: true,
});

function arrayBufferViewTypeToIndex(abView: ArrayBufferView) {
  const type = ObjectPrototypeToString(abView);
  if (type === "[object Int8Array]") return 0;
  if (type === "[object Uint8Array]") return 1;
  if (type === "[object Uint8ClampedArray]") return 2;
  if (type === "[object Int16Array]") return 3;
  if (type === "[object Uint16Array]") return 4;
  if (type === "[object Int32Array]") return 5;
  if (type === "[object Uint32Array]") return 6;
  if (type === "[object Float32Array]") return 7;
  if (type === "[object Float64Array]") return 8;
  if (type === "[object DataView]") return 9;
  // Index 10 is FastBuffer.
  if (type === "[object BigInt64Array]") return 11;
  if (type === "[object BigUint64Array]") return 12;
  if (type === "[object Float16Array]") return 13;
  return -1;
}
class DefaultSerializer extends Serializer {
  constructor() {
    super();
    this._setTreatArrayBufferViewsAsHostObjects(true);
  }

  // deno-lint-ignore no-explicit-any
  _writeHostObject(abView: any) {
    // Keep track of how to handle different ArrayBufferViews. The default
    // Serializer for Node does not use the V8 methods for serializing those
    // objects because Node's `Buffer` objects use pooled allocation in many
    // cases, and their underlying `ArrayBuffer`s would show up in the
    // serialization. Because a) those may contain sensitive data and the user
    // may not be aware of that and b) they are often much larger than the
    // `Buffer` itself, custom serialization is applied.
    let i = 10; // FastBuffer
    if (abView.constructor !== Buffer) {
      i = arrayBufferViewTypeToIndex(abView);
      if (i === -1) {
        throw new this._getDataCloneError(
          `Unserializable host object: ${abView}`,
        );
      }
    }
    this.writeUint32(i);
    this.writeUint32(abView.byteLength);
    this.writeRawBytes(
      new Uint8Array(abView.buffer, abView.byteOffset, abView.byteLength),
    );
  }
}

// deno-lint-ignore no-explicit-any
function arrayBufferViewIndexToType(index: number): any {
  if (index === 0) return Int8Array;
  if (index === 1) return Uint8Array;
  if (index === 2) return Uint8ClampedArray;
  if (index === 3) return Int16Array;
  if (index === 4) return Uint16Array;
  if (index === 5) return Int32Array;
  if (index === 6) return Uint32Array;
  if (index === 7) return Float32Array;
  if (index === 8) return Float64Array;
  if (index === 9) return DataView;
  if (index === 10) return Buffer[SymbolSpecies];
  if (index === 11) return BigInt64Array;
  if (index === 12) return BigUint64Array;
  if (index === 13) return Float16Array;
  return undefined;
}

const kGCHandle = Symbol("kGCHandle");
const kGCStartTime = Symbol("kGCStartTime");

class GCProfiler {
  [kGCHandle]: object | null = null;
  [kGCStartTime]: number = 0;

  start() {
    if (this[kGCHandle] !== null) return;
    const handle = op_v8_gc_profiler_new();
    this[kGCStartTime] = Date.now();
    op_v8_gc_profiler_start(handle);
    this[kGCHandle] = handle;
  }

  stop() {
    const handle = this[kGCHandle];
    if (handle === null) return undefined;
    this[kGCHandle] = null;
    const endTime = Date.now();
    const result = op_v8_gc_profiler_stop(handle);
    if (result === null) return undefined;
    return {
      version: 1,
      startTime: this[kGCStartTime],
      endTime,
      statistics: result.statistics,
    };
  }

  [SymbolDispose]() {
    const handle = this[kGCHandle];
    if (handle === null) return undefined;
    this[kGCHandle] = null;
    // Ignore the report; dispose() must return undefined.
    op_v8_gc_profiler_stop(handle);
    return undefined;
  }
}

// https://nodejs.org/api/v8.html#startup-snapshot-api
//
// Deno does not ship `--build-snapshot` / `--snapshot-blob` for users, so this
// is an API-surface polyfill that lets modules calling `v8.startupSnapshot`
// load without errors. `isBuildingSnapshot()` always returns false. The
// serialize/deserialize callbacks are stored but never invoked because there
// is no snapshot lifecycle. `setDeserializeMainFunction` invokes the callback
// synchronously so scripts that register a deserialize main still run their
// entry point in plain Deno runs.
// deno-lint-ignore no-explicit-any
type SnapshotCallback = (data: any) => unknown;
const serializeCallbacks: { fn: SnapshotCallback; data: unknown }[] = [];
const deserializeCallbacks: { fn: SnapshotCallback; data: unknown }[] = [];
let deserializeMainCalled = false;

function startupSnapshotSetDeserializeMainFunction(
  fn: SnapshotCallback,
  data?: unknown,
) {
  validateFunction(fn, "callback");
  if (deserializeMainCalled) {
    throw new Error(
      "v8.startupSnapshot.setDeserializeMainFunction() can only be called once.",
    );
  }
  deserializeMainCalled = true;
  fn(data);
}

function startupSnapshotAddSerializeCallback(
  fn: SnapshotCallback,
  data?: unknown,
) {
  validateFunction(fn, "callback");
  ArrayPrototypePush(serializeCallbacks, { fn, data });
}

function startupSnapshotAddDeserializeCallback(
  fn: SnapshotCallback,
  data?: unknown,
) {
  validateFunction(fn, "callback");
  ArrayPrototypePush(deserializeCallbacks, { fn, data });
}

function startupSnapshotIsBuildingSnapshot() {
  return false;
}

const startupSnapshot = ObjectFreeze({
  setDeserializeMainFunction: startupSnapshotSetDeserializeMainFunction,
  addSerializeCallback: startupSnapshotAddSerializeCallback,
  addDeserializeCallback: startupSnapshotAddDeserializeCallback,
  isBuildingSnapshot: startupSnapshotIsBuildingSnapshot,
});

class DefaultDeserializer extends Deserializer {
  constructor(buffer: ArrayBufferView) {
    super(buffer);
  }

  _readHostObject() {
    const typeIndex = this.readUint32();
    const ctor = arrayBufferViewIndexToType(typeIndex);
    const byteLength = this.readUint32();
    const byteOffset = this._readRawBytes(byteLength);
    const BYTES_PER_ELEMENT = ctor?.BYTES_PER_ELEMENT ?? 1;

    const offset = this.buffer.byteOffset + byteOffset;
    if (offset % BYTES_PER_ELEMENT === 0) {
      return new ctor(
        this.buffer.buffer,
        offset,
        byteLength / BYTES_PER_ELEMENT,
      );
    }
    // Copy to an aligned buffer first.
    const bufferCopy = Buffer.allocUnsafe(byteLength);
    Buffer.from(
      this.buffer.buffer,
      byteOffset,
      byteLength,
    ).copy(bufferCopy);
    return new ctor(
      bufferCopy.buffer,
      bufferCopy.byteOffset,
      byteLength / BYTES_PER_ELEMENT,
    );
  }
}
// node:v8 `promiseHooks`, mirroring upstream lib/internal/promise_hooks.js. The
// engine machinery (core.setPromiseHooks -> op_set_promise_hooks) is append-only
// with no unregister and is also consumed by ext/node async_hooks.ts, so this
// registry installs ONE fixed set of trampolines exactly once (lazily) and keeps
// its own mutable per-type lists. stop() splices the list, and the installed
// trampoline naturally stops calling the removed hook. deno_core's 4th "resolve"
// callback is Node's "settled".
const promiseHookLists = { init: [], before: [], after: [], settled: [] };
let promiseHookTrampolinesInstalled = false;

function reportPromiseHookExceptions(exceptions) {
  // Deferred so a throw in one hook does not stop the others from running,
  // mirroring upstream's triggerUncaughtException(err, false).
  for (let i = 0; i < exceptions.length; i++) {
    core.__reportException(exceptions[i]);
  }
}

function runPromiseInitTrampoline(promise, parent) {
  const snapshot = promiseHookLists.init.slice();
  const exceptions = [];
  for (let i = 0; i < snapshot.length; i++) {
    try {
      snapshot[i](promise, parent);
    } catch (err) {
      exceptions.push(err);
    }
  }
  reportPromiseHookExceptions(exceptions);
}

function makePromiseHookTrampoline(name) {
  return (promise) => {
    const snapshot = promiseHookLists[name].slice();
    const exceptions = [];
    for (let i = 0; i < snapshot.length; i++) {
      try {
        snapshot[i](promise);
      } catch (err) {
        exceptions.push(err);
      }
    }
    reportPromiseHookExceptions(exceptions);
  };
}

const runPromiseBeforeTrampoline = makePromiseHookTrampoline("before");
const runPromiseAfterTrampoline = makePromiseHookTrampoline("after");
const runPromiseSettledTrampoline = makePromiseHookTrampoline("settled");

function ensurePromiseHookTrampolines() {
  if (promiseHookTrampolinesInstalled) return;
  promiseHookTrampolinesInstalled = true;
  core.setPromiseHooks(
    runPromiseInitTrampoline,
    runPromiseBeforeTrampoline,
    runPromiseAfterTrampoline,
    runPromiseSettledTrampoline,
  );
}

function validatePromiseHookFn(fn, name) {
  if (
    typeof fn !== "function" ||
    isAsyncFunction(fn) ||
    isGeneratorFunction(fn)
  ) {
    throw new codes.ERR_INVALID_ARG_TYPE(`${name}Hook`, "Function", fn);
  }
}

function makeUsePromiseHook(name) {
  const list = promiseHookLists[name];
  return (hook) => {
    validatePromiseHookFn(hook, name);
    ensurePromiseHookTrampolines();
    list.push(hook);
    let stopped = false;
    return function stop() {
      if (stopped) {
        return;
      }
      const index = list.indexOf(hook);
      if (index >= 0) {
        list.splice(index, 1);
      }
      stopped = true;
    };
  };
}

const onInit = makeUsePromiseHook("init");
const onBefore = makeUsePromiseHook("before");
const onAfter = makeUsePromiseHook("after");
const onSettled = makeUsePromiseHook("settled");

function createPromiseHook(callbacks) {
  const { init, before, after, settled } = callbacks ?? {};
  const stops = [];
  if (init) {
    stops.push(onInit(init));
  }
  if (before) {
    stops.push(onBefore(before));
  }
  if (after) {
    stops.push(onAfter(after));
  }
  if (settled) {
    stops.push(onSettled(settled));
  }
  return function stop() {
    for (let i = 0; i < stops.length; i++) {
      stops[i]();
    }
  };
}

const promiseHooks = ObjectFreeze({
  createHook: createPromiseHook,
  onInit,
  onBefore,
  onAfter,
  onSettled,
});

return {
  cachedDataVersionTag,
  getHeapCodeStatistics,
  getHeapSnapshot,
  getHeapSpaceStatistics,
  getHeapStatistics,
  promiseHooks,
  queryObjects,
  setFlagsFromString,
  startupSnapshot,
  stopCoverage,
  takeCoverage,
  writeHeapSnapshot,
  serialize,
  deserialize,
  GCProfiler,
  Serializer,
  Deserializer,
  DefaultSerializer,
  DefaultDeserializer,
};
})();
