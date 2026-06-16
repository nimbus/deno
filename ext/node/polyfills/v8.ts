// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

/// <reference path="../../core/internal.d.ts" />

(function () {
const { core, primordials } = __bootstrap;
const {
  Array,
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypeSlice,
  ArrayPrototypeSplice,
  BigInt64Array,
  BigUint64Array,
  DataView,
  DataViewPrototypeGetBuffer,
  DataViewPrototypeGetByteLength,
  DataViewPrototypeGetByteOffset,
  Date,
  DateNow,
  DatePrototypeGetDate,
  DatePrototypeGetFullYear,
  DatePrototypeGetHours,
  DatePrototypeGetMinutes,
  DatePrototypeGetMonth,
  DatePrototypeGetSeconds,
  Error,
  Float32Array,
  Float64Array,
  Int16Array,
  Int32Array,
  Int8Array,
  ObjectFreeze,
  ObjectPrototypeToString,
  SafeWeakSet,
  Promise,
  PromisePrototypeThen,
  ReflectApply,
  String,
  StringPrototypeCharCodeAt,
  StringPrototypePadStart,
  Symbol,
  SymbolDispose,
  SymbolSpecies,
  TypeError,
  TypedArrayPrototypeGetBuffer,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeGetByteOffset,
  Uint16Array,
  Uint32Array,
  Uint8Array,
  Uint8ClampedArray,
  WeakSetPrototypeAdd,
  WeakSetPrototypeHas,
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
const { isArrayBufferView, isDataView } = core.loadExtScript(
  "ext:deno_node/internal/util/types.ts",
);
const { ERR_INVALID_ARG_TYPE } = core.loadExtScript(
  "ext:deno_node/internal/errors.ts",
);

function getViewBuffer(view: ArrayBufferView): ArrayBufferLike {
  return isDataView(view)
    ? DataViewPrototypeGetBuffer(view as DataView)
    : TypedArrayPrototypeGetBuffer(view as Uint8Array);
}
function getViewByteOffset(view: ArrayBufferView): number {
  return isDataView(view)
    ? DataViewPrototypeGetByteOffset(view as DataView)
    : TypedArrayPrototypeGetByteOffset(view as Uint8Array);
}
function getViewByteLength(view: ArrayBufferView): number {
  return isDataView(view)
    ? DataViewPrototypeGetByteLength(view as DataView)
    : TypedArrayPrototypeGetByteLength(view as Uint8Array);
}
const lazyFsUtils = core.createLazyLoader(
  "ext:deno_node/internal/fs/utils.mjs",
);
const {
  validateBoolean,
  validateFunction,
  validateInt32,
  validateInteger,
  validateObject,
  validateOneOf,
  validateString,
} = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);

function cachedDataVersionTag() {
  return op_v8_cached_data_version_tag();
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

function getHeapSpaceStatistics() {
  const numberOfHeapSpaces = op_v8_number_of_heap_spaces();
  const heapSpaceStatistics = new Array(numberOfHeapSpaces);
  for (let i = 0; i < numberOfHeapSpaces; i++) {
    const spaceName = op_v8_update_heap_space_statistics(
      heapSpaceStatisticsBuffer,
      i,
    );
    heapSpaceStatistics[i] = {
      space_name: spaceName,
      space_size: heapSpaceStatisticsBuffer[0],
      space_used_size: heapSpaceStatisticsBuffer[1],
      space_available_size: heapSpaceStatisticsBuffer[2],
      physical_space_size: heapSpaceStatisticsBuffer[3],
    };
  }
  return heapSpaceStatistics;
}

const buffer = new Float64Array(15);

function getHeapStatistics() {
  op_v8_get_heap_statistics(buffer);

  return {
    total_heap_size: buffer[0],
    total_heap_size_executable: buffer[1],
    total_physical_size: buffer[2],
    total_available_size: buffer[3],
    used_heap_size: buffer[4],
    heap_size_limit: buffer[5],
    malloced_memory: buffer[6],
    peak_malloced_memory: buffer[7],
    does_zap_garbage: buffer[8],
    number_of_native_contexts: buffer[9],
    number_of_detached_contexts: buffer[10],
    total_global_handles_size: buffer[11],
    used_global_handles_size: buffer[12],
    external_memory: buffer[13],
    total_allocated_bytes: buffer[14],
  };
}

function setFlagsFromString(flags: string) {
  // NOTE(bartlomieju): From Node.js docs:
  // The v8.setFlagsFromString() method can be used to programmatically set V8
  // command-line flags. This method should be used with care. Changing settings
  // after the VM has started may result in unpredictable behavior, including
  // crashes and data loss; or it may simply do nothing.
  validateString(flags, "flags");
  op_v8_set_flags_from_string(flags);
}

const EMPTY_SAMPLING_HEAP_PROFILE =
  '{"head":{"callFrame":{"functionName":"(root)","scriptId":"0","url":"","lineNumber":-1,"columnNumber":-1},"selfSize":0,"id":1,"children":[]},"samples":[]}';

let heapProfileStarted = false;

// Deno does not expose V8's sampling heap profiler through rusty_v8 today, so
// this wrapper preserves Node's public validation and handle lifecycle while
// returning a minimal valid sampling-profile document from stop().
function normalizeHeapProfileOptions(options: Record<string, unknown> = {}) {
  validateObject(options, "options");
  const {
    sampleInterval = 512 * 1024,
    stackDepth = 16,
    forceGC = false,
    includeObjectsCollectedByMajorGC = false,
    includeObjectsCollectedByMinorGC = false,
  } = options;

  validateInteger(sampleInterval, "options.sampleInterval", 1);
  validateInt32(stackDepth, "options.stackDepth", 0);
  validateBoolean(forceGC, "options.forceGC");
  validateBoolean(
    includeObjectsCollectedByMajorGC,
    "options.includeObjectsCollectedByMajorGC",
  );
  validateBoolean(
    includeObjectsCollectedByMinorGC,
    "options.includeObjectsCollectedByMinorGC",
  );
}

function throwHeapProfileStarted() {
  const error = new Error("Heap profile has already been started");
  (error as Error & { code?: string }).code =
    "ERR_HEAP_PROFILE_HAVE_BEEN_STARTED";
  throw error;
}

class SyncHeapProfileHandle {
  #stopped = false;

  stop() {
    if (this.#stopped) return undefined;
    this.#stopped = true;
    heapProfileStarted = false;
    return EMPTY_SAMPLING_HEAP_PROFILE;
  }

  [SymbolDispose]() {
    this.stop();
  }
}

function startHeapProfile(options?: Record<string, unknown>) {
  normalizeHeapProfileOptions(options);
  if (heapProfileStarted) {
    throwHeapProfileStarted();
  }
  heapProfileStarted = true;
  return new SyncHeapProfileHandle();
}

function isStringOneByteRepresentation(content: string) {
  validateString(content, "content");
  for (let i = 0; i < content.length; i++) {
    if (StringPrototypeCharCodeAt(content, i) > 0xff) {
      return false;
    }
  }
  return true;
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
    const year = DatePrototypeGetFullYear(now);
    const month = StringPrototypePadStart(
      String(DatePrototypeGetMonth(now) + 1),
      2,
      "0",
    );
    const day = StringPrototypePadStart(
      String(DatePrototypeGetDate(now)),
      2,
      "0",
    );
    const hours = StringPrototypePadStart(
      String(DatePrototypeGetHours(now)),
      2,
      "0",
    );
    const minutes = StringPrototypePadStart(
      String(DatePrototypeGetMinutes(now)),
      2,
      "0",
    );
    const seconds = StringPrototypePadStart(
      String(DatePrototypeGetSeconds(now)),
      2,
      "0",
    );
    const pid = globalThis.process?.pid ?? 0;
    const thread = 0;
    const seq = ++heapSnapshotCounter;
    filename =
      `Heap.${year}${month}${day}.${hours}${minutes}${seconds}.${pid}.${thread}.${
        StringPrototypePadStart(String(seq), 3, "0")
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
// Deno currently only supports Node's default count form and `{ format:
// 'summary' }`. Returning live instances would require V8's
// `HeapProfiler::QueryObjects`, which isn't exposed in the rusty_v8 bindings.
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
  const format = options?.format ?? "count";

  const name = typeof ctor.name === "string" ? ctor.name : "";
  if (name === "") {
    return format === "count" ? 0 : [];
  }
  const count = op_v8_query_objects_count(name);
  if (format === "count") {
    return count;
  }
  if (format === "summary") {
    if (count === 0) return [];
    return [`${count} instance(s) of ${name}`];
  }
  return count;
}

const promiseHookLists = {
  init: [] as ((promise: Promise<unknown>, parent: Promise<unknown>) => void)[],
  before: [] as ((promise: Promise<unknown>) => void)[],
  after: [] as ((promise: Promise<unknown>) => void)[],
  settled: [] as ((promise: Promise<unknown>) => void)[],
};
const settledPublicPromiseHookPromises = new SafeWeakSet<Promise<unknown>>();
let promiseHooksInstalled = false;

function validatePlainPromiseHook(
  hook: unknown,
  name: string,
): asserts hook is (...args: unknown[]) => void {
  const tag = ObjectPrototypeToString(hook);
  if (
    typeof hook !== "function" ||
    tag === "[object AsyncFunction]" ||
    tag === "[object AsyncGeneratorFunction]"
  ) {
    throw new ERR_INVALID_ARG_TYPE(name, "Function", hook);
  }
}

function triggerUncaughtPromiseHookException(error: unknown): void {
  if (
    globalThis.process !== undefined &&
    typeof globalThis.process._fatalException === "function" &&
    globalThis.process._fatalException(error, false)
  ) {
    return;
  }
  throw error;
}

function runPromiseInitHooks(
  promise: Promise<unknown>,
  parent: Promise<unknown>,
): void {
  if (core.isPromiseHooksSuppressed()) return;
  const hookSet = ArrayPrototypeSlice(promiseHookLists.init);
  const exceptions = [];
  for (let i = 0; i < hookSet.length; i++) {
    try {
      hookSet[i](promise, parent);
    } catch (error) {
      ArrayPrototypePush(exceptions, error);
    }
  }
  for (let i = 0; i < exceptions.length; i++) {
    triggerUncaughtPromiseHookException(exceptions[i]);
  }
}

function makePromiseHookRunner(
  list: ((promise: Promise<unknown>) => void)[],
) {
  return (promise: Promise<unknown>) => {
    const hookSet = ArrayPrototypeSlice(list);
    const exceptions = [];
    for (let i = 0; i < hookSet.length; i++) {
      try {
        hookSet[i](promise);
      } catch (error) {
        ArrayPrototypePush(exceptions, error);
      }
    }
    for (let i = 0; i < exceptions.length; i++) {
      triggerUncaughtPromiseHookException(exceptions[i]);
    }
  };
}

const runPromiseBeforeHooks = makePromiseHookRunner(promiseHookLists.before);
const runPromiseAfterHooks = makePromiseHookRunner(promiseHookLists.after);
const runPromiseSettledHooks = makePromiseHookRunner(promiseHookLists.settled);

function runPromiseSettledOnce(promise: Promise<unknown>): void {
  if (WeakSetPrototypeHas(settledPublicPromiseHookPromises, promise)) return;
  WeakSetPrototypeAdd(settledPublicPromiseHookPromises, promise);
  runPromiseSettledHooks(promise);
}

function ensurePublicPromiseHooksInstalled(): void {
  if (promiseHooksInstalled) return;
  promiseHooksInstalled = true;

  const OriginalPromise = Promise;
  const originalCatch = OriginalPromise.prototype.catch;
  const originalFinally = OriginalPromise.prototype.finally;

  function InstrumentedPromise(
    this: unknown,
    executor: (
      resolve: (value?: unknown) => void,
      reject: (reason?: unknown) => void,
    ) => void,
  ) {
    let created = false;
    let settledBeforeCreate = false;
    let promise: Promise<unknown>;
    promise = new OriginalPromise((resolve, reject) => {
      const settle = (fn: (value?: unknown) => void, value?: unknown) => {
        fn(value);
        if (created) {
          runPromiseSettledOnce(promise);
        } else {
          settledBeforeCreate = true;
        }
      };
      try {
        executor(
          (value?: unknown) => settle(resolve, value),
          (reason?: unknown) => settle(reject, reason),
        );
      } catch (error) {
        settle(reject, error);
      }
    });
    created = true;
    runPromiseInitHooks(promise, undefined as unknown as Promise<unknown>);
    if (settledBeforeCreate) runPromiseSettledOnce(promise);
    return promise;
  }

  InstrumentedPromise.prototype = OriginalPromise.prototype;
  Object.setPrototypeOf(InstrumentedPromise, OriginalPromise);

  InstrumentedPromise.resolve = (value?: unknown) => {
    const promise = OriginalPromise.resolve(value);
    runPromiseInitHooks(promise, undefined as unknown as Promise<unknown>);
    runPromiseSettledOnce(promise);
    return promise;
  };
  InstrumentedPromise.reject = (reason?: unknown) => {
    const promise = OriginalPromise.reject(reason);
    runPromiseInitHooks(promise, undefined as unknown as Promise<unknown>);
    runPromiseSettledOnce(promise);
    return promise;
  };

  OriginalPromise.prototype.then = function (
    onFulfilled?: ((value: unknown) => unknown) | null,
    onRejected?: ((reason: unknown) => unknown) | null,
  ) {
    let child: Promise<unknown>;
    const wrap = (handler: unknown) => {
      if (typeof handler !== "function") return handler;
      return function (this: unknown, value: unknown) {
        runPromiseBeforeHooks(child);
        try {
          return ReflectApply(handler, this, [value]);
        } finally {
          runPromiseAfterHooks(child);
          runPromiseSettledOnce(child);
        }
      };
    };
    child = PromisePrototypeThen(
      this,
      wrap(onFulfilled),
      wrap(onRejected),
    );
    runPromiseInitHooks(child, this as Promise<unknown>);
    PromisePrototypeThen(
      child,
      () => runPromiseSettledOnce(child),
      () => runPromiseSettledOnce(child),
    );
    return child;
  };
  OriginalPromise.prototype.catch = function (
    onRejected?: ((reason: unknown) => unknown) | null,
  ) {
    return ReflectApply(originalCatch, this, [onRejected]);
  };
  OriginalPromise.prototype.finally = function (
    onFinally?: (() => unknown) | null,
  ) {
    return ReflectApply(originalFinally, this, [onFinally]);
  };
  (globalThis as { Promise: PromiseConstructor }).Promise =
    InstrumentedPromise as unknown as PromiseConstructor;
}

function stopPromiseHook(list: unknown[], hook: unknown): void {
  const index = ArrayPrototypeIndexOf(list, hook);
  if (index >= 0) {
    ArrayPrototypeSplice(list, index, 1);
  }
}

function makeUsePromiseHook(
  name: "init" | "before" | "after" | "settled",
  argumentName: string,
) {
  const list = promiseHookLists[name];
  return (hook: unknown) => {
    validatePlainPromiseHook(hook, argumentName);
    ensurePublicPromiseHooksInstalled();
    ArrayPrototypePush(list, hook);
    return () => stopPromiseHook(list, hook);
  };
}

const onPromiseInit = makeUsePromiseHook("init", "initHook");
const onPromiseBefore = makeUsePromiseHook("before", "beforeHook");
const onPromiseAfter = makeUsePromiseHook("after", "afterHook");
const onPromiseSettled = makeUsePromiseHook("settled", "settledHook");

function createPromiseHook(
  hooks:
    | {
      init?: (...args: unknown[]) => void;
      before?: (...args: unknown[]) => void;
      after?: (...args: unknown[]) => void;
      settled?: (...args: unknown[]) => void;
    }
    | undefined = undefined,
) {
  if (hooks === undefined) {
    hooks = {};
  } else {
    validateObject(hooks, "hooks");
  }

  const stops = [];
  if (hooks.init) ArrayPrototypePush(stops, onPromiseInit(hooks.init));
  if (hooks.before) ArrayPrototypePush(stops, onPromiseBefore(hooks.before));
  if (hooks.after) ArrayPrototypePush(stops, onPromiseAfter(hooks.after));
  if (hooks.settled) {
    ArrayPrototypePush(stops, onPromiseSettled(hooks.settled));
  }

  return () => {
    for (let i = 0; i < stops.length; i++) {
      stops[i]();
    }
  };
}

const promiseHooks = ObjectFreeze({
  createHook: createPromiseHook,
  onInit: onPromiseInit,
  onBefore: onPromiseBefore,
  onAfter: onPromiseAfter,
  onSettled: onPromiseSettled,
});

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
const kHeaderWritten = Symbol("kHeaderWritten");

class Serializer {
  [kHandle]: object;
  [kHeaderWritten] = false;
  constructor() {
    this[kHandle] = op_v8_new_serializer(this);
  }

  _setTreatArrayBufferViewsAsHostObjects(value: boolean): void {
    op_v8_set_treat_array_buffer_views_as_host_objects(this[kHandle], value);
  }

  releaseBuffer(): Buffer {
    const buf = Buffer.from(op_v8_release_buffer(this[kHandle]));
    // V8 14.9 bumped the ValueSerializer wire format version from 15 to
    // 16 to support ArrayBuffers larger than 4GB. Node.js cannot
    // deserialize format 16, which breaks consumers that feed
    // `v8.serialize` output to a Node.js process. For payloads smaller
    // than 4GB both formats encode identical bytes after the two-byte
    // header, so relabel the header as version 15 to keep the output
    // readable by Node.js. See
    // https://github.com/denoland/deno/issues/35113.
    if (
      this[kHeaderWritten] && getViewByteLength(buf) < 0x100000000 &&
      buf[0] === 0xFF && buf[1] === 0x10
    ) {
      buf[1] = 0x0F;
    }
    return buf;
  }

  transferArrayBuffer(_id: number, _arrayBuffer: ArrayBuffer): void {
    op_v8_transfer_array_buffer(this[kHandle], _id, _arrayBuffer);
  }

  writeDouble(value: number): void {
    op_v8_write_double(this[kHandle], value);
  }

  writeHeader(): void {
    op_v8_write_header(this[kHandle]);
    this[kHeaderWritten] = true;
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

class Deserializer {
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
    // `this.buffer` is the Deserializer's own field, not a TypedArray getter.
    // deno-lint-ignore prefer-primordials
    const view = this.buffer;
    return Buffer.from(
      getViewBuffer(view),
      getViewByteOffset(view) + offset,
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
    this.writeUint32(getViewByteLength(abView));
    this.writeRawBytes(
      new Uint8Array(
        getViewBuffer(abView),
        getViewByteOffset(abView),
        getViewByteLength(abView),
      ),
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
    this[kGCStartTime] = DateNow();
    op_v8_gc_profiler_start(handle);
    this[kGCHandle] = handle;
  }

  stop() {
    const handle = this[kGCHandle];
    if (handle === null) return undefined;
    this[kGCHandle] = null;
    const endTime = DateNow();
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

    // `this.buffer` is the Deserializer's own field, not a TypedArray getter.
    // deno-lint-ignore prefer-primordials
    const view = this.buffer;
    const offset = getViewByteOffset(view) + byteOffset;
    if (offset % BYTES_PER_ELEMENT === 0) {
      return new ctor(
        getViewBuffer(view),
        offset,
        byteLength / BYTES_PER_ELEMENT,
      );
    }
    // Copy to an aligned buffer first.
    const bufferCopy = Buffer.allocUnsafe(byteLength);
    Buffer.from(
      getViewBuffer(view),
      byteOffset,
      byteLength,
    ).copy(bufferCopy);
    return new ctor(
      TypedArrayPrototypeGetBuffer(bufferCopy),
      TypedArrayPrototypeGetByteOffset(bufferCopy),
      byteLength / BYTES_PER_ELEMENT,
    );
  }
}
return {
  cachedDataVersionTag,
  getHeapCodeStatistics,
  getHeapSnapshot,
  getHeapSpaceStatistics,
  getHeapStatistics,
  promiseHooks,
  queryObjects,
  setFlagsFromString,
  startHeapProfile,
  isStringOneByteRepresentation,
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
