// Copyright 2018-2026 the Deno authors. MIT license.

// deno-lint-ignore-file no-explicit-any no-node-globals

import { core, primordials } from "ext:core/mod.js";
const { EventEmitter } = core.loadExtScript("ext:deno_node/_events.mjs");
const lazyFs = core.createLazyLoader("node:fs");
const lazyReadline = core.createLazyLoader("node:readline");
const lazyBuffer = core.createLazyLoader("node:buffer");
import { op_node_fs_close } from "ext:core/ops";
import type {
  BinaryOptionsArgument,
  FileOptionsArgument,
  TextOptionsArgument,
} from "ext:deno_node/_fs/_fs_common.ts";
// writev loaded lazily from node:fs via lazyFs

export interface WriteVResult {
  bytesWritten: number;
  buffers: ReadonlyArray<ArrayBufferView>;
}

function writevPromise(
  fd: number,
  buffers: ArrayBufferView[],
  position?: number,
): Promise<WriteVResult> {
  return new Promise((resolve, reject) => {
    lazyFs().writev(fd, buffers, position, (err, bytesWritten, buffers) => {
      if (err) reject(err);
      else resolve({ bytesWritten, buffers });
    });
  });
}
// readvPromise loaded lazily from node:fs via lazyFs
const { fstatPromise } = core.loadExtScript("ext:deno_node/_fs/_fs_fstat.ts");
// fchown, ftruncate, futimes loaded lazily from node:fs via lazyFs
const { kEmptyObject, promisify } = core.loadExtScript(
  "ext:deno_node/internal/util.mjs",
);

// CreateReadStreamOptions, CreateWriteStreamOptions types from node:fs/promises
const assert = core.loadExtScript(
  "ext:deno_node/internal/assert.mjs",
);
const {
  denoErrorToNodeError,
  ERR_INVALID_STATE,
  ERR_OUT_OF_RANGE,
} = core.loadExtScript("ext:deno_node/internal/errors.ts");
const { readableStreamCancel } = core.loadExtScript(
  "ext:deno_web/06_streams.js",
);
const {
  validateAbortSignal,
  validateBuffer,
  validateBoolean,
  validateInteger,
  validateObject,
} = core.loadExtScript("ext:deno_node/internal/validators.mjs");
const { isDataView } = core.loadExtScript(
  "ext:deno_node/internal/util/types.ts",
);
const lazyProcess = core.createLazyLoader("node:process");

// Promisified wrappers must NOT be built at module body: handle.ts is loaded
// during `fs.promises` evaluation, and calling `lazyFs()` here re-enters
// `node:fs`'s still-evaluating module body. Its `export const promises =
// mod.promises` then re-triggers `get promises` -> `lazyInternalPromises()
// .default` which is in TDZ. Build the wrappers on first call instead.
let _fchmodPromise: any;
const fchmodPromise = (
  fd: number,
  mode: string | number,
): Promise<void> => {
  _fchmodPromise ??= promisify(lazyFs().fchmod);
  return _fchmodPromise(fd, mode);
};
let _fdatasyncPromise: any;
const fdatasyncPromise = (fd: number): Promise<void> => {
  _fdatasyncPromise ??= promisify(lazyFs().fdatasync);
  return _fdatasyncPromise(fd);
};
let _fsyncPromise: any;
const fsyncPromise = (fd: number): Promise<void> => {
  _fsyncPromise ??= promisify(lazyFs().fsync);
  return _fsyncPromise(fd);
};

const {
  ArrayPrototypePush,
  DataViewPrototypeGetByteLength,
  Error,
  MathMin,
  ObjectAssign,
  ObjectPrototypeIsPrototypeOf,
  Promise,
  PromiseReject,
  PromisePrototypeCatch,
  PromisePrototypeThen,
  SafePromisePrototypeFinally,
  PromiseResolve,
  SafeArrayIterator,
  Symbol,
  SymbolAsyncDispose,
  SymbolDispose,
  SymbolIterator,
  SymbolAsyncIterator,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeGetByteOffset,
  TypedArrayPrototypeSubarray,
  Uint8ArrayPrototype,
} = primordials;

function getByteLength(buffer: ArrayBufferView): number {
  return isDataView(buffer)
    ? DataViewPrototypeGetByteLength(buffer)
    : TypedArrayPrototypeGetByteLength(buffer);
}

const kRefs = Symbol("kRefs");
const kClosePromise = Symbol("kClosePromise");
const kCloseResolve = Symbol("kCloseResolve");
const kCloseReject = Symbol("kCloseReject");
export const kRef = Symbol("kRef");
export const kUnref = Symbol("kUnref");
const kLocked = Symbol("kLocked");
const kCloseSync = Symbol("kCloseSync");
const kDefaultStreamIterChunkSize = 131072;
const kNoPosition = -1;
const kNullProto = { __proto__: null };

let _streamIterPull: any;
let _streamIterPullSync: any;
let _streamIterParsePullArgs: any;
let _streamIterToUint8Array: any;
let _streamIterConvertChunks: any;
function lazyStreamIter() {
  if (_streamIterPull === undefined) {
    const pullModule = core.loadExtScript(
      "ext:deno_node/internal/streams/iter/pull.js",
    );
    const utils = core.loadExtScript(
      "ext:deno_node/internal/streams/iter/utils.js",
    );
    _streamIterPull = pullModule.pull;
    _streamIterPullSync = pullModule.pullSync;
    _streamIterParsePullArgs = utils.parsePullArgs;
    _streamIterToUint8Array = utils.toUint8Array;
    _streamIterConvertChunks = utils.convertChunks;
  }
}

// See `fchmodPromise` above for why these are deferred.
let _ftruncatePromise: any;
const ftruncatePromise = (...args: any[]) => {
  _ftruncatePromise ??= promisify(lazyFs().ftruncate);
  return _ftruncatePromise(...new SafeArrayIterator(args));
};
let _fchownPromise: any;
const fchownPromise = (...args: any[]) => {
  _fchownPromise ??= promisify(lazyFs().fchown);
  return _fchownPromise(...new SafeArrayIterator(args));
};
let _futimesPromise: any;
const futimesPromise = (...args: any[]) => {
  _futimesPromise ??= promisify(lazyFs().futimes);
  return _futimesPromise(...new SafeArrayIterator(args));
};

interface WriteResult {
  bytesWritten: number;
  buffer: Buffer | string;
}

interface ReadResult {
  bytesRead: number;
  buffer: Buffer;
}

export class FileHandle extends EventEmitter {
  #rid: number;
  [kRefs]: number;
  [kClosePromise]?: Promise<void> | null;
  [kCloseResolve]?: () => void;
  [kCloseReject]?: (err: Error) => void;
  [kLocked]: boolean;

  constructor(rid: number) {
    super();
    this.#rid = rid;

    this[kRefs] = 1;
    this[kClosePromise] = null;
    this[kLocked] = false;
  }

  get fd() {
    return this.#rid;
  }

  read(
    buffer: ArrayBufferView,
    offset?: number,
    length?: number,
    position?: number | null,
  ): Promise<ReadResult>;
  read(
    buffer: ArrayBufferView,
    options?: any,
  ): Promise<ReadResult>;
  read(options?: any): Promise<ReadResult>;
  read(
    bufferOrOpt?: ArrayBufferView | any,
    offsetOrOpt?: number | any,
    length?: number,
    position?: number | null,
  ): Promise<ReadResult> {
    // Normalize arguments to mirror Node's lib/internal/fs/promises.js
    // FileHandle.read: when length/position are nullish in any of the three
    // overload shapes, fall back to buffer-relative defaults rather than
    // letting them reach fs.read() as `undefined`/`null` and get coerced
    // to 0.
    let buf: ArrayBufferView;
    let offset: number;
    if (ObjectPrototypeIsPrototypeOf(Uint8ArrayPrototype, bufferOrOpt)) {
      buf = bufferOrOpt as ArrayBufferView;
      if (offsetOrOpt == null || typeof offsetOrOpt === "object") {
        // fileHandle.read(buffer, options)
        const opts = (offsetOrOpt ?? {}) as {
          offset?: number;
          length?: number;
          position?: number | null;
        };
        offset = opts.offset ?? 0;
        length = opts.length ?? getByteLength(buf) - offset;
        position = opts.position ?? null;
      } else {
        // fileHandle.read(buffer, offset, length, position)
        offset = offsetOrOpt as number;
        if (length == null) length = getByteLength(buf) - offset;
        if (position == null) position = null;
      }
    } else {
      // fileHandle.read(options)
      if (
        bufferOrOpt !== undefined &&
        bufferOrOpt !== null &&
        typeof bufferOrOpt !== "object"
      ) {
        validateBuffer(bufferOrOpt, "buffer");
      }
      const opts = (bufferOrOpt ?? {}) as {
        buffer?: ArrayBufferView;
        offset?: number;
        length?: number;
        position?: number | null;
      };
      // `opts` is a plain options object; `.buffer` is a normal property,
      // not the TypedArray `.buffer` getter.
      // deno-lint-ignore prefer-primordials
      buf = opts.buffer ?? lazyBuffer().Buffer.alloc(16384);
      offset = opts.offset ?? 0;
      length = opts.length ?? getByteLength(buf) - offset;
      position = opts.position ?? null;
    }
    return fsCall(readPromise, "read", this, buf, offset, length, position);
  }

  truncate(len?: number): Promise<void> {
    return fsCall(ftruncatePromise, "ftruncate", this, len);
  }

  readFile(
    opt?: TextOptionsArgument | BinaryOptionsArgument | FileOptionsArgument,
  ): Promise<string | Buffer> {
    return fsCall(lazyFs().promises.readFile, "readFile", this, opt);
  }

  write(
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
  ): Promise<WriteResult>;
  write(str: string, position: number, encoding: string): Promise<WriteResult>;
  write(
    bufferOrStr: Uint8Array | string,
    offsetOrPosition: number,
    lengthOrEncoding: number | string,
    position?: number,
  ): Promise<WriteResult> {
    return fsCall(
      writePromise,
      "write",
      this,
      bufferOrStr,
      offsetOrPosition,
      lengthOrEncoding,
      position,
    );
  }

  writeFile(data, options): Promise<void> {
    return fsCall(
      lazyFs().promises.writeFile,
      "writeFile",
      this,
      data,
      options,
    );
  }

  writev(buffers: ArrayBufferView[], position?: number): Promise<WriteVResult> {
    return fsCall(writevPromise, "writev", this, buffers, position);
  }

  readv(
    buffers: readonly ArrayBufferView[],
    position?: number,
  ): Promise<any> {
    return fsCall(lazyFs().readvPromise, "readv", this, buffers, position);
  }

  [kRef]() {
    this[kRefs]++;
  }

  [kUnref]() {
    this[kRefs]--;
    // Use #rid (the backing storage) rather than `this.fd` so user code that
    // overrides FileHandle.prototype.fd can't perturb internal close logic.
    // Mirrors Node's lib/internal/fs/promises.js use of `this[kFd]` here.
    if (this[kRefs] > 0 || this.#rid === -1) {
      return;
    }

    PromisePrototypeThen(
      this.#close(),
      this[kCloseResolve],
      this[kCloseReject],
    );
  }

  #close(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        op_node_fs_close(this.#rid);
        this.#rid = -1;
        resolve();
      } catch (err) {
        reject(denoErrorToNodeError(err as Error, { syscall: "close" }));
      }
    });
  }

  [kCloseSync]() {
    if (this.#rid === -1) return;
    if (this[kClosePromise]) {
      throw new ERR_INVALID_STATE("The FileHandle is closing");
    }
    op_node_fs_close(this.#rid);
    this.#rid = -1;
    this.emit("close");
  }

  close(): Promise<void> {
    if (this.#rid === -1) {
      return PromiseResolve();
    }

    if (this[kClosePromise]) {
      return this[kClosePromise];
    }

    this[kRefs]--;
    if (this[kRefs] === 0) {
      this[kClosePromise] = SafePromisePrototypeFinally(
        this.#close(),
        () => {
          this[kClosePromise] = null;
        },
      );
    } else {
      this[kClosePromise] = SafePromisePrototypeFinally(
        new Promise((resolve, reject) => {
          this[kCloseResolve] = resolve as () => void;
          this[kCloseReject] = reject;
        }),
        () => {
          this[kClosePromise] = null;
          this[kCloseReject] = undefined;
          this[kCloseResolve] = undefined;
        },
      );
    }

    this.emit("close");
    return this[kClosePromise];
  }

  stat(): Promise<any>;
  stat(options: { bigint: false }): Promise<any>;
  stat(options: { bigint: true }): Promise<any>;
  stat(options?: { bigint: boolean }): Promise<any> {
    return fsCall(fstatPromise, "fstat", this, options);
  }

  chmod(mode: any): Promise<void> {
    return fsCall(fchmodPromise, "fchmod", this, mode);
  }

  datasync(): Promise<void> {
    return fsCall(fdatasyncPromise, "fdatasync", this);
  }

  sync(): Promise<void> {
    return fsCall(fsyncPromise, "fsync", this);
  }

  utimes(
    atime: number | string | Date,
    mtime: number | string | Date,
  ): Promise<void> {
    return fsCall(futimesPromise, "futimes", this, atime, mtime);
  }

  chown(uid: number, gid: number): Promise<void> {
    return fsCall(fchownPromise, "fchown", this, uid, gid);
  }

  createReadStream(options?: any): any {
    return new (lazyFs().ReadStream)(undefined, { ...options, fd: this });
  }

  createWriteStream(options?: any): any {
    return new (lazyFs().WriteStream)(undefined, { ...options, fd: this });
  }

  readLines(options?: any): any {
    return lazyReadline().createInterface({
      input: this.createReadStream(options),
      crlfDelay: Infinity,
    });
  }

  readableWebStream(
    options: { autoClose?: boolean; type?: string } = kEmptyObject,
  ): ReadableStream<Uint8Array> {
    if (this.fd === -1) {
      throw new ERR_INVALID_STATE("The FileHandle is closed");
    }
    if (this[kClosePromise]) {
      throw new ERR_INVALID_STATE("The FileHandle is closing");
    }
    if (this[kLocked]) {
      throw new ERR_INVALID_STATE("The FileHandle is locked");
    }
    this[kLocked] = true;

    validateObject(options, "options");
    const autoClose = options?.autoClose ?? false;
    const type = options?.type ?? "bytes";
    validateBoolean(autoClose, "options.autoClose");

    if (type !== "bytes") {
      lazyProcess().default.emitWarning(
        'A non-"bytes" options.type has no effect. A byte-oriented steam is ' +
          "always created.",
        "ExperimentalWarning",
      );
    }

    const ondone = async () => {
      this[kUnref]();
      if (autoClose) {
        await PromisePrototypeCatch(this.close(), () => {});
      }
    };

    const readable = new ReadableStream({
      type: "bytes",
      autoAllocateChunkSize: 16384,

      pull: async (controller) => {
        const view = controller.byobRequest!.view! as Uint8Array;
        const { bytesRead } = await this.read(
          view,
          TypedArrayPrototypeGetByteOffset(view),
          TypedArrayPrototypeGetByteLength(view),
        );

        if (bytesRead === 0) {
          controller.close();
          await ondone();
        }

        controller.byobRequest!.respond(bytesRead);
      },

      cancel: async () => {
        await ondone();
      },
    });

    this[kRef]();
    this.once("close", () => {
      readableStreamCancel(readable);
    });

    return readable;
  }

  [SymbolAsyncDispose]() {
    return this.close();
  }

  appendFile(
    data: string | ArrayBufferView | ArrayBuffer | DataView,
    options?: string | { encoding?: string; mode?: number; flag?: string },
  ): Promise<void> {
    const resolvedOptions = typeof options === "string"
      ? { encoding: options }
      : (options ?? {});

    const optsWithAppend = {
      ...resolvedOptions,
      flag: resolvedOptions.flag ?? "a",
    };

    return fsCall(
      lazyFs().promises.writeFile,
      "writeFile",
      this,
      data,
      optsWithAppend,
    );
  }
}

(FileHandle.prototype as any).pull = function pull(
  this: FileHandle,
  ...args: any[]
) {
  if (this.fd === kNoPosition) {
    throw new ERR_INVALID_STATE("The FileHandle is closed");
  }
  if (this[kClosePromise]) {
    throw new ERR_INVALID_STATE("The FileHandle is closing");
  }
  if (this[kLocked]) {
    throw new ERR_INVALID_STATE("The FileHandle is locked");
  }

  lazyStreamIter();
  const { transforms, options = kNullProto } = _streamIterParsePullArgs(args);

  const {
    autoClose = false,
    chunkSize: readSize = kDefaultStreamIterChunkSize,
    signal,
  } = options;
  let {
    start: pos = kNoPosition,
    limit: remaining = kNoPosition,
  } = options;

  validateBoolean(autoClose, "options.autoClose");
  if (pos !== kNoPosition) validateInteger(pos, "options.start", 0);
  if (remaining !== kNoPosition) {
    validateInteger(remaining, "options.limit", 1);
  }
  if (readSize !== undefined) {
    validateInteger(readSize, "options.chunkSize", 1);
  }
  if (signal !== undefined) validateAbortSignal(signal, "options.signal");

  const handle = this;
  this[kLocked] = true;

  const source = {
    __proto__: null,
    async *[SymbolAsyncIterator]() {
      handle[kRef]();
      try {
        while (remaining !== 0) {
          if (signal?.aborted) {
            throw signal.reason;
          }
          const toRead = remaining > 0
            ? MathMin(readSize, remaining)
            : readSize;
          const buf = lazyBuffer().Buffer.allocUnsafe(toRead);
          const { bytesRead } = await handle.read(
            buf,
            0,
            toRead,
            pos >= 0 ? pos : null,
          );
          if (bytesRead === 0) break;
          if (pos >= 0) pos += bytesRead;
          if (remaining > 0) remaining -= bytesRead;
          yield [
            bytesRead < toRead
              ? TypedArrayPrototypeSubarray(buf, 0, bytesRead)
              : buf,
          ];
        }
      } finally {
        handle[kLocked] = false;
        handle[kUnref]();
        if (autoClose) {
          await PromisePrototypeCatch(handle.close(), () => {});
        }
      }
    },
  };

  if (transforms.length > 0) {
    const pullArgs = [...new SafeArrayIterator(transforms)];
    if (options) ArrayPrototypePush(pullArgs, options);
    return _streamIterPull(source, ...new SafeArrayIterator(pullArgs));
  }
  return source;
};

(FileHandle.prototype as any).pullSync = function pullSync(
  this: FileHandle,
  ...args: any[]
) {
  if (this.fd === kNoPosition) {
    throw new ERR_INVALID_STATE("The FileHandle is closed");
  }
  if (this[kClosePromise]) {
    throw new ERR_INVALID_STATE("The FileHandle is closing");
  }
  if (this[kLocked]) {
    throw new ERR_INVALID_STATE("The FileHandle is locked");
  }

  lazyStreamIter();
  const { transforms, options = kNullProto } = _streamIterParsePullArgs(args);

  const {
    autoClose = false,
    chunkSize: readSize = kDefaultStreamIterChunkSize,
  } = options;
  let {
    start: pos = kNoPosition,
    limit: remaining = kNoPosition,
  } = options;

  validateBoolean(autoClose, "options.autoClose");
  if (pos !== kNoPosition) validateInteger(pos, "options.start", 0);
  if (remaining !== kNoPosition) {
    validateInteger(remaining, "options.limit", 1);
  }
  if (readSize !== undefined) {
    validateInteger(readSize, "options.chunkSize", 1);
  }

  const handle = this;
  const fd = this.fd;
  this[kLocked] = true;
  handle[kRef]();

  function cleanup() {
    handle[kLocked] = false;
    handle[kUnref]();
    if (autoClose) handle[kCloseSync]();
  }

  const source = {
    __proto__: null,
    [SymbolIterator]() {
      let done = false;
      return {
        __proto__: null,
        next() {
          if (done || remaining === 0) {
            if (!done) {
              done = true;
              cleanup();
            }
            return { __proto__: null, done: true, value: undefined };
          }
          const toRead = remaining > 0
            ? MathMin(readSize, remaining)
            : readSize;
          const buf = lazyBuffer().Buffer.allocUnsafe(toRead);
          let bytesRead;
          try {
            bytesRead = lazyFs().readSync(
              fd,
              buf,
              0,
              toRead,
              pos >= 0 ? pos : null,
            ) || 0;
          } catch (err) {
            done = true;
            cleanup();
            throw err;
          }
          if (bytesRead === 0) {
            done = true;
            cleanup();
            return { __proto__: null, done: true, value: undefined };
          }
          if (pos >= 0) pos += bytesRead;
          if (remaining > 0) remaining -= bytesRead;
          const chunk = bytesRead < toRead
            ? TypedArrayPrototypeSubarray(buf, 0, bytesRead)
            : buf;
          return { __proto__: null, done: false, value: [chunk] };
        },
        return() {
          if (!done) {
            done = true;
            cleanup();
          }
          return { __proto__: null, done: true, value: undefined };
        },
      };
    },
  };

  if (transforms.length > 0) {
    return _streamIterPullSync(source, ...new SafeArrayIterator(transforms));
  }
  return source;
};

(FileHandle.prototype as any).writer = function writer(
  this: FileHandle,
  options = kNullProto,
) {
  if (this.fd === kNoPosition) {
    throw new ERR_INVALID_STATE("The FileHandle is closed");
  }
  if (this[kClosePromise]) {
    throw new ERR_INVALID_STATE("The FileHandle is closing");
  }
  if (this[kLocked]) {
    throw new ERR_INVALID_STATE("The FileHandle is locked");
  }

  lazyStreamIter();
  validateObject(options, "options");
  const {
    autoClose = false,
    chunkSize: syncWriteThreshold = kDefaultStreamIterChunkSize,
  } = options;
  let {
    start: pos = kNoPosition,
    limit: bytesRemaining = kNoPosition,
  } = options;

  validateBoolean(autoClose, "options.autoClose");
  if (pos !== kNoPosition) validateInteger(pos, "options.start", 0);
  if (bytesRemaining !== kNoPosition) {
    validateInteger(bytesRemaining, "options.limit", 1);
  }
  if (syncWriteThreshold !== undefined) {
    validateInteger(syncWriteThreshold, "options.chunkSize", 1);
  }

  const handle = this;
  const fd = this.fd;
  let totalBytesWritten = 0;
  let closed = false;
  let closing = false;
  let pendingEndPromise: Promise<number> | null = null;
  let error: Error | null = null;
  let asyncPending = false;

  this[kLocked] = true;
  handle[kRef]();

  async function writeAll(
    buf: Uint8Array,
    offset: number,
    length: number,
    position: number,
    signal?: AbortSignal,
  ) {
    asyncPending = true;
    try {
      while (length > 0) {
        const { bytesWritten } = await handle.write(
          buf,
          offset,
          length,
          position >= 0 ? position : null,
        );
        signal?.throwIfAborted();
        totalBytesWritten += bytesWritten;
        offset += bytesWritten;
        length -= bytesWritten;
        if (position >= 0) position += bytesWritten;
        if (bytesWritten === 0 && length > 0) {
          throw new ERR_INVALID_STATE("write made no progress");
        }
      }
    } finally {
      asyncPending = false;
    }
  }

  async function writevAll(
    buffers: Uint8Array[],
    position: number,
    signal?: AbortSignal,
  ) {
    asyncPending = true;
    try {
      let totalSize = 0;
      for (let i = 0; i < buffers.length; i++) {
        totalSize += TypedArrayPrototypeGetByteLength(buffers[i]);
      }
      if (totalSize === 0) return;
      const { bytesWritten } = await handle.writev(
        buffers,
        position >= 0 ? position : null,
      );
      signal?.throwIfAborted();
      totalBytesWritten += bytesWritten;
      if (bytesWritten < totalSize) {
        const remaining = lazyBuffer().Buffer.concat(buffers);
        await writeAll(
          remaining,
          bytesWritten,
          totalSize - bytesWritten,
          position >= 0 ? position + bytesWritten : kNoPosition,
          signal,
        );
      }
    } finally {
      asyncPending = false;
    }
  }

  function writeSyncAll(
    buf: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ) {
    while (length > 0) {
      const bytesWritten = lazyFs().writeSync(
        fd,
        buf,
        offset,
        length,
        position >= 0 ? position : null,
      ) || 0;
      totalBytesWritten += bytesWritten;
      offset += bytesWritten;
      length -= bytesWritten;
      if (position >= 0) position += bytesWritten;
      if (bytesWritten === 0 && length > 0) {
        throw new ERR_INVALID_STATE("write made no progress");
      }
    }
  }

  async function cleanup() {
    if (closed) return;
    closed = true;
    handle[kLocked] = false;
    handle[kUnref]();
    if (autoClose) await handle.close();
  }

  function cleanupSync() {
    if (closed) return;
    closed = true;
    handle[kLocked] = false;
    handle[kUnref]();
    if (autoClose) handle[kCloseSync]();
  }

  return {
    __proto__: null,
    write(chunk: Uint8Array | string, options = kNullProto) {
      if (error) return PromiseReject(error);
      if (closed) {
        return PromiseReject(
          new ERR_INVALID_STATE.TypeError("The writer is closed"),
        );
      }
      validateObject(options, "options");
      const { signal } = options;
      if (signal !== undefined) {
        validateAbortSignal(signal, "options.signal");
        if (signal.aborted) return PromiseReject(signal.reason);
      }
      chunk = _streamIterToUint8Array(chunk);
      if (
        bytesRemaining >= 0 &&
        TypedArrayPrototypeGetByteLength(chunk) > bytesRemaining
      ) {
        return PromiseReject(
          new ERR_OUT_OF_RANGE(
            "write",
            `<= ${bytesRemaining} bytes`,
            TypedArrayPrototypeGetByteLength(chunk),
          ),
        );
      }
      if (bytesRemaining > 0) {
        bytesRemaining -= TypedArrayPrototypeGetByteLength(chunk);
      }
      const position = pos;
      if (pos >= 0) pos += TypedArrayPrototypeGetByteLength(chunk);
      return writeAll(
        chunk,
        0,
        TypedArrayPrototypeGetByteLength(chunk),
        position,
        signal,
      );
    },

    writev(chunks: Uint8Array[], options = kNullProto) {
      if (error) return PromiseReject(error);
      if (closed) {
        return PromiseReject(
          new ERR_INVALID_STATE.TypeError("The writer is closed"),
        );
      }
      validateObject(options, "options");
      const { signal } = options;
      if (signal !== undefined) {
        validateAbortSignal(signal, "options.signal");
        if (signal.aborted) return PromiseReject(signal.reason);
      }
      chunks = _streamIterConvertChunks(chunks);
      let totalSize = 0;
      for (let i = 0; i < chunks.length; i++) {
        totalSize += TypedArrayPrototypeGetByteLength(chunks[i]);
      }
      if (bytesRemaining >= 0 && totalSize > bytesRemaining) {
        return PromiseReject(
          new ERR_OUT_OF_RANGE(
            "writev",
            `<= ${bytesRemaining} bytes`,
            totalSize,
          ),
        );
      }
      if (bytesRemaining > 0) bytesRemaining -= totalSize;
      const position = pos;
      if (pos >= 0) pos += totalSize;
      return writevAll(chunks, position, signal);
    },

    writeSync(chunk: Uint8Array | string) {
      if (error || closed || asyncPending) return false;
      chunk = _streamIterToUint8Array(chunk);
      const length = TypedArrayPrototypeGetByteLength(chunk);
      if (length > syncWriteThreshold) return false;
      if (length === 0) return true;
      if (bytesRemaining >= 0 && length > bytesRemaining) return false;
      const position = pos;
      try {
        const bytesWritten = lazyFs().writeSync(
          fd,
          chunk,
          0,
          length,
          position >= 0 ? position : null,
        ) || 0;
        totalBytesWritten += bytesWritten;
        if (position >= 0) pos = position + bytesWritten;
        if (bytesWritten !== length) {
          writeSyncAll(
            chunk,
            bytesWritten,
            length - bytesWritten,
            position >= 0 ? position + bytesWritten : kNoPosition,
          );
        }
        if (bytesRemaining > 0) bytesRemaining -= length;
        return true;
      } catch {
        return false;
      }
    },

    writevSync(chunks: Uint8Array[]) {
      if (error || closed || asyncPending) return false;
      chunks = _streamIterConvertChunks(chunks);
      let totalSize = 0;
      for (let i = 0; i < chunks.length; i++) {
        totalSize += TypedArrayPrototypeGetByteLength(chunks[i]);
      }
      if (totalSize > syncWriteThreshold) return false;
      if (totalSize === 0) return true;
      if (bytesRemaining >= 0 && totalSize > bytesRemaining) return false;
      const position = pos;
      try {
        const bytesWritten = lazyFs().writevSync(
          fd,
          chunks,
          position >= 0 ? position : null,
        ) || 0;
        totalBytesWritten += bytesWritten;
        if (position >= 0) pos = position + bytesWritten;
        if (bytesWritten !== totalSize) {
          const rest = lazyBuffer().Buffer.concat(chunks);
          writeSyncAll(
            rest,
            bytesWritten,
            totalSize - bytesWritten,
            position >= 0 ? position + bytesWritten : kNoPosition,
          );
        }
        if (bytesRemaining > 0) bytesRemaining -= totalSize;
        return true;
      } catch {
        return false;
      }
    },

    end(options = kNullProto) {
      if (error) return PromiseReject(error);
      if (closed) return PromiseResolve(totalBytesWritten);
      if (closing) return pendingEndPromise;
      validateObject(options, "options");
      const { signal } = options;
      if (signal !== undefined) {
        validateAbortSignal(signal, "options.signal");
        if (signal.aborted) return PromiseReject(signal.reason);
      }
      closing = true;
      pendingEndPromise = PromisePrototypeThen(
        cleanup(),
        () => totalBytesWritten,
      );
      return pendingEndPromise;
    },

    endSync() {
      if (error) return -1;
      if (closed) return totalBytesWritten;
      if (asyncPending) return -1;
      cleanupSync();
      return totalBytesWritten;
    },

    fail(reason?: Error) {
      if (closed || error) return;
      error = reason ?? new ERR_INVALID_STATE("Failed");
      cleanupSync();
    },

    [SymbolAsyncDispose]() {
      if (closing) return pendingEndPromise ?? PromiseResolve();
      if (!closed && !error) this.fail();
      return PromiseResolve();
    },

    [SymbolDispose]() {
      this.fail();
    },
  };
};

function readPromise(
  rid: number,
  buffer: ArrayBufferView,
  offset?: number,
  length?: number,
  position?: number | null,
): Promise<ReadResult>;
function readPromise(
  rid: number,
  buffer: ArrayBufferView,
  options?: any,
): Promise<ReadResult>;
function readPromise(
  rid: number,
  options?: any,
): Promise<ReadResult>;
function readPromise(
  rid: number,
  bufferOrOpt?: ArrayBufferView | any,
  offsetOrOpt?: number | any,
  length?: number,
  position?: number | null,
): Promise<ReadResult> {
  if (ObjectPrototypeIsPrototypeOf(Uint8ArrayPrototype, bufferOrOpt)) {
    if (
      typeof offsetOrOpt !== "number" && typeof length !== "number" &&
      typeof position !== "number"
    ) {
      // fileHandle.read(buffer) or fileHandle.read(buffer, options)
      const opts = (offsetOrOpt ?? {}) as any;
      return new Promise((resolve, reject) => {
        lazyFs().read(
          rid,
          bufferOrOpt,
          opts,
          (err: Error, bytesRead: number, buffer: Buffer) => {
            if (err) reject(err);
            else resolve({ buffer, bytesRead });
          },
        );
      });
    }

    return new Promise((resolve, reject) => {
      lazyFs().read(
        rid,
        bufferOrOpt,
        offsetOrOpt,
        length,
        position,
        (err: Error, bytesRead: number, buffer: Buffer) => {
          if (err) reject(err);
          else resolve({ buffer, bytesRead });
        },
      );
    });
  } else {
    return new Promise((resolve, reject) => {
      lazyFs().read(
        rid,
        bufferOrOpt,
        (err: Error, bytesRead: number, buffer: Buffer) => {
          if (err) reject(err);
          else resolve({ buffer, bytesRead });
        },
      );
    });
  }
}

function writePromise(
  rid: number,
  buffer: Buffer,
  offset: number,
  length: number,
  position: number,
): Promise<WriteResult>;
function writePromise(
  rid: number,
  str: string,
  position: number,
  encoding: string,
): Promise<WriteResult>;
function writePromise(
  rid: number,
  bufferOrStr: Uint8Array | string,
  offsetOrPosition: number,
  lengthOrEncoding: number | string,
  position?: number,
): Promise<WriteResult> {
  if (ObjectPrototypeIsPrototypeOf(Uint8ArrayPrototype, bufferOrStr)) {
    const buffer = bufferOrStr;
    const offset = offsetOrPosition;
    const length = lengthOrEncoding;

    return new Promise((resolve, reject) => {
      lazyFs().write(
        rid,
        buffer,
        offset,
        length,
        position,
        (err: Error, bytesWritten: number, buffer: Buffer) => {
          if (err) reject(err);
          else resolve({ buffer, bytesWritten });
        },
      );
    });
  } else {
    const str = bufferOrStr;
    const position = offsetOrPosition;
    const encoding = lengthOrEncoding;

    return new Promise((resolve, reject) => {
      lazyFs().write(
        rid,
        str,
        position,
        encoding,
        (err: Error, bytesWritten: number, buffer: Buffer) => {
          if (err) reject(err);
          else resolve({ buffer, bytesWritten });
        },
      );
    });
  }
}

function assertNotClosed(rid: number, syscall: string) {
  if (rid === -1) {
    const err = new Error("file closed");
    throw ObjectAssign(err, {
      code: "EBADF",
      syscall,
    });
  }
}

type FileHandleFn<P, R> = (...args: [number, ...P[]]) => Promise<R>;

async function fsCall<P, R, T extends FileHandleFn<P, R>>(
  fn: T,
  fnName: string,
  handle: FileHandle,
  ...args: P[]
): Promise<R> {
  assert(
    handle[kRefs] !== undefined,
    "handle must be an instance of FileHandle",
  );
  assertNotClosed(handle.fd, fnName);
  try {
    handle[kRef]();
    return await fn(handle.fd, ...new SafeArrayIterator(args));
  } finally {
    handle[kUnref]();
  }
}

export default {
  FileHandle,
};
