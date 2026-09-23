// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.
// Ported from Node.js v26.10.0 lib/internal/streams/iter/transform.js.

(function () {
const { core, primordials } = __bootstrap;

// Compression / Decompression Transforms
//
// Creates bare native zlib handles from the zlib binding, bypassing
// the stream.Transform / ZlibBase / EventEmitter machinery entirely.
// Deno's handle.write() runs the engine synchronously; the completion is
// delivered on a later tick, as Node's threadpool completion is.
// Each factory returns a transform descriptor that can be passed to pull().

const {
  ArrayPrototypeMap,
  ArrayPrototypePush,
  ArrayPrototypeShift,
  MathMax,
  NumberIsNaN,
  ObjectEntries,
  ObjectKeys,
  PromiseWithResolvers,
  StringPrototypeStartsWith,
  SymbolAsyncIterator,
  TypedArrayPrototypeFill,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeSlice,
  Uint32Array,
  Uint8Array,
} = primordials;

const process = core.createLazyLoader("node:process")().default;

const { Buffer } = core.loadExtScript("ext:deno_node/internal/buffer.mjs");
const {
  codes: {
    ERR_BROTLI_INVALID_PARAM,
    ERR_INVALID_ARG_TYPE,
    ERR_OUT_OF_RANGE,
    ERR_ZSTD_INVALID_PARAM,
  },
  genericNodeError,
} = core.loadExtScript("ext:deno_node/internal/errors.ts");
const {
  isArrayBufferView,
  isAnyArrayBuffer,
  isUint8Array,
} = core.loadExtScript("ext:deno_node/internal/util/types.ts");
const { kValidatedTransform } = core.loadExtScript(
  "ext:deno_node/internal/streams/iter/types.js",
);
const {
  checkRangesOrGetDefault,
  validateFiniteNumber,
  validateObject,
} = core.loadExtScript("ext:deno_node/internal/validators.mjs");
const binding = core.loadExtScript("ext:deno_node/_zlib_binding.mjs");
const { zlib: constants } = core.loadExtScript(
  "ext:deno_node/internal_binding/constants.ts",
);

const {
  // Zlib modes
  DEFLATE,
  INFLATE,
  GZIP,
  GUNZIP,
  BROTLI_ENCODE,
  BROTLI_DECODE,
  ZSTD_COMPRESS,
  ZSTD_DECOMPRESS,
  // Zlib flush
  Z_NO_FLUSH,
  Z_FINISH,
  // Zlib defaults
  Z_DEFAULT_WINDOWBITS,
  Z_DEFAULT_STRATEGY,
  // Brotli flush
  BROTLI_OPERATION_PROCESS,
  BROTLI_OPERATION_FINISH,
  // Zlib ranges
  Z_MIN_CHUNK,
  Z_MIN_WINDOWBITS,
  Z_MAX_WINDOWBITS,
  Z_MIN_LEVEL,
  Z_MAX_LEVEL,
  Z_MIN_MEMLEVEL,
  Z_MAX_MEMLEVEL,
  Z_FIXED,
  // Zstd flush
  ZSTD_e_continue,
  ZSTD_e_end,
} = constants;

// ---------------------------------------------------------------------------
// Option validation helpers (matching lib/zlib.js validation patterns)
// ---------------------------------------------------------------------------

// Default output buffer size for compression transforms. Larger than
// Z_DEFAULT_CHUNK (16KB) to reduce the number of threadpool re-entries
// when the engine has more output than fits in one buffer. 64KB matches
// BATCH_HWM and the typical input chunk size from pull().
const DEFAULT_OUTPUT_SIZE = 64 * 1024;

// Batch high water mark - yield output in chunks of approximately this size.
const BATCH_HWM = DEFAULT_OUTPUT_SIZE;

// Pre-allocated empty buffer for flush/finalize calls.
const kEmpty = Buffer.alloc(0);

function validateChunkSize(options) {
  let chunkSize = options.chunkSize;
  if (!validateFiniteNumber(chunkSize, "options.chunkSize")) {
    chunkSize = DEFAULT_OUTPUT_SIZE;
  } else if (chunkSize < Z_MIN_CHUNK) {
    throw new ERR_OUT_OF_RANGE(
      "options.chunkSize",
      `>= ${Z_MIN_CHUNK}`,
      chunkSize,
    );
  }
  return chunkSize;
}

function validateDictionary(dictionary) {
  if (dictionary === undefined) return undefined;
  // Deno's binding takes the dictionary as a Uint8Array.
  if (isUint8Array(dictionary)) return dictionary;
  if (isArrayBufferView(dictionary)) {
    return new Uint8Array(
      dictionary.buffer,
      dictionary.byteOffset,
      dictionary.byteLength,
    );
  }
  if (isAnyArrayBuffer(dictionary)) return Buffer.from(dictionary);
  throw new ERR_INVALID_ARG_TYPE(
    "options.dictionary",
    ["Buffer", "TypedArray", "DataView", "ArrayBuffer"],
    dictionary,
  );
}

function validateParams(params, maxParam, errClass) {
  if (params === undefined) return;
  validateObject(params, "options.params", { allowArray: true });
  const keys = ObjectKeys(params);
  for (let i = 0; i < keys.length; i++) {
    const origKey = keys[i];
    const key = +origKey;
    if (NumberIsNaN(key) || key < 0 || key > maxParam) {
      throw new errClass(origKey);
    }
    const value = params[origKey];
    if (typeof value !== "number" && typeof value !== "boolean") {
      throw new ERR_INVALID_ARG_TYPE("options.params[key]", "number", value);
    }
  }
}

// ---------------------------------------------------------------------------
// Brotli / Zstd parameter arrays (computed once, reused per init call).
// Mirrors the pattern in lib/zlib.js.
// ---------------------------------------------------------------------------
const kMaxBrotliParam = MathMax(
  ...ArrayPrototypeMap(
    ObjectEntries(constants),
    (
      { 0: key, 1: value },
    ) => (StringPrototypeStartsWith(key, "BROTLI_PARAM_") ? value : 0),
  ),
);
const brotliInitParamsArray = new Uint32Array(kMaxBrotliParam + 1);

const kMaxZstdCParam = MathMax(
  ...ArrayPrototypeMap(
    ObjectKeys(constants),
    (key) => (StringPrototypeStartsWith(key, "ZSTD_c_") ? constants[key] : 0),
  ),
);
const zstdInitCParamsArray = new Uint32Array(kMaxZstdCParam + 1);

const kMaxZstdDParam = MathMax(
  ...ArrayPrototypeMap(
    ObjectKeys(constants),
    (key) => (StringPrototypeStartsWith(key, "ZSTD_d_") ? constants[key] : 0),
  ),
);
const zstdInitDParamsArray = new Uint32Array(kMaxZstdDParam + 1);

// ---------------------------------------------------------------------------
// Handle creation - bare native handles, no Transform/EventEmitter overhead.
//
// Each factory accepts a processCallback and an onError handler. Deno's
// write ops take the writeState buffer as their last argument instead of
// at init.
// ---------------------------------------------------------------------------

/**
 * Create a bare Zlib handle (gzip, gunzip, deflate, inflate).
 * @returns {{ handle: object, writeState: Uint32Array, chunkSize: number }}
 */
function createZlibHandle(mode, options, processCallback, onError) {
  // Validate all options before creating the native handle to avoid
  // "close before init" assertion if validation throws.
  const chunkSize = validateChunkSize(options);
  const windowBits = checkRangesOrGetDefault(
    options.windowBits,
    "options.windowBits",
    Z_MIN_WINDOWBITS,
    Z_MAX_WINDOWBITS,
    Z_DEFAULT_WINDOWBITS,
  );
  // Default compression level 4 (not Z_DEFAULT_COMPRESSION which maps to
  // level 6). Level 4 is ~1.5x faster with only ~5-10% worse compression
  // ratio - the sweet spot for streaming and HTTP content-encoding.
  const level = checkRangesOrGetDefault(
    options.level,
    "options.level",
    Z_MIN_LEVEL,
    Z_MAX_LEVEL,
    4,
  );
  // memLevel 9 uses ~128KB more memory than 8 but provides faster hash
  // lookups during compression. Negligible memory cost for the speed gain.
  const memLevel = checkRangesOrGetDefault(
    options.memLevel,
    "options.memLevel",
    Z_MIN_MEMLEVEL,
    Z_MAX_MEMLEVEL,
    9,
  );
  const strategy = checkRangesOrGetDefault(
    options.strategy,
    "options.strategy",
    Z_DEFAULT_STRATEGY,
    Z_FIXED,
    Z_DEFAULT_STRATEGY,
  );
  const dictionary = validateDictionary(options.dictionary);

  const handle = new binding.Zlib(mode);
  const writeState = new Uint32Array(2);

  handle.onerror = onError;
  handle.init(
    windowBits,
    level,
    memLevel,
    strategy,
    processCallback,
    dictionary,
  );

  return { __proto__: null, handle, writeState, chunkSize };
}

/**
 * Create a bare Brotli handle.
 * @returns {{ handle: object, writeState: Uint32Array, chunkSize: number }}
 */
function createBrotliHandle(mode, options, processCallback, onError) {
  // Validate before creating native handle.
  const chunkSize = validateChunkSize(options);
  const dictionary = validateDictionary(options.dictionary);
  validateParams(options.params, kMaxBrotliParam, ERR_BROTLI_INVALID_PARAM);

  const handle = mode === BROTLI_ENCODE
    ? new binding.BrotliEncoder(mode)
    : new binding.BrotliDecoder(mode);
  const writeState = new Uint32Array(2);

  TypedArrayPrototypeFill(brotliInitParamsArray, -1);
  // Streaming-appropriate defaults: quality 6 (not 11) and lgwin 20 (1MB,
  // not 4MB). Quality 11 is intended for offline/build-time compression
  // and allocates ~400MB of internal state. Quality 6 is ~10x faster with
  // only ~10-15% worse compression ratio - the standard for dynamic HTTP
  // content-encoding (nginx, Caddy, Cloudflare all use 4-6).
  if (mode === BROTLI_ENCODE) {
    brotliInitParamsArray[constants.BROTLI_PARAM_QUALITY] = 6;
    brotliInitParamsArray[constants.BROTLI_PARAM_LGWIN] = 20;
  }
  if (options.params) {
    // User-supplied params override the defaults above.
    const params = options.params;
    const keys = ObjectKeys(params);
    for (let i = 0; i < keys.length; i++) {
      const key = +keys[i];
      brotliInitParamsArray[key] = params[keys[i]];
    }
  }

  handle.onerror = onError;
  // Deno's Brotli binding has no dictionary support, as in lib/zlib.js.
  handle.init(
    brotliInitParamsArray,
    processCallback,
  );

  return { __proto__: null, handle, writeState, chunkSize };
}

/**
 * Create a bare Zstd handle.
 * @returns {{ handle: object, writeState: Uint32Array, chunkSize: number }}
 */
function createZstdHandle(mode, options, processCallback, onError) {
  const isCompress = mode === ZSTD_COMPRESS;

  // Validate before creating native handle.
  const chunkSize = validateChunkSize(options);
  const dictionary = validateDictionary(options.dictionary);
  const maxParam = isCompress ? kMaxZstdCParam : kMaxZstdDParam;
  validateParams(options.params, maxParam, ERR_ZSTD_INVALID_PARAM);

  const pledgedSrcSize = options.pledgedSrcSize;

  const handle = isCompress
    ? new binding.ZstdCompress(mode)
    : new binding.ZstdDecompress(mode);
  const writeState = new Uint32Array(2);

  const initArray = isCompress ? zstdInitCParamsArray : zstdInitDParamsArray;
  TypedArrayPrototypeFill(initArray, -1);
  if (options.params) {
    const params = options.params;
    const keys = ObjectKeys(params);
    for (let i = 0; i < keys.length; i++) {
      const key = +keys[i];
      initArray[key] = params[keys[i]];
    }
  }

  handle.onerror = onError;
  handle.init(
    initArray,
    processCallback,
    pledgedSrcSize,
    dictionary,
  );

  return { __proto__: null, handle, writeState, chunkSize };
}

// ---------------------------------------------------------------------------
// Core: makeZlibTransform
//
// Uses handle.write() and completes each write on a later tick, as Node's
// threadpool completion does. The generator manually iterates the source
// with pre-reading: the next upstream read+transform is started before
// awaiting the current compression.
// ---------------------------------------------------------------------------
function makeZlibTransform(createHandleFn, processFlag, finishFlag) {
  return {
    __proto__: null,
    [kValidatedTransform]: true,
    transform: async function* (source, options) {
      const { signal } = options;

      // Fail fast if already aborted - don't allocate a native handle.
      signal?.throwIfAborted();

      // ---- Per-invocation state shared with the write callback ----
      let outBuf;
      let outOffset = 0;
      let chunkSize;
      let pending = [];
      let pendingBytes = 0;

      // Current write operation state (read by the callback for looping).
      let resolveWrite, rejectWrite;
      let writeInput, writeFlush;
      let writeInOff, writeAvailIn, writeAvailOutBefore;

      // Called on the tick after a write that did not fail. Collects
      // output, loops if the engine has more output to produce
      // (availOut === 0), then resolves the promise when all output for
      // this input chunk is collected.
      function onWriteComplete() {
        const availOut = writeState[0];
        const availInAfter = writeState[1];
        const have = writeAvailOutBefore - availOut;
        const bufferExhausted = availOut === 0 || outOffset + have >= chunkSize;

        if (have > 0) {
          if (bufferExhausted && outOffset === 0) {
            // Entire buffer filled from start - yield directly, no copy.
            ArrayPrototypePush(pending, outBuf);
          } else if (bufferExhausted) {
            // Tail of buffer filled and buffer is being replaced -
            // subarray is safe since outBuf reference is overwritten below.
            ArrayPrototypePush(
              pending,
              outBuf.subarray(outOffset, outOffset + have),
            );
          } else {
            // Partial fill, buffer will be reused - must copy.
            ArrayPrototypePush(
              pending,
              TypedArrayPrototypeSlice(outBuf, outOffset, outOffset + have),
            );
          }
          pendingBytes += have;
          outOffset += have;
        }

        // Reallocate output buffer if exhausted.
        if (bufferExhausted) {
          outBuf = Buffer.allocUnsafe(chunkSize);
          outOffset = 0;
        }

        if (availOut === 0) {
          // Engine has more output - but if aborted, don't loop.
          if (!resolveWrite) return;

          const consumed = writeAvailIn - availInAfter;
          writeInOff += consumed;
          writeAvailIn = availInAfter;
          writeAvailOutBefore = chunkSize - outOffset;

          dispatchWrite(
            writeFlush,
            writeInput,
            writeInOff,
            writeAvailIn,
            outBuf,
            outOffset,
            writeAvailOutBefore,
          );
          return; // Will call onWriteComplete again.
        }

        // All input consumed and output collected.
        handle.buffer = null;
        const resolve = resolveWrite;
        resolveWrite = undefined;
        rejectWrite = undefined;
        if (resolve) resolve();
      }

      // onError: called by the binding when the engine encounters an error.
      // Fires instead of onWriteComplete - reject the promise.
      function onError(message, errno, code) {
        writeFailed = true;
        const error = genericNodeError(message, {
          __proto__: null,
          errno,
          code,
        });
        error.errno = errno;
        error.code = code;
        const reject = rejectWrite;
        resolveWrite = undefined;
        rejectWrite = undefined;
        if (reject) reject(error);
      }

      // Deno's binding runs the engine inside handle.write(). Brotli and
      // Zstd call the process callback before write() returns, and Zlib
      // does not call it. Ignore it and complete every write on the next
      // tick unless onError reported a failure.
      let writeFailed = false;
      function dispatchWrite(
        flushFlag,
        input,
        inOff,
        availIn,
        out,
        outOff,
        availOut,
      ) {
        writeFailed = false;
        try {
          handle.write(
            flushFlag,
            input,
            inOff,
            availIn,
            out,
            outOff,
            availOut,
            writeState,
          );
        } catch (err) {
          // Some Deno engine errors throw instead of calling onerror. This
          // can run from a nextTick callback, so reject the write instead.
          const reject = rejectWrite;
          resolveWrite = undefined;
          rejectWrite = undefined;
          if (reject) reject(err);
          return;
        }
        if (!writeFailed) process.nextTick(onWriteComplete);
      }

      // ---- Create the handle with our callbacks ----
      const result = createHandleFn(() => {}, onError);
      const handle = result.handle;
      const writeState = result.writeState;
      chunkSize = result.chunkSize;
      outBuf = Buffer.allocUnsafe(chunkSize);

      // Abort handler: reject any in-flight threadpool operation so the
      // generator doesn't block waiting for compression to finish.
      const onAbort = () => {
        const reject = rejectWrite;
        resolveWrite = undefined;
        rejectWrite = undefined;
        if (reject) {
          reject(signal.reason);
        }
      };
      signal.addEventListener("abort", onAbort, {
        __proto__: null,
        once: true,
      });

      // Dispatch input to the threadpool and return a promise.
      function processInputAsync(input, flushFlag) {
        const { promise, resolve, reject } = PromiseWithResolvers();
        resolveWrite = resolve;
        rejectWrite = reject;
        writeInput = input;
        writeFlush = flushFlag;
        writeInOff = 0;
        writeAvailIn = TypedArrayPrototypeGetByteLength(input);
        writeAvailOutBefore = chunkSize - outOffset;

        // Keep input alive while the threadpool references it.
        handle.buffer = input;

        dispatchWrite(
          flushFlag,
          input,
          0,
          writeAvailIn,
          outBuf,
          outOffset,
          writeAvailOutBefore,
        );
        return promise;
      }

      function drainBatch() {
        if (pendingBytes <= BATCH_HWM) {
          // Swap instead of splice - avoids copying the array.
          const batch = pending;
          pending = [];
          pendingBytes = 0;
          return batch;
        }
        const batch = [];
        let batchBytes = 0;
        while (pending.length > 0 && batchBytes < BATCH_HWM) {
          const buf = ArrayPrototypeShift(pending);
          ArrayPrototypePush(batch, buf);
          const len = TypedArrayPrototypeGetByteLength(buf);
          batchBytes += len;
          pendingBytes -= len;
        }
        return batch;
      }

      let finalized = false;

      const iter = source[SymbolAsyncIterator]();
      try {
        // Manually iterate the source so we can pre-read: calling
        // iter.next() starts the upstream read + transform on libuv
        // before we await the current compression on the threadpool.
        let nextResult = iter.next();

        while (true) {
          const { value: chunks, done } = await nextResult;
          if (done) break;

          signal?.throwIfAborted();

          if (chunks === null) {
            // Flush signal - finalize the engine.
            if (!finalized) {
              finalized = true;
              await processInputAsync(kEmpty, finishFlag);
              while (pending.length > 0) {
                yield drainBatch();
              }
            }
            nextResult = iter.next();
            continue;
          }

          // Pre-read: start upstream I/O + transform for the NEXT batch
          // while we compress the current batch on the threadpool.
          nextResult = iter.next();

          for (let i = 0; i < chunks.length; i++) {
            await processInputAsync(chunks[i], processFlag);
          }

          if (pendingBytes >= BATCH_HWM) {
            while (pending.length > 0 && pendingBytes >= BATCH_HWM) {
              yield drainBatch();
            }
          }
          if (pending.length > 0) {
            yield drainBatch();
          }
        }

        // Source ended - finalize if not already done by a null signal.
        if (!finalized && !signal.aborted) {
          finalized = true;
          await processInputAsync(kEmpty, finishFlag);
          while (pending.length > 0) {
            yield drainBatch();
          }
        }
      } finally {
        signal.removeEventListener("abort", onAbort);
        handle.close();
        // Close the upstream iterator so its finally blocks run promptly
        // rather than waiting for GC.
        try {
          await iter.return?.();
        } catch { /* Intentional no-op. */ }
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Compression factories
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Core: makeZlibTransformSync
//
// Synchronous counterpart to makeZlibTransform. Uses handle.writeSync()
// which runs compression directly on the main thread (no threadpool).
// Returns a stateful sync transform (generator function).
// ---------------------------------------------------------------------------
function makeZlibTransformSync(createHandleFn, processFlag, finishFlag) {
  return {
    __proto__: null,
    transform: function* (source) {
      // The processCallback is never called in sync mode, but handle.init()
      // requires it. Pass a no-op.
      let error = null;
      function onError(message, errno, code) {
        error = genericNodeError(message, { __proto__: null, errno, code });
        error.errno = errno;
        error.code = code;
      }

      const result = createHandleFn(() => {}, onError);
      const handle = result.handle;
      const writeState = result.writeState;
      const chunkSize = result.chunkSize;
      let outBuf = Buffer.allocUnsafe(chunkSize);
      let outOffset = 0;
      let pending = [];
      let pendingBytes = 0;

      function processSyncInput(input, flushFlag) {
        let inOff = 0;
        let availIn = TypedArrayPrototypeGetByteLength(input);
        let availOutBefore = chunkSize - outOffset;

        handle.writeSync(
          flushFlag,
          input,
          inOff,
          availIn,
          outBuf,
          outOffset,
          availOutBefore,
          writeState,
        );
        if (error) throw error;

        while (true) {
          const availOut = writeState[0];
          const availInAfter = writeState[1];
          const have = availOutBefore - availOut;
          const bufferExhausted = availOut === 0 ||
            outOffset + have >= chunkSize;

          if (have > 0) {
            if (bufferExhausted && outOffset === 0) {
              // Entire buffer filled - yield directly, no copy.
              ArrayPrototypePush(pending, outBuf);
            } else if (bufferExhausted) {
              // Tail filled, buffer being replaced - subarray is safe.
              ArrayPrototypePush(
                pending,
                outBuf.subarray(outOffset, outOffset + have),
              );
            } else {
              // Partial fill, buffer reused - must copy.
              ArrayPrototypePush(
                pending,
                TypedArrayPrototypeSlice(outBuf, outOffset, outOffset + have),
              );
            }
            pendingBytes += have;
            outOffset += have;
          }

          if (bufferExhausted) {
            outBuf = Buffer.allocUnsafe(chunkSize);
            outOffset = 0;
          }

          if (availOut === 0) {
            // Engine has more output - loop.
            const consumed = availIn - availInAfter;
            inOff += consumed;
            availIn = availInAfter;
            availOutBefore = chunkSize - outOffset;

            handle.writeSync(
              flushFlag,
              input,
              inOff,
              availIn,
              outBuf,
              outOffset,
              availOutBefore,
              writeState,
            );
            if (error) throw error;
            continue;
          }

          // All input consumed.
          break;
        }
      }

      function drainBatch() {
        if (pendingBytes <= BATCH_HWM) {
          const batch = pending;
          pending = [];
          pendingBytes = 0;
          return batch;
        }
        const batch = [];
        let batchBytes = 0;
        while (pending.length > 0 && batchBytes < BATCH_HWM) {
          const buf = ArrayPrototypeShift(pending);
          const len = TypedArrayPrototypeGetByteLength(buf);
          ArrayPrototypePush(batch, buf);
          batchBytes += len;
          pendingBytes -= len;
        }
        return batch;
      }

      try {
        for (const batch of source) {
          if (batch === null) {
            // Flush signal - finalize the engine.
            processSyncInput(Buffer.alloc(0), finishFlag);
            while (pending.length > 0) {
              yield drainBatch();
            }
            continue;
          }

          for (let i = 0; i < batch.length; i++) {
            processSyncInput(batch[i], processFlag);
          }

          if (pendingBytes >= BATCH_HWM) {
            while (pending.length > 0 && pendingBytes >= BATCH_HWM) {
              yield drainBatch();
            }
          }
          if (pending.length > 0) {
            yield drainBatch();
          }
        }
      } finally {
        handle.close();
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Async compression factories
// ---------------------------------------------------------------------------

const kNullPrototype = { __proto__: null };

function compressGzip(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransform(
    (cb, onErr) => createZlibHandle(GZIP, options, cb, onErr),
    Z_NO_FLUSH,
    Z_FINISH,
  );
}

function compressDeflate(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransform(
    (cb, onErr) => createZlibHandle(DEFLATE, options, cb, onErr),
    Z_NO_FLUSH,
    Z_FINISH,
  );
}

function compressBrotli(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransform(
    (cb, onErr) => createBrotliHandle(BROTLI_ENCODE, options, cb, onErr),
    BROTLI_OPERATION_PROCESS,
    BROTLI_OPERATION_FINISH,
  );
}

function compressZstd(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransform(
    (cb, onErr) => createZstdHandle(ZSTD_COMPRESS, options, cb, onErr),
    ZSTD_e_continue,
    ZSTD_e_end,
  );
}

// ---------------------------------------------------------------------------
// Decompression factories
// ---------------------------------------------------------------------------

function decompressGzip(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransform(
    (cb, onErr) => createZlibHandle(GUNZIP, options, cb, onErr),
    Z_NO_FLUSH,
    Z_FINISH,
  );
}

function decompressDeflate(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransform(
    (cb, onErr) => createZlibHandle(INFLATE, options, cb, onErr),
    Z_NO_FLUSH,
    Z_FINISH,
  );
}

function decompressBrotli(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransform(
    (cb, onErr) => createBrotliHandle(BROTLI_DECODE, options, cb, onErr),
    BROTLI_OPERATION_PROCESS,
    BROTLI_OPERATION_FINISH,
  );
}

function decompressZstd(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransform(
    (cb, onErr) => createZstdHandle(ZSTD_DECOMPRESS, options, cb, onErr),
    ZSTD_e_continue,
    ZSTD_e_end,
  );
}

// ---------------------------------------------------------------------------
// Sync compression factories
// ---------------------------------------------------------------------------

function compressGzipSync(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransformSync(
    (cb, onErr) => createZlibHandle(GZIP, options, cb, onErr),
    Z_NO_FLUSH,
    Z_FINISH,
  );
}

function compressDeflateSync(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransformSync(
    (cb, onErr) => createZlibHandle(DEFLATE, options, cb, onErr),
    Z_NO_FLUSH,
    Z_FINISH,
  );
}

function compressBrotliSync(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransformSync(
    (cb, onErr) => createBrotliHandle(BROTLI_ENCODE, options, cb, onErr),
    BROTLI_OPERATION_PROCESS,
    BROTLI_OPERATION_FINISH,
  );
}

function compressZstdSync(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransformSync(
    (cb, onErr) => createZstdHandle(ZSTD_COMPRESS, options, cb, onErr),
    ZSTD_e_continue,
    ZSTD_e_end,
  );
}

// ---------------------------------------------------------------------------
// Sync decompression factories
// ---------------------------------------------------------------------------

function decompressGzipSync(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransformSync(
    (cb, onErr) => createZlibHandle(GUNZIP, options, cb, onErr),
    Z_NO_FLUSH,
    Z_FINISH,
  );
}

function decompressDeflateSync(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransformSync(
    (cb, onErr) => createZlibHandle(INFLATE, options, cb, onErr),
    Z_NO_FLUSH,
    Z_FINISH,
  );
}

function decompressBrotliSync(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransformSync(
    (cb, onErr) => createBrotliHandle(BROTLI_DECODE, options, cb, onErr),
    BROTLI_OPERATION_PROCESS,
    BROTLI_OPERATION_FINISH,
  );
}

function decompressZstdSync(options = kNullPrototype) {
  validateObject(options, "options");
  return makeZlibTransformSync(
    (cb, onErr) => createZstdHandle(ZSTD_DECOMPRESS, options, cb, onErr),
    ZSTD_e_continue,
    ZSTD_e_end,
  );
}

return {
  compressBrotli,
  compressBrotliSync,
  compressDeflate,
  compressDeflateSync,
  compressGzip,
  compressGzipSync,
  compressZstd,
  compressZstdSync,
  decompressBrotli,
  decompressBrotliSync,
  decompressDeflate,
  decompressDeflateSync,
  decompressGzip,
  decompressGzipSync,
  decompressZstd,
  decompressZstdSync,
};
})();
