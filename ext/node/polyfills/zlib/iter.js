// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core } = __bootstrap;
const { Buffer } = core.loadExtScript("ext:deno_node/internal/buffer.mjs");
const {
  codes: {
    ERR_BROTLI_INVALID_PARAM,
    ERR_INVALID_ARG_TYPE,
    ERR_OUT_OF_RANGE,
    ERR_ZSTD_INVALID_PARAM,
  },
} = core.loadExtScript("ext:deno_node/internal/errors.ts");
const { emitExperimentalWarning } = core.loadExtScript(
  "ext:deno_node/internal/util.mjs",
);
const { kValidatedTransform } = core.loadExtScript(
  "ext:deno_node/internal/streams/iter/types.js",
);
const zlib = core.loadExtScript("ext:deno_node/zlib.js");
const { zlib: zlibConstants } = core.loadExtScript(
  "ext:deno_node/internal_binding/constants.ts",
);

emitExperimentalWarning("zlib/iter");

function validateOptions(options) {
  if (options !== undefined && (options === null || typeof options !== "object")) {
    throw new ERR_INVALID_ARG_TYPE("options", "Object", options);
  }
  return options ?? {};
}

function validateParams(options, maxParam, ErrorClass) {
  if (options.params === undefined) {
    return;
  }
  const params = options.params;
  if (params === null || typeof params !== "object") {
    throw new ERR_INVALID_ARG_TYPE("options.params", "Object", params);
  }
  for (const key of Object.keys(params)) {
    const numberKey = Number(key);
    if (!Number.isFinite(numberKey) || numberKey < 0 || numberKey > maxParam) {
      throw new ErrorClass(key);
    }
    const value = params[key];
    if (typeof value !== "number" && typeof value !== "boolean") {
      throw new ERR_INVALID_ARG_TYPE("options.params[key]", "number", value);
    }
  }
}

function validateBrotliOptions(options) {
  validateParams(options, zlibConstants.BROTLI_PARAM_NDIRECT, ERR_BROTLI_INVALID_PARAM);
}

function validateZstdOptions(options) {
  validateParams(options, zlibConstants.ZSTD_c_overlapLog, ERR_ZSTD_INVALID_PARAM);
  if (options.pledgedSrcSize !== undefined) {
    const pledgedSrcSize = options.pledgedSrcSize;
    if (typeof pledgedSrcSize !== "number") {
      throw new ERR_INVALID_ARG_TYPE(
        "options.pledgedSrcSize",
        "number",
        pledgedSrcSize,
      );
    }
    if (!Number.isInteger(pledgedSrcSize) || pledgedSrcSize < 0) {
      throw new ERR_OUT_OF_RANGE(
        "options.pledgedSrcSize",
        "an integer >= 0",
        pledgedSrcSize,
      );
    }
  }
}

function collectBatch(parts, batch) {
  if (batch === null) {
    return;
  }
  for (let i = 0; i < batch.length; i++) {
    parts.push(batch[i]);
  }
}

function collectInput(parts) {
  return parts.length === 0 ? Buffer.alloc(0) : Buffer.concat(parts);
}

function callAsync(method, input, options) {
  return new Promise((resolve, reject) => {
    try {
      method(input, options, (error, result) => {
        if (error) {
          if (
            method === zlib.brotliDecompress &&
            error.code === undefined &&
            typeof error.message === "string" &&
            error.message.includes("PADDING_2")
          ) {
            error.code = "ERR__ERROR_FORMAT_PADDING_2";
          }
          if (
            method === zlib.zstdDecompress &&
            error.code === undefined &&
            typeof error.message === "string"
          ) {
            error.code = "ZSTD_error_prefix_unknown";
          }
          reject(error);
        } else {
          resolve(result);
        }
      });
    } catch (error) {
      reject(error);
    }
  });
}

function exactBuffer(value) {
  const buffer = Buffer.alloc(value.length);
  buffer.set(value);
  return buffer;
}

function createAsyncTransform(method, options, validate) {
  options = validateOptions(options);
  const transform = {
    __proto__: null,
    async *transform(source, { signal } = {}) {
      validate?.(options);
      const parts = [];
      for await (const batch of source) {
        signal?.throwIfAborted();
        collectBatch(parts, batch);
      }
      signal?.throwIfAborted();
      const result = await callAsync(method, collectInput(parts), options);
      signal?.throwIfAborted();
      if (result.length > 0) {
        yield [exactBuffer(result)];
      }
    },
  };
  transform[kValidatedTransform] = true;
  return transform;
}

function createSyncTransform(method, options, validate) {
  options = validateOptions(options);
  return {
    __proto__: null,
    *transform(source) {
      validate?.(options);
      const parts = [];
      for (const batch of source) {
        collectBatch(parts, batch);
      }
      const result = method(collectInput(parts), options);
      if (result.length > 0) {
        yield [exactBuffer(result)];
      }
    },
  };
}

function compressGzip(options) {
  return createAsyncTransform(zlib.gzip, options);
}
function compressGzipSync(options) {
  return createSyncTransform(zlib.gzipSync, options);
}
function compressDeflate(options) {
  return createAsyncTransform(zlib.deflate, options);
}
function compressDeflateSync(options) {
  return createSyncTransform(zlib.deflateSync, options);
}
function compressBrotli(options) {
  return createAsyncTransform(zlib.brotliCompress, options, validateBrotliOptions);
}
function compressBrotliSync(options) {
  return createSyncTransform(zlib.brotliCompressSync, options, validateBrotliOptions);
}
function compressZstd(options) {
  return createAsyncTransform(zlib.zstdCompress, options, validateZstdOptions);
}
function compressZstdSync(options) {
  return createSyncTransform(zlib.zstdCompressSync, options, validateZstdOptions);
}
function decompressGzip(options) {
  return createAsyncTransform(zlib.gunzip, options);
}
function decompressGzipSync(options) {
  return createSyncTransform(zlib.gunzipSync, options);
}
function decompressDeflate(options) {
  return createAsyncTransform(zlib.inflate, options);
}
function decompressDeflateSync(options) {
  return createSyncTransform(zlib.inflateSync, options);
}
function decompressBrotli(options) {
  return createAsyncTransform(zlib.brotliDecompress, options);
}
function decompressBrotliSync(options) {
  return createSyncTransform(zlib.brotliDecompressSync, options);
}
function decompressZstd(options) {
  return createAsyncTransform(zlib.zstdDecompress, options);
}
function decompressZstdSync(options) {
  return createSyncTransform(zlib.zstdDecompressSync, options);
}

return {
  compressGzip,
  compressGzipSync,
  compressDeflate,
  compressDeflateSync,
  compressBrotli,
  compressBrotliSync,
  compressZstd,
  compressZstdSync,
  decompressGzip,
  decompressGzipSync,
  decompressDeflate,
  decompressDeflateSync,
  decompressBrotli,
  decompressBrotliSync,
  decompressZstd,
  decompressZstdSync,
};
})();
