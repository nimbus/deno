// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.
// Ported from Node.js v26.10.0 lib/zlib/iter.js.

(function () {
const { core, primordials } = __bootstrap;

// Public entry point for the iterable compression/decompression API.
// Usage: require('zlib/iter') or require('node:zlib/iter')
// Requires: --experimental-stream-iter

const { emitExperimentalWarning } = core.loadExtScript(
  "ext:deno_node/internal/util.mjs",
);
emitExperimentalWarning("zlib/iter");

const {
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
} = core.loadExtScript("ext:deno_node/internal/streams/iter/transform.js");

return {
  // Compression transforms (async)
  compressGzip,
  compressDeflate,
  compressBrotli,
  compressZstd,

  // Compression transforms (sync)
  compressGzipSync,
  compressDeflateSync,
  compressBrotliSync,
  compressZstdSync,

  // Decompression transforms (async)
  decompressGzip,
  decompressDeflate,
  decompressBrotli,
  decompressZstd,

  // Decompression transforms (sync)
  decompressGzipSync,
  decompressDeflateSync,
  decompressBrotliSync,
  decompressZstdSync,
};
})();
