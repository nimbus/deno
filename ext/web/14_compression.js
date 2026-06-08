// Copyright 2018-2026 the Deno authors. MIT license.

// @ts-check
/// <reference path="../../core/lib.deno_core.d.ts" />
/// <reference path="./internal.d.ts" />
/// <reference path="../../cli/tsc/dts/lib.deno_web.d.ts" />

(function () {
const { core, primordials } = __bootstrap;
const {
  op_compression_finish,
  op_compression_new,
  op_compression_write,
} = core.ops;
const {
  SymbolFor,
  ObjectPrototypeIsPrototypeOf,
  TypedArrayPrototypeGetByteLength,
  TypeError,
} = primordials;

const webidl = core.loadExtScript("ext:deno_webidl/00_webidl.js");
const { createFilteredInspectProxy } = core.loadExtScript(
  "ext:deno_web/01_console.js",
);
const { TransformStream } = core.loadExtScript("ext:deno_web/06_streams.js");

function withCode(error, code) {
  if (error && error.code === undefined) {
    error.code = code;
  }
  return error;
}

function convertCompressionChunk(chunk, prefix) {
  if (typeof chunk === "string") {
    return core.encode(chunk);
  }
  if (chunk === null) {
    throw withCode(
      new TypeError("May not write null values to stream"),
      "ERR_STREAM_NULL_VALUES",
    );
  }
  try {
    return webidl.converters.BufferSource(chunk, prefix, "chunk");
  } catch (error) {
    throw withCode(error, "ERR_INVALID_ARG_TYPE");
  }
}

webidl.converters.CompressionFormat = webidl.createEnumConverter(
  "CompressionFormat",
  [
    "deflate",
    "deflate-raw",
    "gzip",
    "brotli",
  ],
);

class CompressionStream {
  #transform;

  constructor(format) {
    const prefix = "Failed to construct 'CompressionStream'";
    webidl.requiredArguments(arguments.length, 1, prefix);
    format = webidl.converters.CompressionFormat(format, prefix, "Argument 1");

    const rid = op_compression_new(format, false);

    this.#transform = new TransformStream({
      transform(chunk, controller) {
        chunk = convertCompressionChunk(chunk, prefix);
        const output = op_compression_write(
          rid,
          chunk,
        );
        maybeEnqueue(controller, output);
      },
      flush(controller) {
        const output = op_compression_finish(rid, true);
        maybeEnqueue(controller, output);
      },
      cancel: (_reason) => {
        op_compression_finish(rid, false);
      },
    });

    this[webidl.brand] = webidl.brand;
  }

  get readable() {
    webidl.assertBranded(this, CompressionStreamPrototype);
    return this.#transform.readable;
  }

  get writable() {
    webidl.assertBranded(this, CompressionStreamPrototype);
    return this.#transform.writable;
  }

  [SymbolFor("Deno.privateCustomInspect")](inspect, inspectOptions) {
    return inspect(
      createFilteredInspectProxy({
        object: this,
        evaluate: ObjectPrototypeIsPrototypeOf(
          CompressionStreamPrototype,
          this,
        ),
        keys: [
          "readable",
          "writable",
        ],
      }),
      inspectOptions,
    );
  }
}

webidl.configureInterface(CompressionStream);
const CompressionStreamPrototype = CompressionStream.prototype;

class DecompressionStream {
  #transform;

  constructor(format) {
    const prefix = "Failed to construct 'DecompressionStream'";
    webidl.requiredArguments(arguments.length, 1, prefix);
    format = webidl.converters.CompressionFormat(format, prefix, "Argument 1");

    const rid = op_compression_new(format, true);

    this.#transform = new TransformStream({
      transform(chunk, controller) {
        chunk = convertCompressionChunk(chunk, prefix);
        const output = op_compression_write(
          rid,
          chunk,
        );
        maybeEnqueue(controller, output);
      },
      flush(controller) {
        const output = op_compression_finish(rid, true);
        maybeEnqueue(controller, output);
      },
      cancel: (_reason) => {
        op_compression_finish(rid, false);
      },
    });

    this[webidl.brand] = webidl.brand;
  }

  get readable() {
    webidl.assertBranded(this, DecompressionStreamPrototype);
    return this.#transform.readable;
  }

  get writable() {
    webidl.assertBranded(this, DecompressionStreamPrototype);
    return this.#transform.writable;
  }

  [SymbolFor("Deno.privateCustomInspect")](inspect, inspectOptions) {
    return inspect(
      createFilteredInspectProxy({
        object: this,
        evaluate: ObjectPrototypeIsPrototypeOf(
          DecompressionStreamPrototype,
          this,
        ),
        keys: [
          "readable",
          "writable",
        ],
      }),
      inspectOptions,
    );
  }
}

function maybeEnqueue(controller, output) {
  if (output && TypedArrayPrototypeGetByteLength(output) > 0) {
    controller.enqueue(output);
  }
}

webidl.configureInterface(DecompressionStream);
const DecompressionStreamPrototype = DecompressionStream.prototype;

return { CompressionStream, DecompressionStream };
})();
