// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and other Node contributors. All rights reserved.
// MIT license.
//
// Minimal JS-backed port of Node's internal js_stream binding.

// TODO(petamoriken): enable prefer-primordials for node polyfills
// deno-lint-ignore-file prefer-primordials

import {
  AsyncWrap,
  providerType,
} from "ext:deno_node/internal_binding/async_wrap.ts";
import {
  kArrayBufferOffset,
  kBytesWritten,
  kLastWriteWasAsync,
  kReadBytesOrError,
  streamBaseState,
} from "ext:deno_node/internal_binding/stream_wrap.ts";
import { codeMap } from "ext:deno_node/internal_binding/uv.ts";
import { Buffer } from "node:buffer";

const UV_EOF = codeMap.get("EOF")!;
const HOST_OBJECT_MARKER = "__node_internal_js_stream_host_object__";

type WriteRequest = {
  handle?: JSStream;
  oncomplete?: (status?: number) => void;
};

type ShutdownRequest = {
  handle?: JSStream;
  oncomplete?: (status?: number) => void;
};

type OnRead = (chunk?: Uint8Array | ArrayBuffer) => void;
type OnWrite = (req: WriteRequest, bufs: Uint8Array[]) => number | void;
type OnShutdown = (req: ShutdownRequest) => number | void;

function normalizeWriteBuffers(chunks: unknown[], allBuffers: boolean) {
  if (allBuffers) {
    return chunks.map((chunk) => {
      if (typeof chunk === "string") {
        return Buffer.from(chunk);
      }
      return Buffer.from(chunk as Uint8Array);
    });
  }

  const bufs: Uint8Array[] = [];
  for (let i = 0; i < chunks.length; i += 2) {
    const chunk = chunks[i];
    const encoding = chunks[i + 1];
    if (typeof chunk === "string") {
      bufs.push(Buffer.from(chunk, encoding as BufferEncoding));
    } else {
      bufs.push(Buffer.from(chunk as Uint8Array));
    }
  }
  return bufs;
}

export class JSStream extends AsyncWrap {
  onread?: OnRead;
  onreadstart?: () => number;
  onreadstop?: () => number;
  onwrite?: OnWrite;
  onshutdown?: OnShutdown;

  #closing = false;

  constructor() {
    super(providerType.JSSTREAM);
    Object.defineProperty(this, "_externalStream", {
      value: undefined,
      configurable: true,
      enumerable: false,
      writable: false,
    });
    Object.defineProperty(this, HOST_OBJECT_MARKER, {
      value: true,
      configurable: true,
      enumerable: false,
      writable: false,
    });
  }

  isClosing() {
    return this.#closing;
  }

  close(cb?: () => void) {
    this.#closing = true;
    cb?.();
  }

  readStart() {
    return this.onreadstart?.() ?? 0;
  }

  readStop() {
    return this.onreadstop?.() ?? 0;
  }

  shutdown(req: ShutdownRequest) {
    req.handle = this;
    if (typeof this.onshutdown !== "function") {
      return 1;
    }
    return this.onshutdown(req) ?? 0;
  }

  writeBuffer(req: WriteRequest, data: Uint8Array) {
    req.handle = this;
    streamBaseState[kBytesWritten] = data.byteLength;
    if (typeof this.onwrite === "function") {
      streamBaseState[kLastWriteWasAsync] = 1;
      return this.onwrite(req, [data]) ?? 0;
    }
    streamBaseState[kLastWriteWasAsync] = 0;
    return 0;
  }

  writev(req: WriteRequest, chunks: unknown[], allBuffers: boolean) {
    req.handle = this;
    const bufs = normalizeWriteBuffers(chunks, allBuffers);
    streamBaseState[kBytesWritten] = bufs.reduce(
      (total, buf) => total + buf.byteLength,
      0,
    );
    if (typeof this.onwrite === "function") {
      streamBaseState[kLastWriteWasAsync] = 1;
      return this.onwrite(req, bufs) ?? 0;
    }
    streamBaseState[kLastWriteWasAsync] = 0;
    return 0;
  }

  writeAsciiString(req: WriteRequest, data: string) {
    return this.writeBuffer(req, Buffer.from(data, "ascii"));
  }

  writeUtf8String(req: WriteRequest, data: string) {
    return this.writeBuffer(req, Buffer.from(data, "utf8"));
  }

  writeLatin1String(req: WriteRequest, data: string) {
    return this.writeBuffer(req, Buffer.from(data, "latin1"));
  }

  writeUcs2String(req: WriteRequest, data: string) {
    return this.writeBuffer(req, Buffer.from(data, "utf16le"));
  }

  finishWrite(req: WriteRequest, status = 0) {
    req.oncomplete?.(status);
  }

  finishShutdown(req: ShutdownRequest, status = 0) {
    req.oncomplete?.(status);
  }

  readBuffer(buffer: Uint8Array) {
    streamBaseState[kReadBytesOrError] = buffer.byteLength;
    streamBaseState[kArrayBufferOffset] = buffer.byteOffset;
    this.onread?.(buffer);
  }

  emitEOF() {
    streamBaseState[kReadBytesOrError] = UV_EOF;
    this.onread?.();
  }

  toString() {
    return "JSStream {}";
  }
}

JSStream.prototype.isStreamBase = true;

export default {
  JSStream,
};
