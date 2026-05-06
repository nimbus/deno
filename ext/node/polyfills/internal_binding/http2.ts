// Copyright 2018-2026 the Deno authors. MIT license.

import { op_http2_error_string } from "ext:core/ops";
import { core } from "ext:core/mod.js";

const lazyLoadHttp2 = core.createLazyLoader<typeof import("node:http2")>(
  "node:http2",
);
const lazyLoadHttp2Util = core.createLazyLoader<
  typeof import("ext:deno_node/internal/http2/util.ts")
>("ext:deno_node/internal/http2/util.ts");

export function createHttp2Binding() {
  return {
    get constants() {
      return lazyLoadHttp2().constants;
    },
    get Http2Session() {
      return lazyLoadHttp2().Http2Session;
    },
    get Http2Stream() {
      return lazyLoadHttp2().Http2Stream;
    },
    nghttp2ErrorString(code: number): string {
      return op_http2_error_string(code);
    },
    get optionsBuffer() {
      return lazyLoadHttp2Util().optionsBuffer;
    },
    get sessionState() {
      return lazyLoadHttp2Util().sessionState;
    },
    get settingsBuffer() {
      return lazyLoadHttp2Util().settingsBuffer;
    },
    get streamState() {
      return lazyLoadHttp2Util().streamState;
    },
  };
}
