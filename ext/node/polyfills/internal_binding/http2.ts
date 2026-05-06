// Copyright 2018-2026 the Deno authors. MIT license.

import { op_http2_error_string } from "ext:core/ops";
import {
  Http2Session,
  Http2Stream,
  constants,
} from "node:http2";
import {
  optionsBuffer,
  sessionState,
  settingsBuffer,
  streamState,
} from "ext:deno_node/internal/http2/util.ts";

function nghttp2ErrorString(code: number): string {
  return op_http2_error_string(code);
}

export {
  constants,
  Http2Session,
  Http2Stream,
  nghttp2ErrorString,
  optionsBuffer,
  sessionState,
  settingsBuffer,
  streamState,
};
