// Copyright 2018-2026 the Deno authors. MIT license.
// @deno-types="./_readline.d.ts"

import {
  clearLine,
  clearScreenDown,
  createInterface,
  cursorTo,
  emitKeypressEvents,
  Interface,
  moveCursor,
  promises,
} from "ext:deno_node/_readline.mjs";
import { internals } from "ext:core/mod.js";

const originalDefaultExport = {
  Interface,
  clearLine,
  clearScreenDown,
  createInterface,
  cursorTo,
  emitKeypressEvents,
  moveCursor,
  promises,
};
const processGetBuiltinModule = globalThis.process?.getBuiltinModule;
const defaultExport =
  (!internals.__loadingDenoNodeReadlineDefault &&
      typeof processGetBuiltinModule === "function"
    ? processGetBuiltinModule("readline")
    : undefined) ?? originalDefaultExport;

export {
  clearLine,
  clearScreenDown,
  createInterface,
  cursorTo,
  emitKeypressEvents,
  Interface,
  moveCursor,
  promises,
};

export default defaultExport;
