// Copyright 2018-2026 the Deno authors. MIT license.
// @deno-types="./_events.d.ts"

import { core } from "ext:core/mod.js";
const mod = core.loadExtScript("ext:deno_node/_events.mjs");
const syncBuiltinESMExportsCallbacksSymbol = Symbol.for(
  "deno.node.syncBuiltinESMExports.callbacks",
);
type SyncBuiltinESMExportsCallbackGlobal = {
  [key: symbol]: Set<() => void> | undefined;
};
const syncBuiltinESMExportsCallbacks =
  (globalThis as unknown as SyncBuiltinESMExportsCallbackGlobal)[
    syncBuiltinESMExportsCallbacksSymbol
  ] ??= new Set<() => void>();

export let defaultMaxListeners = mod.default.defaultMaxListeners;

function syncEventsBuiltinESMExports() {
  defaultMaxListeners = mod.default.defaultMaxListeners;
}

syncBuiltinESMExportsCallbacks.add(syncEventsBuiltinESMExports);

export const {
  addAbortListener,
  captureRejectionSymbol,
  errorMonitor,
  EventEmitter,
  EventEmitterAsyncResource,
  getEventListeners,
  getMaxListeners,
  listenerCount,
  on,
  once,
  setMaxListeners,
} = mod;

export default mod.default;
