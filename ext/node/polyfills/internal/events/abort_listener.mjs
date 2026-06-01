// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.
(function () {
const { core, primordials } = __bootstrap;
const { queueMicrotask, SymbolDispose } = primordials;
const { validateAbortSignal, validateFunction } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);
const { kResistStopImmediatePropagation } = core.loadExtScript(
  "ext:deno_web/02_event.js",
);
const { codes } = core.loadExtScript("ext:deno_node/internal/errors.ts");
const { ERR_INVALID_ARG_TYPE } = codes;

/**
 * @param {AbortSignal} signal
 * @param {EventListener} listener
 * @returns {Disposable}
 */
function addAbortListener(signal, listener) {
  if (signal === undefined) {
    throw new ERR_INVALID_ARG_TYPE("signal", "AbortSignal", signal);
  }
  validateAbortSignal(signal, "signal");
  validateFunction(listener, "listener");

  let removeEventListener;
  if (signal.aborted) {
    queueMicrotask(() => listener());
  } else {
    signal.addEventListener("abort", listener, {
      __proto__: null,
      once: true,
      [kResistStopImmediatePropagation]: true,
    });
    removeEventListener = () => {
      signal.removeEventListener("abort", listener);
    };
  }
  return {
    __proto__: null,
    [SymbolDispose]() {
      removeEventListener?.();
    },
  };
}

const _defaultExport = { addAbortListener };

return {
  addAbortListener,
  default: _defaultExport,
};
})();
