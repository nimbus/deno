// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

import { primordials } from "ext:core/mod.js";
const { queueMicrotask, SymbolDispose } = primordials;
import { validateAbortSignal, validateFunction } from "../validators.mjs";
import { codes } from "../errors.ts";
import { kResistStopImmediatePropagation } from "ext:deno_web/02_event.js";
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
    queueMicrotask(() => listener({ target: signal }));
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

export default { addAbortListener };

export { addAbortListener };
