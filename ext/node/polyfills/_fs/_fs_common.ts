// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const { ReflectApply } = primordials;
const { validateFunction } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);

const lazyFsUtils = core.createLazyLoader(
  "ext:deno_node/internal/fs/utils.mjs",
);

function isFileOptions(
  fileOptions,
) {
  if (!fileOptions) return false;

  return (
    fileOptions.encoding != undefined ||
    fileOptions.flag != undefined ||
    fileOptions.signal != undefined ||
    fileOptions.mode != undefined
  );
}

function getValidatedEncoding(
  optOrCallback,
) {
  const encoding = getEncoding(optOrCallback);
  if (encoding) {
    lazyFsUtils().assertEncoding(encoding);
  }
  return encoding;
}

function getEncoding(
  optOrCallback,
) {
  if (!optOrCallback || typeof optOrCallback === "function") {
    return null;
  }

  const encoding = typeof optOrCallback === "string"
    ? optOrCallback
    : optOrCallback.encoding;
  if (!encoding) return null;
  return encoding;
}

function getSignal(optOrCallback) {
  if (!optOrCallback || typeof optOrCallback === "function") {
    return null;
  }

  const signal = typeof optOrCallback === "object" && optOrCallback.signal
    ? optOrCallback.signal
    : null;

  return signal;
}

const __reexport = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);
const isFd = __reexport.isUint32;

function maybeCallback(cb) {
  validateFunction(cb, "cb");

  return wrapCallbackForDomain(cb, false);
}

// Ensure that callbacks run in the global context. Only use this function
// for callbacks that are passed to the binding layer, callbacks that are
// invoked from JS already run in the proper scope.
function makeCallback(cb) {
  validateFunction(cb, "cb");
  cb = wrapCallbackForDomain(cb, true);
  // Callbacks run with `this` = undefined, matching Node.js ESM strict-mode
  // behavior (the original code was an ESM arrow function capturing `this`
  // from makeCallback's call site, which is undefined in strict mode).
  return (...args) => ReflectApply(cb, undefined, args);
}

function wrapCallbackForDomain(cb, forceUndefinedThis) {
  const domain = globalThis.process?.domain;
  if (domain === null || domain === undefined) {
    return cb;
  }

  return function (...args) {
    domain.enter();
    let threw = true;
    try {
      const ret = ReflectApply(
        cb,
        forceUndefinedThis ? undefined : this,
        args,
      );
      threw = false;
      return ret;
    } finally {
      // Exit the domain only on the success path. When the callback throws,
      // leave the domain on the stack so that the runtime's uncaught/
      // unhandled-rejection dispatch still observes the live
      // process.setUncaughtExceptionCaptureCallback hook and routes the error
      // to this domain (test-domain-implicit-fs). domainUncaughtExceptionHandler
      // removes the errored domain from the stack itself, mirroring Node's
      // MakeCallback, which does NOT run domain.exit() when the callback throws.
      // Running domain.exit() here would clear the capture callback before the
      // (asynchronously dispatched) error is delivered, so it would escape the
      // domain.
      if (!threw) {
        domain.exit();
      }
    }
  };
}

return {
  isFileOptions,
  getValidatedEncoding,
  getEncoding,
  getSignal,
  isFd,
  maybeCallback,
  makeCallback,
};
})();
