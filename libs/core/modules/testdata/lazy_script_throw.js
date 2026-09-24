// Copyright 2018-2026 the Deno authors. MIT license.
(function () {
const err = new RangeError("lazy script failure");
err.code = "ERR_TEST_LAZY_SCRIPT";
globalThis.lazyScriptError = err;
throw err;
})();
