// Copyright 2018-2026 the Deno authors. MIT license.
(function () {
const err = new RangeError("synthetic backing failure");
err.code = "ERR_TEST_SYNTHETIC";
globalThis.syntheticError = err;
throw err;
})();
