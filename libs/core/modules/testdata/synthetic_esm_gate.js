// Copyright 2018-2026 the Deno authors. MIT license.
(function () {
globalThis.gateCalls = [];
return function gate(specifier) {
  globalThis.gateCalls.push(specifier);
  if (specifier === "custom:blocked") {
    const err = new Error(`blocked ${specifier}`);
    err.code = "ERR_TEST_BLOCKED";
    throw err;
  }
};
})();
