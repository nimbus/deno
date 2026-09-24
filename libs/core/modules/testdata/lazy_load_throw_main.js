// Copyright 2018-2026 the Deno authors. MIT license.
function assertOriginal(caught, expected, message) {
  if (caught !== expected) {
    throw new Error(`expected the original error, got ${caught?.message}`);
  }
  if (!(caught instanceof RangeError) || caught.message !== message) {
    throw new Error(`unexpected error: ${caught}`);
  }
}

// Each load of a lazy ES module that throws fails with the original error,
// through the op and through a dynamic import.
let caught;
try {
  Deno.core.createLazyLoader("custom:lazy_throw")();
} catch (e) {
  caught = e;
}
assertOriginal(caught, globalThis.lazyModuleError, "lazy module failure");
caught = await import("custom:lazy_throw").then(() => null, (e) => e);
assertOriginal(caught, globalThis.lazyModuleError, "lazy module failure");

// A dynamic import of a `synthetic_esm` module whose backing script throws
// rejects with the original error.
caught = await import("custom:synthetic_throw").then(() => null, (e) => e);
assertOriginal(
  caught,
  globalThis.syntheticError,
  "synthetic backing failure",
);
