// Copyright 2018-2026 the Deno authors. MIT license.
const err = new RangeError("lazy module failure");
err.code = "ERR_TEST_LAZY_MODULE";
globalThis.lazyModuleError = err;
throw err;
