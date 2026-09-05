// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

(function () {
const { internals, primordials } = __bootstrap;
const { Symbol } = primordials;

const kHandle = Symbol("kHandle");
const kKeyObject = internals.kKeyObject === undefined
  ? Symbol("kKeyObject")
  : internals.kKeyObject;

internals.kKeyObject = kKeyObject;

return { kHandle, kKeyObject };
})();
