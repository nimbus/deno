// Copyright 2018-2026 the Deno authors. MIT license.

// This file is here because to break a circular dependency between streams and
// crypto.

(function () {
const { core, primordials } = __bootstrap;
const { Symbol } = primordials;
const { CryptoKey } = core.ops;

const kKeyType = Symbol("kKeyType");

function isKeyObject(obj) {
  return (
    obj != null && obj[kKeyType] !== undefined
  );
}

function isCryptoKey(obj) {
  return CryptoKey.isKey(obj);
}

return { kKeyType, isKeyObject, isCryptoKey };
})();
