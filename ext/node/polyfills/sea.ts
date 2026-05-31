// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
function notInSeaError() {
  const err = new Error("Not in single executable application");
  (err as any).code = "ERR_NOT_IN_SINGLE_EXECUTABLE_APPLICATION";
  return err;
}

function throwNotInSea() {
  throw notInSeaError();
}

function isSea() {
  return false;
}

function getAsset() {
  throwNotInSea();
}

function getAssetAsBlob() {
  throwNotInSea();
}

function getAssetKeys() {
  throwNotInSea();
}

function getRawAsset() {
  throwNotInSea();
}

const sea = {
  getAsset,
  getAssetAsBlob,
  getAssetKeys,
  getRawAsset,
  isSea,
};

return {
  default: sea,
  getAsset,
  getAssetAsBlob,
  getAssetKeys,
  getRawAsset,
  isSea,
};
})();
