// Copyright 2018-2026 the Deno authors. MIT license.

import {
  ERR_NOT_IN_SINGLE_EXECUTABLE_APPLICATION,
} from "ext:deno_node/internal/errors.ts";

function throwNotInSea(): never {
  throw new ERR_NOT_IN_SINGLE_EXECUTABLE_APPLICATION();
}

export function isSea(): boolean {
  return false;
}

export function getAsset(): never {
  return throwNotInSea();
}

export function getRawAsset(): never {
  return throwNotInSea();
}

export function getAssetAsBlob(): never {
  return throwNotInSea();
}

export function getAssetKeys(): never {
  return throwNotInSea();
}

export default {
  isSea,
  getAsset,
  getRawAsset,
  getAssetAsBlob,
  getAssetKeys,
};
