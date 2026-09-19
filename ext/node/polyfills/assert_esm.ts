// Copyright 2018-2026 the Deno authors. MIT license.
import { core } from "ext:core/mod.js";
const mod = core.loadExtScript("ext:deno_node/assert.ts");

export const {
  AssertionError,
  deepEqual,
  deepStrictEqual,
  doesNotMatch,
  doesNotReject,
  doesNotThrow,
  equal,
  fail,
  ifError,
  match,
  notDeepEqual,
  notDeepStrictEqual,
  notEqual,
  notStrictEqual,
  ok,
  rejects,
  strict,
  strictEqual,
  throws,
} = mod;
// The embedder can change the target after a startup snapshot.
export let Assert;
export let CallTracker;
export let partialDeepStrictEqual;
mod.bindVersionedExports((exports) => {
  Assert = exports.Assert;
  CallTracker = exports.CallTracker;
  partialDeepStrictEqual = exports.partialDeepStrictEqual;
});

export default mod.default;
