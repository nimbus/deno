// Copyright 2018-2026 the Deno authors. MIT license.
for (let i = 0; i < 2; i++) {
  const err = await import("custom:blocked").then(() => null, (e) => e);
  if (!(err instanceof Error) || err.code !== "ERR_TEST_BLOCKED") {
    throw new Error(`expected the gate error, got ${err}`);
  }
  if (err.message !== "blocked custom:blocked") {
    throw new Error(`unexpected message: ${err.message}`);
  }
}
const allowed = await import("custom:allowed");
if (allowed.value !== 42) {
  throw new Error(`expected 42, got ${allowed.value}`);
}
const calls = globalThis.gateCalls.join(",");
if (calls !== "custom:blocked,custom:blocked,custom:allowed") {
  throw new Error(`unexpected gate calls: ${calls}`);
}
