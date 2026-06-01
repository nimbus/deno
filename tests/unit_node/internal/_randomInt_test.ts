// Copyright 2018-2026 the Deno authors. MIT license.
import { randomInt } from "node:crypto";
import { assert, assertThrows } from "@std/assert";

const between = (x: number, min: number, max: number) => x >= min && x < max;

Deno.test("[node/crypto.randomInt] No Params", () => {
  assertThrows(() => randomInt(undefined as unknown as number));
});

Deno.test("[node/crypto.randomInt] One Param: Max", () => {
  assert(between(randomInt(55), 0, 55));
});

Deno.test("[node/crypto.randomInt] Two Params: Max and Min", () => {
  assert(between(randomInt(40, 120), 40, 120));
});

Deno.test("[node/crypto.randomInt] Max and Callback", async () => {
  await new Promise<void>((resolve) => {
    randomInt(3, (_err, val) => {
      assert(between(val as number, 0, 3));
      resolve();
    });
  });
});

Deno.test("[node/crypto.randomInt] Min, Max and Callback", async () => {
  await new Promise<void>((resolve) => {
    randomInt(3, 5, (_err, val) => {
      assert(between(val as number, 3, 5));
      resolve();
    });
  });
});

Deno.test("[node/crypto.randomInt] Min is bigger than Max", () => {
  assertThrows(() => randomInt(45, 34));
});
