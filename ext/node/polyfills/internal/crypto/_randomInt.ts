// Copyright 2018-2026 the Deno authors. MIT license.

import { primordials } from "ext:core/mod.js";
import { Buffer } from "node:buffer";
import process from "node:process";
import {
  ERR_INVALID_ARG_TYPE,
  ERR_OUT_OF_RANGE,
} from "ext:deno_node/internal/errors.ts";
import randomFill, {
  randomFillSync,
} from "ext:deno_node/internal/crypto/_randomFill.mjs";
import { validateFunction } from "ext:deno_node/internal/validators.mjs";
const {
  ArrayPrototypePush,
  ArrayPrototypeSplice,
  ArrayPrototypeForEach,
  MathCeil,
  MathFloor,
  NumberIsSafeInteger,
} = primordials;

// Largest integer that can be expressed in 6 bytes, mirrors Node's RAND_MAX
// in lib/internal/crypto/random.js.
const RAND_MAX = 0xFFFF_FFFF_FFFF;
const randomCache = Buffer.allocUnsafe(6 * 1024);
let randomCacheOffset = randomCache.length;
let asyncCacheFillInProgress = false;
const asyncCachePendingTasks: Array<{
  min: number;
  max: number;
  callback: (err: Error | null, n?: number) => void;
}> = [];

export default function randomInt(max: number): number;
export default function randomInt(min: number, max: number): number;
export default function randomInt(
  max: number,
  cb: (err: Error | null, n?: number) => void,
): void;
export default function randomInt(
  min: number,
  max: number,
  cb: (err: Error | null, n?: number) => void,
): void;

// Generates an integer in [min, max) range where min is inclusive and max is
// exclusive. Matches Node's lib/internal/crypto/random.js randomInt().
export default function randomInt(
  min: number,
  max?: ((err: Error | null, n?: number) => void) | number,
  callback?: (err: Error | null, n?: number) => void,
): number | void {
  // Detect optional min syntax
  // randomInt(max)
  // randomInt(max, callback)
  const minNotSpecified = typeof max === "undefined" ||
    typeof max === "function";

  if (minNotSpecified) {
    callback = max as (err: Error | null, n?: number) => void;
    max = min;
    min = 0;
  }

  const isSync = typeof callback === "undefined";
  if (!isSync) {
    validateFunction(callback, "callback");
  }
  if (!NumberIsSafeInteger(min)) {
    throw new ERR_INVALID_ARG_TYPE("min", "a safe integer", min);
  }
  if (!NumberIsSafeInteger(max)) {
    throw new ERR_INVALID_ARG_TYPE("max", "a safe integer", max);
  }
  if ((max as number) <= min) {
    throw new ERR_OUT_OF_RANGE(
      "max",
      `greater than the value of "min" (${min})`,
      max,
    );
  }

  const range = (max as number) - min;
  if (!(range <= RAND_MAX)) {
    throw new ERR_OUT_OF_RANGE(
      `max${minNotSpecified ? "" : " - min"}`,
      `<= ${RAND_MAX}`,
      range,
    );
  }

  min = MathCeil(min);
  const flooredMax = MathFloor(max as number);
  const randLimit = RAND_MAX - (RAND_MAX % range);

  while (isSync || randomCacheOffset < randomCache.length) {
    if (randomCacheOffset === randomCache.length) {
      randomFillSync(randomCache);
      randomCacheOffset = 0;
    }

    const x = randomCache.readUIntBE(randomCacheOffset, 6);
    randomCacheOffset += 6;

    if (x < randLimit) {
      const result = (x % range) + min;
      if (isSync) {
        return result;
      }
      process.nextTick(callback!, undefined, result);
      return;
    }
  }

  ArrayPrototypePush(asyncCachePendingTasks, {
    min,
    max: flooredMax,
    callback: callback!,
  });
  asyncRefillRandomIntCache();
}

function asyncRefillRandomIntCache() {
  if (asyncCacheFillInProgress) {
    return;
  }

  asyncCacheFillInProgress = true;
  randomFill(randomCache, (err) => {
    asyncCacheFillInProgress = false;
    const tasks = ArrayPrototypeSplice(asyncCachePendingTasks, 0);
    if (!err) {
      randomCacheOffset = 0;
    }
    ArrayPrototypeForEach(tasks, (task) => {
      if (err) {
        task.callback(err);
        return;
      }
      randomInt(task.min, task.max, task.callback);
    });
  });
}
