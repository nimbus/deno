// Copyright 2018-2026 the Deno authors. MIT license.
import * as assert from "node:assert";
import * as strictAssert from "node:assert/strict";

Deno.test("[node/assert] .throws() compares Error instance", () => {
  assert.throws(
    () => {
      throw new Error("FAIL");
    },
    Error,
  );

  assert.throws(
    () => {
      throw new TypeError("FAIL");
    },
    TypeError,
  );
});

Deno.test("[node/assert] deepStrictEqual(0, -0)", () => {
  assert.throws(
    () => {
      assert.deepStrictEqual(0, -0);
    },
  );
});

Deno.test("[node/assert] formats multibyte source expressions", () => {
  const 汉汉: typeof assert = assert;
  assert.throws(
    () => {
      汉汉.ok(false);
    },
    /汉汉\.ok\(false\)/,
  );
});

Deno.test("[node/assert] CallTracker correctly exported", () => {
  assert.strictEqual(typeof assert.CallTracker, "function");
  assert.strictEqual(typeof assert.default.CallTracker, "function");
  assert.strictEqual(assert.CallTracker, assert.default.CallTracker);
});

Deno.test("[node/assert] error message from strictEqual should be the same as AssertionError message", () => {
  const { message } = new assert.AssertionError({
    actual: 1,
    expected: 2,
    operator: "strictEqual",
  });

  assert.throws(
    () => {
      assert.strictEqual(1, 2);
    },
    { message },
  );
});

Deno.test("[node/assert] deepStrictEqual throws for different Number objects", () => {
  // Test case from issue #31172
  assert.throws(
    () => {
      assert.deepStrictEqual(new Number(1), new Number(2));
    },
    assert.AssertionError,
  );
});

Deno.test("[node/assert] deepStrictEqual passes for equal Number objects", () => {
  // Equal Number objects should pass
  assert.doesNotThrow(() => {
    assert.deepStrictEqual(new Number(1), new Number(1));
  });
});

Deno.test("[node/assert] throws with 2 parameters", () => {
  assert.throws(
    () => {
      throw new Error("test error");
    },
    "custom message",
  );
});

Deno.test("[node/assert] throws with 3 parameters", () => {
  assert.throws(
    () => {
      throw new TypeError("test error");
    },
    TypeError,
    "custom message",
  );
});

Deno.test("[node/assert] doesNotThrow with 2 parameters", () => {
  assert.doesNotThrow(
    () => {},
    "custom message",
  );
});

Deno.test("[node/assert] doesNotThrow with 3 parameters", () => {
  assert.doesNotThrow(
    () => {},
    TypeError,
    "custom message",
  );
});

Deno.test("[node/assert] rejects with 2 parameters", async () => {
  await assert.rejects(
    // deno-lint-ignore require-await
    async () => {
      throw new Error("async error");
    },
    "custom message",
  );
});

Deno.test("[node/assert] rejects with 3 parameters", async () => {
  await assert.rejects(
    // deno-lint-ignore require-await
    async () => {
      throw new TypeError("async error");
    },
    TypeError,
    "custom message",
  );
});

Deno.test("[node/assert] doesNotReject with 2 parameters", async () => {
  await assert.doesNotReject(
    async () => {},
    "custom message",
  );
});

Deno.test("[node/assert] doesNotReject with 3 parameters", async () => {
  await assert.doesNotReject(
    async () => {},
    TypeError,
    "custom message",
  );
});

Deno.test("[node/assert] exports the versioned classes and functions", () => {
  // The bundled Node.js types do not declare `Assert`.
  const names = ["Assert", "CallTracker", "partialDeepStrictEqual"];
  const defaultExport = assert.default as unknown as Record<string, unknown>;
  for (
    const namespace of [assert, strictAssert] as unknown as Record<
      string,
      unknown
    >[]
  ) {
    for (const name of names) {
      assert.strictEqual(typeof namespace[name], "function", name);
      assert.strictEqual(namespace[name], defaultExport[name], name);
    }
  }
});

Deno.test("[node/assert] deepStrictEqual reuses an expected element after a nested comparison", () => {
  // nodejs/node#62509: the first comparison must not leave `shared` in the
  // cycle memo. A circular comparison makes all later comparisons use the
  // memo.
  const circularA: Record<string, unknown> = {};
  circularA.self = circularA;
  const circularB: Record<string, unknown> = {};
  circularB.self = circularB;
  assert.deepStrictEqual(circularA, circularB);

  const shared = { outer: { inner: 0 } };
  assert.deepStrictEqual(
    [{ outer: { inner: 0 } }, { outer: { inner: 0 } }],
    [shared, shared],
  );
});

Deno.test("[node/assert] deep equality compares a Map null key with object keys", () => {
  // nodejs/node#64441: a `null` key must not reach the object key comparator.
  const actual = new Map<unknown, unknown>([[null, { v: 1 }], [{ a: 1 }, 1]]);
  const other = new Map<unknown, unknown>([[{ b: 2 }, { v: 1 }], [
    { a: 1 },
    1,
  ]]);
  assert.notDeepStrictEqual(actual, other);
  assert.notDeepEqual(actual, other);
  assert.deepStrictEqual(
    actual,
    new Map<unknown, unknown>([[null, { v: 1 }], [{ a: 1 }, 1]]),
  );
});
