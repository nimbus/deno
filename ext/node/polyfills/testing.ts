// Copyright 2018-2026 the Deno authors. MIT license.

import { primordials } from "ext:core/mod.js";
const {
  ArrayPrototypeForEach,
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypeShift,
  ArrayPrototypeSplice,
  Error,
  ObjectDefineProperty,
  Promise,
  PromisePrototypeThen,
  ReflectApply,
  SafeArrayIterator,
  SafePromiseAll,
  SafePromisePrototypeFinally,
  String,
  Symbol,
  TypeError,
} = primordials;
import { notImplemented } from "ext:deno_node/_utils.ts";
import nodeAssert from "node:assert";
import { EventEmitter } from "node:events";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { relative as relativePath, resolve as resolvePath } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  validateBoolean,
  validateFunction,
  validateNumber,
  validateObject,
  validateStringArray,
  validateString,
  validateUint32,
} from "ext:deno_node/internal/validators.mjs";
import { ERR_INVALID_ARG_TYPE } from "ext:deno_node/internal/errors.ts";
import { innerOk } from "ext:deno_node/internal/assert/utils.ts";

const methodsToCopy = [
  "deepEqual",
  "deepStrictEqual",
  "doesNotMatch",
  "doesNotReject",
  "doesNotThrow",
  "equal",
  "fail",
  "ifError",
  "match",
  "notDeepEqual",
  "notDeepStrictEqual",
  "notEqual",
  "notStrictEqual",
  "partialDeepStrictEqual",
  "rejects",
  "strictEqual",
  "throws",
  "ok",
];

function notImplementedAssertion(name: string) {
  return function () {
    notImplemented(name);
  };
}

let assertMethods:
  | Map<string, ((...args: unknown[]) => unknown) | unknown>
  | undefined;
function getAssertMethods() {
  if (assertMethods === undefined) {
    assertMethods = new Map();
    ArrayPrototypeForEach(methodsToCopy, (method) => {
      assertMethods!.set(
        method,
        nodeAssert[method as keyof typeof nodeAssert] as (
          ...args: unknown[]
        ) => unknown,
      );
    });
    assertMethods.set(
      "CallTracker",
      "CallTracker" in nodeAssert
        ? nodeAssert.CallTracker as unknown
        : function CallTracker() {
          notImplemented("test.assert.CallTracker");
        },
    );
    assertMethods.set(
      "snapshot",
      notImplementedAssertion("test.assert.snapshot"),
    );
    assertMethods.set(
      "fileSnapshot",
      notImplementedAssertion("test.assert.fileSnapshot"),
    );
  }
  return assertMethods;
}

function register(name: string, fn: (...args: unknown[]) => unknown) {
  validateString(name, "name");
  validateFunction(fn, "fn");
  getAssertMethods().set(name, fn);
}

export const assert = {
  __proto__: null,
  register,
};

class TestRunStream extends EventEmitter {
  #closed = false;
  #failureCount = 0;
  #queue = [];
  #waiters = [];

  emitTestEvent(type: string, data: unknown) {
    super.emit(type, data);
    if (type === "test:fail") {
      this.#failureCount += 1;
    }
    const event = { __proto__: null, type, data };
    const waiter = ArrayPrototypeShift(this.#waiters);
    if (waiter !== undefined) {
      waiter({ value: event, done: false });
      return;
    }
    ArrayPrototypePush(this.#queue, event);
  }

  close() {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    while (this.#waiters.length > 0) {
      const waiter = ArrayPrototypeShift(this.#waiters);
      waiter?.({ value: undefined, done: true });
    }
  }

  [Symbol.asyncIterator]() {
    return this;
  }

  next() {
    if (this.#queue.length > 0) {
      const value = ArrayPrototypeShift(this.#queue);
      return Promise.resolve({ value, done: false });
    }
    if (this.#closed) {
      return Promise.resolve({ value: undefined, done: true });
    }
    return new Promise((resolve) => {
      ArrayPrototypePush(this.#waiters, resolve);
    });
  }

  compose(transform: unknown) {
    return Readable.from(this).compose(transform);
  }

  get failureCount() {
    return this.#failureCount;
  }
}

let activeRunState:
  | {
    currentFilePath?: string;
    currentRootName?: string;
    nextTestId: number;
    rerun?:
      | {
        currentAttempt: number;
        disambiguator: Map<string, number>;
        filePath: string;
        pendingSyntheticPasses: Promise<unknown>[];
        previousAttempt: Record<string, Record<string, unknown>> | null;
        previousRuns: Record<string, Record<string, unknown>>[];
        rawEvents: Array<{ type: string; data: Record<string, unknown> }>;
      }
      | undefined;
    stream: TestRunStream;
  }
  | undefined;
let activeRunQueue = Promise.resolve();

function parseRerunState(
  filePath: string,
): Record<string, Record<string, unknown>>[] {
  let source: string;
  try {
    source = readFileSync(filePath, "utf8");
  } catch (error) {
    if (error === undefined) {
      return [];
    }
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return [];
    }
    throw error;
  }

  const parsed = JSON.parse(source);
  return Array.isArray(parsed)
    ? parsed as Record<string, Record<string, unknown>>[]
    : [];
}

function getCallerLocation() {
  const stack = new Error().stack;
  if (typeof stack !== "string") {
    return undefined;
  }

  for (const rawLine of stack.split("\n")) {
    const line = rawLine.trim();
    if (!line.startsWith("at ")) {
      continue;
    }
    let location = line.slice(3);
    if (location.endsWith(")")) {
      const openParenIndex = location.lastIndexOf(" (");
      if (openParenIndex !== -1) {
        location = location.slice(openParenIndex + 2, -1);
      }
    }
    const match = location.match(/^(.*):(\d+):(\d+)$/);
    if (!match) {
      continue;
    }
    let [, file, lineNumber, columnNumber] = match;
    if (
      file === "node:test" ||
      file.startsWith("node:") ||
      file === "<anonymous>" ||
      file.endsWith("/ext/node/polyfills/testing.ts")
    ) {
      continue;
    }
    if (file.startsWith("file://")) {
      file = fileURLToPath(file);
    }
    return {
      __proto__: null,
      file,
      line: Number(lineNumber),
      column: Number(columnNumber),
    };
  }

  return undefined;
}

function getRerunDeclarationMetadata(
  loc: { file: string; line: number; column: number } | undefined,
) {
  const rerun = activeRunState?.rerun;
  if (rerun === undefined || loc === undefined) {
    return {
      __proto__: null,
      attempt: 0,
      identifier: undefined,
      previousEntry: undefined,
    };
  }

  const baseIdentifier =
    `${relativePath(globalThis.process?.cwd?.() ?? ".", loc.file).replaceAll("\\", "/")}:${loc.line}:${loc.column}`;
  const disambiguator = rerun.disambiguator.get(baseIdentifier) ?? 0;
  rerun.disambiguator.set(baseIdentifier, disambiguator + 1);
  const identifier = disambiguator === 0
    ? baseIdentifier
    : `${baseIdentifier}:(${disambiguator})`;

  return {
    __proto__: null,
    attempt: rerun.currentAttempt,
    identifier,
    previousEntry: rerun.previousAttempt?.[identifier] as
      | Record<string, unknown>
      | undefined,
  };
}

function normalizeSyntheticRerunFilePath(file: string) {
  const cwd = globalThis.process?.cwd?.();
  if (typeof cwd !== "string") {
    return file;
  }

  const normalizedFile = file.replaceAll("\\", "/");
  const normalizedCwd = cwd.replaceAll("\\", "/");
  const bundleMarker = "/app/.nimbus/convex/";
  const fileBundleIndex = normalizedFile.indexOf(bundleMarker);
  const cwdBundleIndex = normalizedCwd.indexOf(bundleMarker);

  if (fileBundleIndex !== -1 && cwdBundleIndex !== -1) {
    const currentBundleRoot = normalizedCwd.slice(
      0,
      cwdBundleIndex + bundleMarker.length,
    );
    const bundleRelative = normalizedFile.slice(
      fileBundleIndex + bundleMarker.length,
    );
    return resolvePath(currentBundleRoot, bundleRelative);
  }

  const testRelativeIndex = normalizedFile.lastIndexOf("/test/");
  if (testRelativeIndex !== -1) {
    return resolvePath(cwd, normalizedFile.slice(testRelativeIndex + 1));
  }

  return file;
}

function normalizeSyntheticRerunEntry(entry: Record<string, unknown>) {
  if (typeof entry.file === "string") {
    entry.file = normalizeSyntheticRerunFilePath(entry.file);
  }
  if (Array.isArray(entry.children)) {
    for (const child of new SafeArrayIterator(entry.children)) {
      normalizeSyntheticRerunEntry(child as Record<string, unknown>);
    }
  }
}

function reserveSyntheticRerunIdentifiers(entry: Record<string, unknown>) {
  const rerun = activeRunState?.rerun;
  if (rerun === undefined) {
    return;
  }

  const visit = (node: Record<string, unknown>) => {
    if (
      typeof node.file === "string" &&
      typeof node.line === "number" &&
      typeof node.column === "number"
    ) {
      const baseIdentifier =
        `${relativePath(globalThis.process?.cwd?.() ?? ".", node.file).replaceAll("\\", "/")}:${node.line}:${node.column}`;
      const disambiguator = rerun.disambiguator.get(baseIdentifier) ?? 0;
      rerun.disambiguator.set(baseIdentifier, disambiguator + 1);
    }
    if (Array.isArray(node.children)) {
      for (const child of new SafeArrayIterator(node.children)) {
        visit(child as Record<string, unknown>);
      }
    }
  };

  visit(entry);
}

function emitActiveRunEvent(type: string, data: Record<string, unknown>) {
  if (activeRunState?.rerun) {
    ArrayPrototypePush(activeRunState.rerun.rawEvents, { type, data });
  }
  activeRunState?.stream.emitTestEvent(type, data);
}

function trackActiveRunSyntheticPass(promise: Promise<unknown>) {
  if (activeRunState?.rerun) {
    ArrayPrototypePush(activeRunState.rerun.pendingSyntheticPasses, promise);
  }
  return promise;
}

function nextActiveRunTestId() {
  if (activeRunState === undefined) {
    return undefined;
  }
  const testId = activeRunState.nextTestId;
  activeRunState.nextTestId += 1;
  return testId;
}

function writeRerunState(
  previousRuns: Record<string, Record<string, unknown>>[],
  rerunFailuresFilePath: string,
  events: Array<{ type: string; data: Record<string, unknown> }>,
) {
  const obj = { __proto__: null } as Record<string, Record<string, unknown>>;
  const disambiguator = { __proto__: null } as Record<string, number>;
  type RerunNode = {
    data: Record<string, unknown>;
    parent: RerunNode | null;
    children: RerunNode[];
  };
  let currentSuite:
    | RerunNode
    | null = null;

  function getTestId(data: Record<string, unknown>) {
    return `${relativePath(
      globalThis.process?.cwd?.() ?? ".",
      String(data.file),
    ).replaceAll("\\", "/")}:${data.line}:${data.column}`;
  }

  function startTest(data: Record<string, unknown>) {
    const parent = currentSuite;
    currentSuite = {
      __proto__: null,
      data,
      parent,
      children: [],
    };
    if (parent?.children) {
      ArrayPrototypePush(parent.children, currentSuite);
    }
  }

  for (const event of new SafeArrayIterator(events)) {
    const { type, data } = event;
    let currentTest;
    if (type === "test:start") {
      startTest(data);
    } else if (type === "test:fail" || type === "test:pass") {
      if (!currentSuite) {
        startTest({ __proto__: null, name: "root", nesting: 0 });
      }
      if (
        currentSuite.data.name !== data.name ||
        currentSuite.data.nesting !== data.nesting
      ) {
        startTest(data);
      }
      currentTest = currentSuite;
      if (currentSuite?.data.nesting === data.nesting) {
        currentSuite = currentSuite.parent as typeof currentSuite;
      }
    }

    if (type === "test:pass") {
      let identifier = getTestId(data);
      if (disambiguator[identifier] !== undefined) {
        identifier += `:(${disambiguator[identifier]})`;
        disambiguator[identifier] += 1;
      } else {
        disambiguator[identifier] = 1;
      }
      obj[identifier] = {
        __proto__: null,
        name: data.name,
        children: Array.isArray(data.children) && data.children.length > 0
          ? data.children
          : currentTest?.children.map((child) => child.data) ?? [],
        passed_on_attempt: data.details?.passed_on_attempt ??
          data.details?.attempt,
      };
    }
  }

  ArrayPrototypePush(previousRuns, obj);
  writeFileSync(rerunFailuresFilePath, JSON.stringify(previousRuns, null, 2), "utf8");
}

function createSubtestFailureError() {
  return Object.assign(new Error("subtests failed"), {
    failureType: "subtestsFailed",
  });
}

function ensureStepPassed<T>(step: Promise<T | boolean>) {
  return PromisePrototypeThen(step, (result) => {
    if (result === false) {
      throw createSubtestFailureError();
    }
    return result;
  });
}

function emitRootFileFailure(
  stream: TestRunStream,
  displayName: string,
  resolvedPath: string,
  caught: unknown,
  testId?: number,
) {
  const error = caught instanceof Error
    ? caught as Error & { failureType?: string }
    : Object.assign(new Error(String(caught)), { failureType: "testCodeFailure" });
  error.failureType ??= "testCodeFailure";
  stream.emitTestEvent("test:fail", {
    __proto__: null,
    name: displayName,
    file: resolvedPath,
    line: 1,
    column: 1,
    testId,
    details: {
      __proto__: null,
      error,
    },
  });
}

async function loadRunFile(
  require: NodeRequire,
  resolvedPath: string,
) {
  if (resolvedPath.endsWith(".mjs")) {
    await import(pathToFileURL(resolvedPath).href);
    return;
  }
  if (require.cache && resolvedPath in require.cache) {
    delete require.cache[resolvedPath];
  }
  require(resolvedPath);
}

export function run(options = {}) {
  validateObject(options, "options");
  const files = options.files ?? [];
  validateStringArray(files, "options.files");
  if (options.rerunFailuresFilePath !== undefined) {
    validateString(
      options.rerunFailuresFilePath,
      "options.rerunFailuresFilePath",
    );
  }

  const stream = new TestRunStream();
  const flushEmbeddedTests = globalThis.__nimbusFlushEmbeddedTests;
  const require = createRequire(
    resolvePath(globalThis.process?.cwd?.() ?? ".", "__nimbus-test-runner__.js"),
  );

  queueMicrotask(() => {
    const execute = async () => {
      const previousRunState = activeRunState;
      const previousRuns = typeof options.rerunFailuresFilePath === "string"
        ? parseRerunState(options.rerunFailuresFilePath)
        : [];
      activeRunState = {
        stream,
        nextTestId: 1,
        rerun: typeof options.rerunFailuresFilePath === "string"
          ? {
            currentAttempt: previousRuns.length,
            disambiguator: new Map(),
            filePath: options.rerunFailuresFilePath,
            pendingSyntheticPasses: [],
            previousAttempt: previousRuns.length > 0
              ? previousRuns[previousRuns.length - 1]
              : null,
            previousRuns,
            rawEvents: [],
          }
          : undefined,
      };
      try {
        for (const file of files) {
          const resolvedPath = resolvePath(globalThis.process?.cwd?.() ?? ".", file);
          activeRunState.currentFilePath = resolvedPath;
          activeRunState.currentRootName = file;
          if (activeRunState.rerun) {
            activeRunState.rerun.disambiguator = new Map();
          }
          const rootFileTestId = nextActiveRunTestId();
          if (rootFileTestId !== undefined) {
            emitActiveRunEvent("test:enqueue", {
              __proto__: null,
              name: file,
              file: resolvedPath,
              testId: rootFileTestId,
            });
            emitActiveRunEvent("test:dequeue", {
              __proto__: null,
              name: file,
              file: resolvedPath,
              testId: rootFileTestId,
            });
            emitActiveRunEvent("test:complete", {
              __proto__: null,
              name: file,
              file: resolvedPath,
              testId: rootFileTestId,
            });
          }
          const previousSuite = currentSuite;
          const previousContext = currentTestContext;
          try {
            currentSuite = null;
            currentTestContext = undefined;
            await loadRunFile(require, resolvedPath);
          } catch (err) {
            emitRootFileFailure(stream, file, resolvedPath, err, rootFileTestId);
            continue;
          } finally {
            currentSuite = previousSuite;
            currentTestContext = previousContext;
          }
          if (typeof flushEmbeddedTests === "function") {
            try {
              await flushEmbeddedTests({ continueOnError: true });
            } catch {
              // Individual test failures are already surfaced through
              // the event stream; they are not root file-load failures.
            }
          }
        }
        if (activeRunState.rerun?.pendingSyntheticPasses.length) {
          await SafePromiseAll(activeRunState.rerun.pendingSyntheticPasses);
          activeRunState.rerun.pendingSyntheticPasses.length = 0;
        }
        if (activeRunState.rerun) {
          writeRerunState(
            activeRunState.rerun.previousRuns,
            activeRunState.rerun.filePath,
            activeRunState.rerun.rawEvents,
          );
        }
      } finally {
        activeRunState = previousRunState;
        stream.close();
      }
    };
    const queuedRun = PromisePrototypeThen(activeRunQueue, execute, execute);
    const settledRun = PromisePrototypeThen(
      queuedRun,
      () => undefined,
      (error) => {
        if (stream.failureCount > 0) {
          return undefined;
        }
        throw error;
      },
    );
    activeRunQueue = SafePromisePrototypeFinally(settledRun, noop);
  });

  return stream;
}

function noop() {}

function failureTypeFromError(error: unknown) {
  return typeof error === "object" &&
      error !== null &&
      "failureType" in error &&
      typeof error.failureType === "string"
    ? error.failureType
    : "testCodeFailure";
}

class TestPlan {
  #keepAliveId: ReturnType<typeof setInterval> | null = null;
  #waitIndefinitely = false;
  #planPromise:
    | {
      promise: Promise<void>;
      resolve: () => void;
      reject: (reason?: unknown) => void;
    }
    | null = null;
  #timeoutId: ReturnType<typeof setTimeout> | null = null;
  actual = 0;
  expected: number;
  wait: boolean | number | undefined;

  constructor(count: number, options: Record<string, unknown> = {}) {
    validateUint32(count, "count");
    validateObject(options, "options");
    this.expected = count;

    const { wait } = options;
    if (typeof wait === "boolean") {
      this.wait = wait;
      this.#waitIndefinitely = wait;
    } else if (typeof wait === "number") {
      validateNumber(wait, "options.wait", 0, 0x7fffffff);
      this.wait = wait;
    } else if (wait !== undefined) {
      throw new ERR_INVALID_ARG_TYPE("options.wait", ["boolean", "number"], wait);
    }
  }

  #planMet() {
    return this.actual === this.expected;
  }

  #clearTimeout() {
    if (this.#timeoutId !== null) {
      clearTimeout(this.#timeoutId);
      this.#timeoutId = null;
    }
  }

  #clearKeepAlive() {
    if (this.#keepAliveId !== null) {
      clearInterval(this.#keepAliveId);
      this.#keepAliveId = null;
    }
  }

  #shouldWait() {
    return this.wait !== undefined && this.wait !== false;
  }

  #createTimeout(reject: (reason?: unknown) => void) {
    return setTimeout(() => {
      this.#timeoutId = null;
      this.#planPromise = null;
      reject(
        new Error(
          `plan timed out after ${this.wait}ms with ${this.actual} assertions when expecting ${this.expected}`,
        ),
      );
    }, this.wait);
  }

  check() {
    if (this.#planMet()) {
      this.#clearTimeout();
      this.#clearKeepAlive();
      if (this.#planPromise) {
        const { resolve } = this.#planPromise;
        this.#planPromise = null;
        resolve();
      }
      return;
    }

    if (!this.#shouldWait()) {
      throw new Error(
        `plan expected ${this.expected} assertions but received ${this.actual}`,
      );
    }

    if (!this.#planPromise) {
      const { promise, resolve, reject } = Promise.withResolvers<void>();
      this.#planPromise = { __proto__: null, promise, resolve, reject };
      if (this.#waitIndefinitely) {
        this.#keepAliveId = setInterval(noop, 60_000);
      } else {
        this.#timeoutId = this.#createTimeout(reject);
      }
    }

    return this.#planPromise.promise;
  }

  count() {
    this.actual += 1;
    if (this.#planPromise) {
      this.check();
    }
  }

  fail(err: unknown) {
    this.#clearTimeout();
    this.#clearKeepAlive();
    if (this.#planPromise) {
      const { reject } = this.#planPromise;
      this.#planPromise = null;
      reject(err);
    }
  }

  get waiting() {
    return this.#planPromise !== null;
  }
}

const skippedSymbol = Symbol("skipped");
const globalBeforeHooks = [];
const globalBeforeEachHooks = [];
const globalAfterHooks = [];
const globalAfterEachHooks = [];
let currentTestContext: NodeTestContext | undefined;
let rootHooksPendingCount = 0;
let rootBeforeHooksRan = false;
let rootAfterHooksRan = false;

async function withCurrentTestContext<T>(
  context: NodeTestContext,
  fn: () => Promise<T> | T,
): Promise<T> {
  const previousContext = currentTestContext;
  currentTestContext = context;
  try {
    return await fn();
  } finally {
    currentTestContext = previousContext;
  }
}

function createActiveRunEventData(
  name: string,
  options: {
    attempt?: number;
    column?: number;
    file?: string;
    kind?: string;
    line?: number;
    nesting?: number;
    passedAttempt?: number;
    testId?: number;
  } = {},
) {
  const data = {
    __proto__: null,
    name,
    testId: options.testId,
  } as Record<string, unknown>;

  if (activeRunState?.rerun) {
    if (options.file !== undefined) {
      data.file = options.file;
    }
    if (options.line !== undefined) {
      data.line = options.line;
    }
    if (options.nesting !== undefined) {
      data.nesting = options.nesting;
    }
    if (options.kind !== undefined || options.attempt !== undefined) {
      const details = { __proto__: null } as Record<string, unknown>;
      if (options.kind !== undefined) {
        details.type = options.kind;
      }
      if (options.attempt !== undefined) {
        details.attempt = options.attempt;
      }
      if (options.passedAttempt !== undefined) {
        details.passed_on_attempt = options.passedAttempt;
      }
      data.details = details;
    }
    if (options.column !== undefined) {
      data.column = options.column;
    }
  }

  return data;
}

async function emitSyntheticRerunPass(
  entry: Record<string, unknown>,
  options: {
    attempt: number;
    column?: number;
    file?: string;
    kind: string;
    line?: number;
    nesting: number;
    passedAttempt?: number;
    testId?: number;
  },
) {
  const scheduledTestId = options.testId ?? nextActiveRunTestId();
  const name = String(entry.name ?? "<anonymous>");
  const file = typeof entry.file === "string" ? entry.file : options.file;
  const line = typeof entry.line === "number" ? entry.line : options.line;
  const column = typeof entry.column === "number" ? entry.column : options.column;
  const nesting = typeof entry.nesting === "number"
    ? entry.nesting
    : options.nesting;
  const kind = typeof entry.details?.type === "string"
    ? String(entry.details.type)
    : options.kind;
  const passedAttempt = typeof entry.passed_on_attempt === "number"
    ? entry.passed_on_attempt
    : options.passedAttempt;

  emitActiveRunEvent(
    "test:enqueue",
    createActiveRunEventData(name, {
      attempt: options.attempt,
      file,
      kind,
      line,
      nesting,
      passedAttempt,
      testId: scheduledTestId,
      column,
    }),
  );
  emitActiveRunEvent(
    "test:dequeue",
    createActiveRunEventData(name, {
      attempt: options.attempt,
      file,
      kind,
      line,
      nesting,
      passedAttempt,
      testId: scheduledTestId,
      column,
    }),
  );
  emitActiveRunEvent(
    "test:start",
    createActiveRunEventData(name, {
      attempt: options.attempt,
      file,
      kind,
      line,
      nesting,
      passedAttempt,
      testId: scheduledTestId,
      column,
    }),
  );

  if (Array.isArray(entry.children)) {
    for (const child of new SafeArrayIterator(entry.children)) {
      await emitSyntheticRerunPass(
        child as Record<string, unknown>,
        {
          attempt: options.attempt,
          column,
          file,
          kind: "test",
          line,
          nesting: nesting + 1,
          passedAttempt,
        },
      );
    }
  }

  const passData = createActiveRunEventData(name, {
    attempt: options.attempt,
    file,
    kind,
    line,
    nesting,
    passedAttempt,
    testId: scheduledTestId,
    column,
  });
  if (Array.isArray(entry.children) && entry.children.length > 0) {
    passData.children = entry.children;
  }
  emitActiveRunEvent("test:pass", passData);
  emitActiveRunEvent(
    "test:complete",
    createActiveRunEventData(name, {
      attempt: options.attempt,
      file,
      kind,
      line,
      nesting,
      passedAttempt,
      testId: scheduledTestId,
      column,
    }),
  );
}

class NodeTestContext {
  #attempt = 0;
  #completedChildren: Record<string, unknown>[] = [];
  #denoContext: Deno.TestContext;
  #filePath: string | undefined;
  #kind = "test";
  #loc:
    | {
      column: number;
      file: string;
      line: number;
    }
    | undefined;
  #name: string;
  #passedAttempt: number | undefined;
  #testId: number | undefined;
  #afterHooks: (() => void)[] = [];
  #assertObject: Record<string, unknown> | undefined;
  #beforeHooks: (() => void)[] = [];
  #parent: NodeTestContext | undefined;
  #plan: TestPlan | null = null;
  #skipped = false;
  #subtestQueue = Promise.resolve();
  #subtests: Promise<unknown>[] = [];

  constructor(
    t: Deno.TestContext,
    parent: NodeTestContext | undefined,
    options?: {
      attempt?: number;
      filePath?: string;
      kind?: string;
      loc?: { column: number; file: string; line: number };
      name?: string;
      passedAttempt?: number;
      testId?: number;
    },
  ) {
    const fallbackFilePath = activeRunState?.currentFilePath ??
      (
        typeof globalThis.process?.argv?.[1] === "string"
          ? globalThis.process.argv[1]
          : undefined
      );
    this.#denoContext = t;
    this.#filePath = options?.filePath ?? parent?.filePath ?? fallbackFilePath;
    this.#attempt = options?.attempt ?? parent?.attempt ?? 0;
    this.#kind = options?.kind ?? "test";
    this.#loc = options?.loc;
    this.#name = options?.name ?? t.name;
    this.#passedAttempt = options?.passedAttempt;
    this.#testId = options?.testId;
    this.#parent = parent;
  }

  get [skippedSymbol]() {
    return this.#skipped || (this.#parent?.[skippedSymbol] ?? false);
  }

  get assert() {
    if (this.#assertObject === undefined) {
      const assertObject = { __proto__: null } as Record<string, unknown>;
      for (const [name, method] of getAssertMethods()) {
        if (name === "ok" && method === nodeAssert.ok) {
          function ok(value: unknown, message?: string | Error) {
            const waiting = this.#plan?.waiting === true;
            if (!waiting) {
              this.#plan?.count();
            }
            try {
              innerOk(ok, arguments.length, value, message);
              if (waiting) {
                this.#plan?.count();
              }
            } catch (err) {
              if (waiting) {
                this.#plan.fail(err);
                return;
              }
              throw err;
            }
          }
          assertObject[name] = ok.bind(this);
        } else if (typeof method === "function" && name !== "CallTracker") {
          assertObject[name] = (...args: unknown[]) => {
            const waiting = this.#plan?.waiting === true;
            if (!waiting) {
              this.#plan?.count();
            }
            try {
              const result = ReflectApply(method, this, args);
              if (waiting) {
                this.#plan?.count();
              }
              return result;
            } catch (err) {
              if (waiting) {
                this.#plan.fail(err);
                return;
              }
              throw err;
            }
          };
        } else {
          assertObject[name] = method;
        }
      }
      this.#assertObject = assertObject;
    }
    return this.#assertObject;
  }

  get signal() {
    return this.#denoContext.signal ?? null;
  }

  get name() {
    return this.#name;
  }

  get kind() {
    return this.#kind;
  }

  get nesting() {
    let nesting = 0;
    let parent = this.#parent;
    while (parent !== undefined) {
      nesting += 1;
      parent = parent.parent;
    }
    return nesting;
  }

  get fullName() {
    if (this.#parent) {
      return `${this.#parent.fullName} > ${this.name}`;
    }
    return this.name;
  }

  get filePath() {
    return this.#filePath;
  }

  get location() {
    return this.#loc;
  }

  get parent() {
    return this.#parent;
  }

  get rerunChildren() {
    return this.#completedChildren;
  }

  get testId() {
    return this.#testId;
  }

  get attempt() {
    return this.#attempt;
  }

  get passedAttempt() {
    return this.#passedAttempt;
  }

  get passed() {
    return false;
  }

  recordChild(data: Record<string, unknown>) {
    ArrayPrototypePush(this.#completedChildren, data);
  }

  diagnostic(message) {
    // deno-lint-ignore no-console
    console.log("DIAGNOSTIC:", message);
  }

  plan(count: number, options: Record<string, unknown> = {}) {
    if (this.#plan !== null) {
      throw new Error("cannot set plan more than once");
    }
    this.#plan = new TestPlan(count, options);
  }

  async checkPlan() {
    await this.#plan?.check();
  }

  async waitForSubtests() {
    if (this.#subtests.length === 0) {
      return;
    }
    const pendingSubtests = this.#subtests;
    this.#subtests = [];
    let failed = false;
    for (const subtest of new SafeArrayIterator(pendingSubtests)) {
      try {
        await subtest;
      } catch {
        failed = true;
      }
    }
    if (failed) {
      throw Object.assign(new Error("subtests failed"), {
        failureType: "subtestsFailed",
      });
    }
  }

  get mock() {
    return mock;
  }

  runOnly() {
    notImplemented("test.TestContext.runOnly");
    return null;
  }

  skip() {
    this.#skipped = true;
    return null;
  }

  todo() {
    this.#skipped = true;
    return null;
  }

  test(name, options, fn) {
    const prepared = prepareOptions(name, options, fn, {});
    this.#plan?.count();
    const loc = getCallerLocation();
    const rerunMetadata = getRerunDeclarationMetadata(loc);
    const scheduledTestId = nextActiveRunTestId();
    // deno-lint-ignore no-this-alias
    const parentContext = this;
    const nesting = this.nesting + 1;
  const syntheticRerunEntry = rerunMetadata.previousEntry;
  if (syntheticRerunEntry !== undefined) {
      normalizeSyntheticRerunEntry(syntheticRerunEntry);
      reserveSyntheticRerunIdentifiers(syntheticRerunEntry);
      const trackedSyntheticSubtestPromise = emitSyntheticRerunPass(
        syntheticRerunEntry,
        {
          attempt: rerunMetadata.attempt,
          column: loc?.column,
          file: loc?.file ?? parentContext.filePath,
          kind: "test",
          line: loc?.line,
          nesting,
          passedAttempt: typeof syntheticRerunEntry.passed_on_attempt === "number"
            ? syntheticRerunEntry.passed_on_attempt as number
            : undefined,
          testId: scheduledTestId,
        },
      );
      ArrayPrototypePush(this.#subtests, trackedSyntheticSubtestPromise);
      PromisePrototypeThen(trackedSyntheticSubtestPromise, noop, noop);
      return PromisePrototypeThen(
        trackedSyntheticSubtestPromise,
        () => undefined,
        () => undefined,
      );
    }
    if (scheduledTestId !== undefined) {
      emitActiveRunEvent(
        "test:enqueue",
        createActiveRunEventData(prepared.name, {
          attempt: rerunMetadata.attempt,
          file: loc?.file ?? parentContext.filePath,
          kind: "test",
          line: loc?.line,
          nesting,
          testId: scheduledTestId,
          column: loc?.column,
        }),
      );
    }
    const after = async () => {
      for (const hook of new SafeArrayIterator(this.#afterHooks)) {
        await hook();
      }
    };
    const before = async () => {
      for (const hook of new SafeArrayIterator(this.#beforeHooks)) {
        await hook();
      }
    };
    const runSubtest = () => this.#denoContext.step({
        name: prepared.name,
        fn: async (denoTestContext) => {
          const newNodeTextContext = new NodeTestContext(
            denoTestContext,
            parentContext,
            {
              attempt: rerunMetadata.attempt,
              filePath: parentContext.filePath,
              kind: "test",
              loc,
              name: prepared.name,
              passedAttempt: undefined,
              testId: scheduledTestId,
            },
          );
          if (newNodeTextContext.testId !== undefined) {
            emitActiveRunEvent(
              "test:dequeue",
              createActiveRunEventData(newNodeTextContext.name, {
                attempt: newNodeTextContext.attempt,
                file: newNodeTextContext.location?.file ??
                  newNodeTextContext.filePath,
                kind: newNodeTextContext.kind,
                line: newNodeTextContext.location?.line,
                nesting: newNodeTextContext.nesting,
                testId: newNodeTextContext.testId,
                column: newNodeTextContext.location?.column,
              }),
            );
            emitActiveRunEvent(
              "test:start",
              createActiveRunEventData(newNodeTextContext.name, {
                attempt: newNodeTextContext.attempt,
                file: newNodeTextContext.location?.file ??
                  newNodeTextContext.filePath,
                kind: newNodeTextContext.kind,
                line: newNodeTextContext.location?.line,
                nesting: newNodeTextContext.nesting,
                testId: newNodeTextContext.testId,
                column: newNodeTextContext.location?.column,
              }),
            );
          }
          try {
            await withCurrentTestContext(newNodeTextContext, async () => {
              if (prepared.options.plan !== undefined) {
                newNodeTextContext.plan(prepared.options.plan);
              }
              await before();
              if (prepared.fn.length >= 2) {
                await new Promise((testResolve, testReject) => {
                  const done = (err?: Error) => {
                    if (err) {
                      testReject(err);
                    } else {
                      testResolve(undefined);
                    }
                  };
                  try {
                    prepared.fn(newNodeTextContext, done);
                  } catch (err) {
                    testReject(err);
                  }
                });
              } else {
                await prepared.fn(newNodeTextContext);
              }
              await newNodeTextContext.checkPlan();
              await newNodeTextContext.waitForSubtests();
              await after();
            });
            if (newNodeTextContext.testId !== undefined) {
              const data = createActiveRunEventData(newNodeTextContext.name, {
                attempt: newNodeTextContext.attempt,
                file: newNodeTextContext.location?.file ??
                  newNodeTextContext.filePath,
                kind: newNodeTextContext.kind,
                line: newNodeTextContext.location?.line,
                nesting: newNodeTextContext.nesting,
                testId: newNodeTextContext.testId,
                column: newNodeTextContext.location?.column,
              });
              if (newNodeTextContext.rerunChildren.length > 0) {
                data.children = [...newNodeTextContext.rerunChildren];
              }
              emitActiveRunEvent("test:pass", data);
              parentContext.recordChild(data);
            }
          } catch (err) {
            if (!newNodeTextContext[skippedSymbol]) {
              if (newNodeTextContext.testId !== undefined) {
                const data = createActiveRunEventData(newNodeTextContext.name, {
                  attempt: newNodeTextContext.attempt,
                  file: newNodeTextContext.location?.file ??
                    newNodeTextContext.filePath,
                  kind: newNodeTextContext.kind,
                  line: newNodeTextContext.location?.line,
                  nesting: newNodeTextContext.nesting,
                  testId: newNodeTextContext.testId,
                  column: newNodeTextContext.location?.column,
                });
                (data.details as Record<string, unknown> | undefined ??=
                  { __proto__: null }).error = {
                    __proto__: null,
                    failureType: failureTypeFromError(err),
                  };
                emitActiveRunEvent("test:fail", data);
              }
              throw err;
            }
            try {
              await after();
            } catch {
              // ignore, test is already failing
            }
          } finally {
            if (newNodeTextContext.testId !== undefined) {
              emitActiveRunEvent(
                "test:complete",
                createActiveRunEventData(newNodeTextContext.name, {
                  attempt: newNodeTextContext.attempt,
                  file: newNodeTextContext.location?.file ??
                    newNodeTextContext.filePath,
                  kind: newNodeTextContext.kind,
                  line: newNodeTextContext.location?.line,
                  nesting: newNodeTextContext.nesting,
                  testId: newNodeTextContext.testId,
                  column: newNodeTextContext.location?.column,
                }),
              );
            }
            mock.restoreAll();
          }
        },
        ignore: prepared.options.todo || prepared.options.skip,
        sanitizeExit: false,
        sanitizeOps: false,
        sanitizeResources: false,
      });
    const allowConcurrentSubtests =
      prepared.options.concurrency === true ||
      (typeof prepared.options.concurrency === "number" &&
        prepared.options.concurrency > 1);
    const queuedSubtest = allowConcurrentSubtests
      ? runSubtest()
      : PromisePrototypeThen(this.#subtestQueue, runSubtest, runSubtest);
    if (!allowConcurrentSubtests) {
      this.#subtestQueue = PromisePrototypeThen(queuedSubtest, noop, noop);
    }
    const trackedSubtestPromise = PromisePrototypeThen(
      ensureStepPassed(queuedSubtest),
      () => undefined,
    );
    ArrayPrototypePush(this.#subtests, trackedSubtestPromise);
    PromisePrototypeThen(trackedSubtestPromise, noop, noop);
    return PromisePrototypeThen(
      trackedSubtestPromise,
      () => undefined,
      () => undefined,
    );
  }

  before(fn, _options) {
    if (typeof fn !== "function") {
      throw new TypeError("before() requires a function");
    }
    ArrayPrototypePush(this.#beforeHooks, fn);
  }

  after(fn, _options) {
    if (typeof fn !== "function") {
      throw new TypeError("after() requires a function");
    }
    ArrayPrototypePush(this.#afterHooks, fn);
  }

  beforeEach(_fn, _options) {
    notImplemented("test.TestContext.beforeEach");
  }

  afterEach(_fn, _options) {
    notImplemented("test.TestContext.afterEach");
  }
}

let currentSuite: TestSuite | null = null;

async function runRootBeforeHooks(t: Deno.TestContext) {
  if (rootBeforeHooksRan) {
    return;
  }
  rootBeforeHooksRan = true;
  const rootContext = new NodeTestContext(t, undefined, {
    name: "<root>",
  });
  await withCurrentTestContext(rootContext, async () => {
    for (const hook of new SafeArrayIterator(globalBeforeHooks)) {
      await hook(rootContext);
    }
  });
}

async function maybeRunRootAfterHooks(t: Deno.TestContext) {
  if (rootAfterHooksRan) {
    return;
  }
  rootHooksPendingCount -= 1;
  if (rootHooksPendingCount !== 0) {
    return;
  }
  rootAfterHooksRan = true;
  const rootContext = new NodeTestContext(t, undefined, {
    name: "<root>",
  });
  await withCurrentTestContext(rootContext, async () => {
    for (const hook of new SafeArrayIterator(globalAfterHooks)) {
      await hook(rootContext);
    }
  });
}

class TestSuite {
  #denoTestContext: Deno.TestContext;
  #parentContext: NodeTestContext | undefined;
  steps: Promise<boolean>[] = [];

  constructor(t: Deno.TestContext, parentContext: NodeTestContext | undefined) {
    this.#denoTestContext = t;
    this.#parentContext = parentContext;
  }

  addTest(name, options, fn, overrides) {
    const prepared = prepareOptions(name, options, fn, overrides);
    const loc = getCallerLocation();
    const rerunMetadata = getRerunDeclarationMetadata(loc);
    const scheduledTestId = nextActiveRunTestId();
    if (rerunMetadata.previousEntry !== undefined) {
      normalizeSyntheticRerunEntry(rerunMetadata.previousEntry);
      reserveSyntheticRerunIdentifiers(rerunMetadata.previousEntry);
      const syntheticStep = emitSyntheticRerunPass(
        rerunMetadata.previousEntry,
        {
          attempt: rerunMetadata.attempt,
          column: loc?.column,
          file: loc?.file ?? this.#parentContext?.filePath,
          kind: "test",
          line: loc?.line,
          nesting: (this.#parentContext?.nesting ?? -1) + 1,
          passedAttempt:
            typeof rerunMetadata.previousEntry.passed_on_attempt === "number"
              ? rerunMetadata.previousEntry.passed_on_attempt as number
              : undefined,
          testId: scheduledTestId,
        },
      ) as Promise<boolean>;
      ArrayPrototypePush(this.steps, syntheticStep);
      return;
    }
    if (scheduledTestId !== undefined) {
      emitActiveRunEvent(
        "test:enqueue",
        createActiveRunEventData(prepared.name, {
          attempt: rerunMetadata.attempt,
          file: loc?.file ?? this.#parentContext?.filePath,
          kind: "test",
          line: loc?.line,
          nesting: (this.#parentContext?.nesting ?? -1) + 1,
          testId: scheduledTestId,
          column: loc?.column,
        }),
      );
    }
    const step = this.#denoTestContext.step({
      name: prepared.name,
      fn: async (denoTestContext) => {
        const newNodeTextContext = new NodeTestContext(
          denoTestContext,
          this.#parentContext,
          {
            attempt: rerunMetadata.attempt,
            filePath: this.#parentContext?.filePath,
            kind: "test",
            loc,
            name: prepared.name,
            testId: scheduledTestId,
          },
        );
        if (newNodeTextContext.testId !== undefined) {
          emitActiveRunEvent(
            "test:dequeue",
            createActiveRunEventData(newNodeTextContext.name, {
              attempt: newNodeTextContext.attempt,
              file: newNodeTextContext.location?.file ??
                newNodeTextContext.filePath,
              kind: newNodeTextContext.kind,
              line: newNodeTextContext.location?.line,
              nesting: newNodeTextContext.nesting,
              testId: newNodeTextContext.testId,
              column: newNodeTextContext.location?.column,
            }),
          );
          emitActiveRunEvent(
            "test:start",
            createActiveRunEventData(newNodeTextContext.name, {
              attempt: newNodeTextContext.attempt,
              file: newNodeTextContext.location?.file ??
                newNodeTextContext.filePath,
              kind: newNodeTextContext.kind,
              line: newNodeTextContext.location?.line,
              nesting: newNodeTextContext.nesting,
              testId: newNodeTextContext.testId,
              column: newNodeTextContext.location?.column,
            }),
          );
        }
        try {
          return await withCurrentTestContext(newNodeTextContext, async () => {
            if (prepared.options.plan !== undefined) {
              newNodeTextContext.plan(prepared.options.plan);
            }
            let result;
            if (prepared.fn.length >= 2) {
              result = await new Promise((testResolve, testReject) => {
                const done = (err?: Error) => {
                  if (err) {
                    testReject(err);
                  } else {
                    testResolve(undefined);
                  }
                };
                try {
                  prepared.fn(newNodeTextContext, done);
                } catch (err) {
                  testReject(err);
                }
              });
            } else {
              result = await prepared.fn(newNodeTextContext);
            }
            await newNodeTextContext.checkPlan();
            await newNodeTextContext.waitForSubtests();
            if (newNodeTextContext.testId !== undefined) {
              const data = createActiveRunEventData(newNodeTextContext.name, {
                attempt: newNodeTextContext.attempt,
                file: newNodeTextContext.location?.file ??
                  newNodeTextContext.filePath,
                kind: newNodeTextContext.kind,
                line: newNodeTextContext.location?.line,
                nesting: newNodeTextContext.nesting,
                testId: newNodeTextContext.testId,
                column: newNodeTextContext.location?.column,
              });
              if (newNodeTextContext.rerunChildren.length > 0) {
                data.children = [...newNodeTextContext.rerunChildren];
              }
              emitActiveRunEvent("test:pass", data);
              this.#parentContext?.recordChild(data);
            }
            return result;
          });
        } catch (err) {
          if (newNodeTextContext[skippedSymbol]) {
            return undefined;
          } else {
            if (newNodeTextContext.testId !== undefined) {
              const data = createActiveRunEventData(newNodeTextContext.name, {
                attempt: newNodeTextContext.attempt,
                file: newNodeTextContext.location?.file ??
                  newNodeTextContext.filePath,
                kind: newNodeTextContext.kind,
                line: newNodeTextContext.location?.line,
                nesting: newNodeTextContext.nesting,
                testId: newNodeTextContext.testId,
                column: newNodeTextContext.location?.column,
              });
              (data.details as Record<string, unknown> | undefined ??=
                { __proto__: null }).error = {
                  __proto__: null,
                  failureType: failureTypeFromError(err),
                };
              emitActiveRunEvent("test:fail", data);
            }
            throw err;
          }
        } finally {
          if (newNodeTextContext.testId !== undefined) {
            emitActiveRunEvent(
              "test:complete",
              createActiveRunEventData(newNodeTextContext.name, {
                attempt: newNodeTextContext.attempt,
                file: newNodeTextContext.location?.file ??
                  newNodeTextContext.filePath,
                kind: newNodeTextContext.kind,
                line: newNodeTextContext.location?.line,
                nesting: newNodeTextContext.nesting,
                testId: newNodeTextContext.testId,
                column: newNodeTextContext.location?.column,
              }),
            );
          }
        }
      },
      ignore: prepared.options.todo || prepared.options.skip,
      sanitizeExit: false,
      sanitizeOps: false,
      sanitizeResources: false,
    });
    ArrayPrototypePush(this.steps, ensureStepPassed(step));
  }

  addSuite(name, options, fn, overrides) {
    const prepared = prepareOptions(name, options, fn, overrides);
    const loc = getCallerLocation();
    const rerunMetadata = getRerunDeclarationMetadata(loc);
    const scheduledTestId = activeRunState?.rerun ? nextActiveRunTestId() : undefined;
    // deno-lint-ignore prefer-primordials
    const { promise, resolve } = Promise.withResolvers();
    if (rerunMetadata.previousEntry !== undefined) {
      normalizeSyntheticRerunEntry(rerunMetadata.previousEntry);
      reserveSyntheticRerunIdentifiers(rerunMetadata.previousEntry);
      queueMicrotask(() => {
        emitSyntheticRerunPass(
          rerunMetadata.previousEntry!,
          {
            attempt: rerunMetadata.attempt,
            column: loc?.column,
            file: loc?.file ?? this.#parentContext?.filePath,
            kind: "suite",
            line: loc?.line,
            nesting: (this.#parentContext?.nesting ?? -1) + 1,
            passedAttempt:
              typeof rerunMetadata.previousEntry?.passed_on_attempt === "number"
                ? rerunMetadata.previousEntry.passed_on_attempt as number
                : undefined,
            testId: scheduledTestId,
          },
        ).then(resolve, resolve);
      });
      return promise;
    }
    if (scheduledTestId !== undefined) {
      emitActiveRunEvent(
        "test:enqueue",
        createActiveRunEventData(prepared.name, {
          attempt: rerunMetadata.attempt,
          file: loc?.file ?? this.#parentContext?.filePath,
          kind: "suite",
          line: loc?.line,
          nesting: (this.#parentContext?.nesting ?? -1) + 1,
          testId: scheduledTestId,
          column: loc?.column,
        }),
      );
    }
    const step = this.#denoTestContext.step({
      name: prepared.name,
      fn: wrapSuiteFn(prepared.fn, resolve, {
        attempt: rerunMetadata.attempt,
        filePath: this.#parentContext?.filePath,
        kind: "suite",
        loc,
        name: prepared.name,
        testId: scheduledTestId,
      }, this.#parentContext),
      ignore: prepared.options.todo || prepared.options.skip,
      sanitizeExit: false,
      sanitizeOps: false,
      sanitizeResources: false,
    });
    ArrayPrototypePush(this.steps, ensureStepPassed(step));
    return promise;
  }
}

function prepareOptions(name, options, fn, overrides) {
  if (typeof name === "function") {
    fn = name;
  } else if (name !== null && typeof name === "object") {
    fn = options;
    options = name;
  } else if (typeof options === "function") {
    fn = options;
  }

  if (options === null || typeof options !== "object") {
    options = {};
  }

  const finalOptions = { ...options, ...overrides };
  const { concurrency, timeout, plan } = finalOptions;

  if (timeout != null && timeout !== Infinity) {
    validateNumber(timeout, "options.timeout", 0, 0x7fffffff);
  }

  switch (typeof concurrency) {
    case "number":
      validateUint32(concurrency, "options.concurrency", true);
      break;
    case "boolean":
      validateBoolean(concurrency, "options.concurrency");
      break;
    default:
      if (concurrency != null) {
        validateBoolean(concurrency, "options.concurrency");
      }
      break;
  }

  if (plan !== undefined) {
    validateUint32(plan, "options.plan");
  }

  if (typeof fn !== "function") {
    fn = noop;
  }

  if (typeof name !== "string" || name === "") {
    name = fn.name || "<anonymous>";
  }

  return { fn, options: finalOptions, name };
}

function wrapTestFn(
  fn,
  resolve,
  options?: {
    attempt?: number;
    filePath?: string;
    kind?: string;
    loc?: { column: number; file: string; line: number };
    name?: string;
    plan?: number;
    passedAttempt?: number;
    testId?: number;
  },
) {
  return async function (t) {
    const nodeTestContext = new NodeTestContext(t, undefined, options);
    if (nodeTestContext.testId !== undefined) {
      emitActiveRunEvent(
        "test:dequeue",
        createActiveRunEventData(nodeTestContext.name, {
          attempt: nodeTestContext.attempt,
          file: nodeTestContext.location?.file ?? nodeTestContext.filePath,
          kind: nodeTestContext.kind,
          line: nodeTestContext.location?.line,
          nesting: nodeTestContext.nesting,
          passedAttempt: nodeTestContext.passedAttempt,
          testId: nodeTestContext.testId,
          column: nodeTestContext.location?.column,
        }),
      );
      emitActiveRunEvent(
        "test:start",
        createActiveRunEventData(nodeTestContext.name, {
          attempt: nodeTestContext.attempt,
          file: nodeTestContext.location?.file ?? nodeTestContext.filePath,
          kind: nodeTestContext.kind,
          line: nodeTestContext.location?.line,
          nesting: nodeTestContext.nesting,
          passedAttempt: nodeTestContext.passedAttempt,
          testId: nodeTestContext.testId,
          column: nodeTestContext.location?.column,
        }),
      );
    }
    try {
      await withCurrentTestContext(nodeTestContext, async () => {
        if (options?.plan !== undefined) {
          nodeTestContext.plan(options.plan);
        }
        await runRootBeforeHooks(t);
        for (const hook of new SafeArrayIterator(globalBeforeEachHooks)) {
          await hook(nodeTestContext);
        }
        // Check if the test function expects a done callback (2 parameters)
        if (fn.length >= 2) {
          // Callback-style async test
          await new Promise((testResolve, testReject) => {
            const done = (err?: Error) => {
              if (err) {
                testReject(err);
              } else {
                testResolve(undefined);
              }
            };
            try {
              fn(nodeTestContext, done);
            } catch (err) {
              testReject(err);
            }
          });
        } else {
          // Promise-style or sync test
          await fn(nodeTestContext);
        }
        await nodeTestContext.checkPlan();
        await nodeTestContext.waitForSubtests();
      });
      if (nodeTestContext.testId !== undefined) {
        const data = createActiveRunEventData(nodeTestContext.name, {
          attempt: nodeTestContext.attempt,
          file: nodeTestContext.location?.file ?? nodeTestContext.filePath,
          kind: nodeTestContext.kind,
          line: nodeTestContext.location?.line,
          nesting: nodeTestContext.nesting,
          passedAttempt: nodeTestContext.passedAttempt,
          testId: nodeTestContext.testId,
          column: nodeTestContext.location?.column,
        });
        if (nodeTestContext.rerunChildren.length > 0) {
          data.children = [...nodeTestContext.rerunChildren];
        }
        emitActiveRunEvent("test:pass", data);
      }
    } catch (err) {
      if (!nodeTestContext[skippedSymbol]) {
        if (nodeTestContext.testId !== undefined) {
          const data = createActiveRunEventData(nodeTestContext.name, {
            attempt: nodeTestContext.attempt,
            file: nodeTestContext.location?.file ?? nodeTestContext.filePath,
            kind: nodeTestContext.kind,
            line: nodeTestContext.location?.line,
            nesting: nodeTestContext.nesting,
            passedAttempt: nodeTestContext.passedAttempt,
            testId: nodeTestContext.testId,
            column: nodeTestContext.location?.column,
          });
          (data.details as Record<string, unknown> | undefined ??=
            { __proto__: null }).error = {
              __proto__: null,
              failureType: failureTypeFromError(err),
            };
          emitActiveRunEvent("test:fail", data);
        }
        throw err;
      }
    } finally {
      if (nodeTestContext.testId !== undefined) {
        emitActiveRunEvent(
          "test:complete",
          createActiveRunEventData(nodeTestContext.name, {
            attempt: nodeTestContext.attempt,
            file: nodeTestContext.location?.file ?? nodeTestContext.filePath,
            kind: nodeTestContext.kind,
            line: nodeTestContext.location?.line,
            nesting: nodeTestContext.nesting,
            passedAttempt: nodeTestContext.passedAttempt,
            testId: nodeTestContext.testId,
            column: nodeTestContext.location?.column,
          }),
        );
      }
      for (const hook of new SafeArrayIterator(globalAfterEachHooks)) {
        await hook(nodeTestContext);
      }
      mock.restoreAll();
      await maybeRunRootAfterHooks(t);
      resolve();
    }
  };
}

function prepareDenoTest(name, options, fn, overrides) {
  const prepared = prepareOptions(name, options, fn, overrides);

  if (prepared.options.todo || prepared.options.skip) {
    return Promise.resolve(undefined);
  }

  const loc = getCallerLocation();
  const rerunMetadata = getRerunDeclarationMetadata(loc);
  const syntheticRerunEntry = rerunMetadata.previousEntry;

  if (syntheticRerunEntry !== undefined) {
    // deno-lint-ignore prefer-primordials
    const { promise, resolve, reject } = Promise.withResolvers();
    const trackedSyntheticPromise = trackActiveRunSyntheticPass(promise);
    normalizeSyntheticRerunEntry(syntheticRerunEntry);
    reserveSyntheticRerunIdentifiers(syntheticRerunEntry);
    queueMicrotask(() => {
      emitSyntheticRerunPass(syntheticRerunEntry, {
        attempt: rerunMetadata.attempt,
        column: loc?.column,
        file: loc?.file ?? activeRunState?.currentFilePath,
        kind: "test",
        line: loc?.line,
        nesting: 0,
        passedAttempt: typeof syntheticRerunEntry.passed_on_attempt === "number"
          ? syntheticRerunEntry.passed_on_attempt as number
          : undefined,
        testId: nextActiveRunTestId(),
      }).then(resolve, reject);
    });
    return trackedSyntheticPromise;
  }

  // TODO(iuioiua): Update once there's a primordial for `Promise.withResolvers()`.
  // deno-lint-ignore prefer-primordials
  const { promise, resolve } = Promise.withResolvers();
  rootHooksPendingCount += 1;
  const scheduledTestId = nextActiveRunTestId();
  if (scheduledTestId !== undefined) {
    emitActiveRunEvent(
      "test:enqueue",
      createActiveRunEventData(prepared.name, {
        attempt: rerunMetadata.attempt,
        file: loc?.file ?? activeRunState?.currentFilePath,
        kind: "test",
        line: loc?.line,
        nesting: 0,
        testId: scheduledTestId,
        column: loc?.column,
      }),
    );
  }

  const denoTestOptions = {
    name: prepared.name,
    fn: wrapTestFn(prepared.fn, resolve, {
      attempt: rerunMetadata.attempt,
      filePath: activeRunState?.currentFilePath,
      kind: "test",
      loc,
      name: prepared.name,
      plan: prepared.options.plan,
      testId: scheduledTestId,
    }),
    only: prepared.options.only,
    ignore: prepared.options.todo || prepared.options.skip,
    sanitizeOnly: false,
    sanitizeExit: false,
    sanitizeOps: false,
    sanitizeResources: false,
  };
  Deno.test(denoTestOptions);
  return promise;
}

function wrapSuiteFn(
  fn,
  resolve,
  options?: {
    attempt?: number;
    filePath?: string;
    kind?: string;
    loc?: { column: number; file: string; line: number };
    name?: string;
    passedAttempt?: number;
    testId?: number;
  },
  parentContext?: NodeTestContext,
) {
  return async function (t) {
    const prevSuite = currentSuite;
    const suiteContext = new NodeTestContext(t, parentContext, options);
    let suiteBodyFailed = false;
    const suite = currentSuite = new TestSuite(t, suiteContext);
    if (suiteContext.testId !== undefined) {
      emitActiveRunEvent(
        "test:dequeue",
        createActiveRunEventData(suiteContext.name, {
          attempt: suiteContext.attempt,
          file: suiteContext.location?.file ?? suiteContext.filePath,
          kind: suiteContext.kind,
          line: suiteContext.location?.line,
          nesting: suiteContext.nesting,
          passedAttempt: suiteContext.passedAttempt,
          testId: suiteContext.testId,
          column: suiteContext.location?.column,
        }),
      );
      emitActiveRunEvent(
        "test:start",
        createActiveRunEventData(suiteContext.name, {
          attempt: suiteContext.attempt,
          file: suiteContext.location?.file ?? suiteContext.filePath,
          kind: suiteContext.kind,
          line: suiteContext.location?.line,
          nesting: suiteContext.nesting,
          passedAttempt: suiteContext.passedAttempt,
          testId: suiteContext.testId,
          column: suiteContext.location?.column,
        }),
      );
    }
    try {
      await runRootBeforeHooks(t);
      await withCurrentTestContext(suiteContext, async () => {
        await fn(suiteContext);
      });
    } catch (err) {
      suiteBodyFailed = true;
      if (!suiteContext[skippedSymbol]) {
        if (suiteContext.testId !== undefined) {
          const data = createActiveRunEventData(suiteContext.name, {
            attempt: suiteContext.attempt,
            file: suiteContext.location?.file ?? suiteContext.filePath,
            kind: suiteContext.kind,
            line: suiteContext.location?.line,
            nesting: suiteContext.nesting,
            passedAttempt: suiteContext.passedAttempt,
            testId: suiteContext.testId,
            column: suiteContext.location?.column,
          });
          (data.details as Record<string, unknown> | undefined ??=
            { __proto__: null }).error = {
              __proto__: null,
              failureType: failureTypeFromError(err),
            };
          emitActiveRunEvent("test:fail", data);
        }
        throw err;
      }
    } finally {
      currentSuite = prevSuite;
    }
    return SafePromisePrototypeFinally(
      (async () => {
        try {
          await SafePromiseAll(suite.steps);
          if (!suiteBodyFailed && suiteContext.testId !== undefined) {
            const data = createActiveRunEventData(suiteContext.name, {
              attempt: suiteContext.attempt,
              file: suiteContext.location?.file ?? suiteContext.filePath,
              kind: suiteContext.kind,
              line: suiteContext.location?.line,
              nesting: suiteContext.nesting,
              passedAttempt: suiteContext.passedAttempt,
              testId: suiteContext.testId,
              column: suiteContext.location?.column,
            });
            if (suiteContext.rerunChildren.length > 0) {
              data.children = [...suiteContext.rerunChildren];
            }
            emitActiveRunEvent("test:pass", data);
            parentContext?.recordChild(data);
          }
        } catch (err) {
          if (!suiteBodyFailed && !suiteContext[skippedSymbol]) {
            if (suiteContext.testId !== undefined) {
              const data = createActiveRunEventData(suiteContext.name, {
                attempt: suiteContext.attempt,
                file: suiteContext.location?.file ?? suiteContext.filePath,
                kind: suiteContext.kind,
                line: suiteContext.location?.line,
                nesting: suiteContext.nesting,
                passedAttempt: suiteContext.passedAttempt,
                testId: suiteContext.testId,
                column: suiteContext.location?.column,
              });
              (data.details as Record<string, unknown> | undefined ??=
                { __proto__: null }).error = {
                  __proto__: null,
                  failureType: failureTypeFromError(err),
                };
              emitActiveRunEvent("test:fail", data);
            }
          }
          throw err;
        }
      })(),
      async () => {
        if (suiteContext.testId !== undefined) {
          emitActiveRunEvent(
            "test:complete",
            createActiveRunEventData(suiteContext.name, {
              attempt: suiteContext.attempt,
              file: suiteContext.location?.file ?? suiteContext.filePath,
              kind: suiteContext.kind,
              line: suiteContext.location?.line,
              nesting: suiteContext.nesting,
              passedAttempt: suiteContext.passedAttempt,
              testId: suiteContext.testId,
              column: suiteContext.location?.column,
            }),
          );
        }
        await maybeRunRootAfterHooks(t);
        resolve();
      },
    );
  };
}

function prepareDenoTestForSuite(name, options, fn, overrides) {
  const prepared = prepareOptions(name, options, fn, overrides);

  if (prepared.options.todo || prepared.options.skip) {
    return Promise.resolve(undefined);
  }

  // deno-lint-ignore prefer-primordials
  const { promise, resolve } = Promise.withResolvers();
  const loc = getCallerLocation();
  const rerunMetadata = getRerunDeclarationMetadata(loc);
  const syntheticRerunEntry = rerunMetadata.previousEntry;

  if (syntheticRerunEntry !== undefined) {
    // deno-lint-ignore prefer-primordials
    const { promise, resolve, reject } = Promise.withResolvers();
    const trackedSyntheticPromise = trackActiveRunSyntheticPass(promise);
    normalizeSyntheticRerunEntry(syntheticRerunEntry);
    reserveSyntheticRerunIdentifiers(syntheticRerunEntry);
    queueMicrotask(() => {
      emitSyntheticRerunPass(syntheticRerunEntry, {
        attempt: rerunMetadata.attempt,
        column: loc?.column,
        file: loc?.file ?? activeRunState?.currentFilePath,
        kind: "suite",
        line: loc?.line,
        nesting: 0,
        passedAttempt: typeof syntheticRerunEntry.passed_on_attempt === "number"
          ? syntheticRerunEntry.passed_on_attempt as number
          : undefined,
        testId: nextActiveRunTestId(),
      }).then(resolve, reject);
    });
    return trackedSyntheticPromise;
  }

  rootHooksPendingCount += 1;
  const scheduledTestId = activeRunState?.rerun ? nextActiveRunTestId() : undefined;
  if (scheduledTestId !== undefined) {
    emitActiveRunEvent(
      "test:enqueue",
      createActiveRunEventData(prepared.name, {
        attempt: rerunMetadata.attempt,
        file: loc?.file ?? activeRunState?.currentFilePath,
        kind: "suite",
        line: loc?.line,
        nesting: 0,
        testId: scheduledTestId,
        column: loc?.column,
      }),
    );
  }

  const denoTestOptions = {
    name: prepared.name,
    fn: wrapSuiteFn(prepared.fn, resolve, {
      attempt: rerunMetadata.attempt,
      filePath: activeRunState?.currentFilePath,
      kind: "suite",
      loc,
      name: prepared.name,
      testId: scheduledTestId,
    }),
    only: prepared.options.only,
    ignore: prepared.options.todo || prepared.options.skip,
    sanitizeOnly: false,
    sanitizeExit: false,
    sanitizeOps: false,
    sanitizeResources: false,
  };
  Deno.test(denoTestOptions);
  return promise;
}

export function test(name, options, fn, overrides) {
  if (currentSuite) {
    return currentSuite.addTest(name, options, fn, overrides);
  }
  return prepareDenoTest(name, options, fn, overrides);
}

test.skip = function skip(name, options, fn) {
  return test(name, options, fn, { skip: true });
};

test.todo = function todo(name, options, fn) {
  return test(name, options, fn, { todo: true });
};

test.only = function only(name, options, fn) {
  return test(name, options, fn, { only: true });
};

export function suite(name, options, fn, overrides) {
  if (currentSuite) {
    return currentSuite.addSuite(name, options, fn, overrides);
  }
  return prepareDenoTestForSuite(name, options, fn, overrides);
}

suite.skip = function skip(name, options, fn) {
  return suite(name, options, fn, { skip: true });
};
suite.todo = function todo(name, options, fn) {
  return suite(name, options, fn, { todo: true });
};
suite.only = function only(name, options, fn) {
  return suite(name, options, fn, { only: true });
};

// Match Node: `it` is just an alias for `test`, and `describe` for `suite`.
// See https://github.com/nodejs/node/blob/main/lib/test.js
export const it = test;
export const describe = suite;

export function getTestContext() {
  return currentTestContext;
}

export function before() {
  if (typeof arguments[0] !== "function") {
    throw new TypeError("before() requires a function");
  }
  ArrayPrototypePush(globalBeforeHooks, arguments[0]);
}

export function after() {
  if (typeof arguments[0] !== "function") {
    throw new TypeError("after() requires a function");
  }
  ArrayPrototypePush(globalAfterHooks, arguments[0]);
}

export function beforeEach(fn) {
  if (typeof fn !== "function") {
    throw new TypeError("beforeEach() requires a function");
  }
  ArrayPrototypePush(globalBeforeEachHooks, fn);
}

export function afterEach(fn) {
  if (typeof fn !== "function") {
    throw new TypeError("afterEach() requires a function");
  }
  ArrayPrototypePush(globalAfterEachHooks, fn);
}

test.it = test;
test.describe = suite;
test.suite = suite;
test.before = before;
test.after = after;
test.beforeEach = beforeEach;
test.afterEach = afterEach;
test.getTestContext = getTestContext;
test.assert = assert;
test.run = run;

// Store all active mocks for restoreAll()
const activeMocks: MockFunctionContext[] = [];

/** Represents a call to a mock function */
interface MockCall {
  arguments: unknown[];
  error?: Error;
  result?: unknown;
  stack: Error;
  target?: unknown;
  this: unknown;
}

/** Context for a mock function with call tracking */
class MockFunctionContext {
  #calls: MockCall[] = [];
  #implementation: ((...args: unknown[]) => unknown) | undefined;
  #restore: (() => void) | undefined;
  #times: number | undefined;

  constructor(
    implementation?: (...args: unknown[]) => unknown,
    restore?: () => void,
    times?: number,
  ) {
    this.#implementation = implementation;
    this.#restore = restore;
    this.#times = times;
  }

  /** Array of call information */
  get calls(): readonly MockCall[] {
    return this.#calls;
  }

  /** Number of times the mock has been called */
  callCount(): number {
    return this.#calls.length;
  }

  /** Reset the call history */
  resetCalls(): void {
    ArrayPrototypeSplice(this.#calls, 0, this.#calls.length);
  }

  /** Restore the original function */
  restore(): void {
    if (this.#restore) {
      this.#restore();
      this.#restore = undefined;
    }
    // Remove from active mocks
    const idx = ArrayPrototypeIndexOf(activeMocks, this);
    if (idx !== -1) {
      ArrayPrototypeSplice(activeMocks, idx, 1);
    }
  }

  /** Internal: record a call */
  _recordCall(
    thisArg: unknown,
    args: unknown[],
    result: unknown,
    error?: Error,
  ): void {
    ArrayPrototypePush(this.#calls, {
      arguments: args,
      error,
      result,
      stack: new Error(),
      this: thisArg,
    });
  }

  /** Internal: check if mock should still be active based on times limit */
  _shouldMock(): boolean {
    if (this.#times === undefined) return true;
    return this.#calls.length < this.#times;
  }

  /** Internal: get the mock implementation */
  _getImplementation(): ((...args: unknown[]) => unknown) | undefined {
    return this.#implementation;
  }
}

/** Creates a mock function wrapper */
function createMockFunction(
  original: ((...args: unknown[]) => unknown) | undefined,
  implementation: ((...args: unknown[]) => unknown) | undefined,
  ctx: MockFunctionContext,
): (...args: unknown[]) => unknown {
  const mockFn = function (this: unknown, ...args: unknown[]): unknown {
    const impl = ctx._shouldMock() ? (implementation ?? original) : original;

    let result: unknown;
    let error: Error | undefined;

    try {
      result = impl ? ReflectApply(impl, this, args) : undefined;
    } catch (e) {
      error = e;
      ctx._recordCall(this, args, undefined, error);
      throw e;
    }

    ctx._recordCall(this, args, result);
    return result;
  };

  // Attach the mock context to the function
  ObjectDefineProperty(mockFn, "mock", {
    __proto__: null,
    value: ctx,
    writable: false,
    enumerable: false,
    configurable: false,
  });

  return mockFn;
}

export const mock = {
  /**
   * Creates a mock function.
   * @param original - Optional original function to wrap
   * @param implementation - Optional mock implementation
   * @param options - Optional configuration
   */
  fn: (
    original?: (...args: unknown[]) => unknown,
    implementation?: (...args: unknown[]) => unknown,
    options?: { times?: number },
  ): ((...args: unknown[]) => unknown) & { mock: MockFunctionContext } => {
    const ctx = new MockFunctionContext(
      implementation ?? original,
      undefined,
      options?.times,
    );
    ArrayPrototypePush(activeMocks, ctx);

    const mockFn = createMockFunction(
      original,
      implementation ?? original,
      ctx,
    );
    return mockFn as ((...args: unknown[]) => unknown) & {
      mock: MockFunctionContext;
    };
  },

  /**
   * Mocks a getter on an object.
   */
  getter: (
    _object: object,
    _methodName: string,
    _implementation?: () => unknown,
    _options?: { times?: number },
  ) => {
    notImplemented("test.mock.getter");
  },

  /**
   * Mocks a method on an object.
   * @param object - The object containing the method
   * @param methodName - The name of the method to mock
   * @param implementation - Optional mock implementation
   * @param options - Optional configuration
   */
  method: <T extends object>(
    object: T,
    methodName: keyof T,
    implementation?: (...args: unknown[]) => unknown,
    options?: { times?: number },
  ): ((...args: unknown[]) => unknown) & { mock: MockFunctionContext } => {
    const original = object[methodName] as (
      ...args: unknown[]
    ) => unknown;

    if (typeof original !== "function") {
      throw new TypeError(
        `Cannot mock property '${
          String(methodName)
        }' because it is not a function`,
      );
    }

    const restore = () => {
      object[methodName] = original as T[keyof T];
    };

    const ctx = new MockFunctionContext(
      implementation,
      restore,
      options?.times,
    );
    ArrayPrototypePush(activeMocks, ctx);

    const mockFn = createMockFunction(original, implementation, ctx);
    object[methodName] = mockFn as T[keyof T];

    return mockFn as ((...args: unknown[]) => unknown) & {
      mock: MockFunctionContext;
    };
  },

  /**
   * Resets the call history of all mocks.
   */
  reset: (): void => {
    ArrayPrototypeForEach(activeMocks, (ctx) => {
      ctx.resetCalls();
    });
  },

  /**
   * Restores all mocked methods to their original implementations.
   */
  restoreAll: (): void => {
    // Restore in reverse order
    while (activeMocks.length > 0) {
      const ctx = activeMocks[activeMocks.length - 1];
      ctx.restore();
    }
  },

  /**
   * Mocks a setter on an object.
   */
  setter: (
    _object: object,
    _methodName: string,
    _implementation?: (value: unknown) => void,
    _options?: { times?: number },
  ) => {
    notImplemented("test.mock.setter");
  },

  timers: {
    enable: () => {
      notImplemented("test.mock.timers.enable");
    },
    reset: () => {
      notImplemented("test.mock.timers.reset");
    },
    tick: () => {
      notImplemented("test.mock.timers.tick");
    },
    runAll: () => {
      notImplemented("test.mock.timers.runAll");
    },
  },
};

test.test = test;
test.mock = mock;

export default test;
