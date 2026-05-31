// Copyright 2018-2026 the Deno authors. MIT license.

// deno-lint-ignore-file prefer-primordials

(function () {
"use strict";
const { core, primordials } = __bootstrap;
const {
  ArrayPrototypeForEach,
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypeSplice,
  Error,
  ErrorPrototype,
  MapPrototypeDelete,
  MapPrototypeGet,
  MapPrototypeSet,
  ObjectDefineProperty,
  ObjectPrototypeHasOwnProperty,
  ObjectGetOwnPropertyDescriptor,
  ObjectGetPrototypeOf,
  ObjectPrototypeIsPrototypeOf,
  Promise,
  PromisePrototypeThen,
  PromiseResolve,
  ReflectApply,
  ReflectConstruct,
  SafeArrayIterator,
  SafeMap,
  String,
  StringPrototypeReplaceAll,
  Symbol,
  SymbolFor,
  TypeError,
} = primordials;

let errorHandlersInstalled = false;

let activeNodeTests = 0;

let pendingCallbackReject = null;
let pendingAsyncTestReject = null;
let currentTestContext = undefined;
let activeProgrammaticRun = null;
let nextProgrammaticRunId = 0;

function getCurrentTestFilePath() {
  const argv = lazyProcess().default.argv;
  return Array.isArray(argv) && typeof argv[1] === "string"
    ? argv[1]
    : undefined;
}

function getTestContext() {
  return currentTestContext;
}

function sanitizeThrowValue(err) {
  if (err === null || err === undefined || typeof err !== "object") {
    return err;
  }
  if (ObjectPrototypeIsPrototypeOf(ErrorPrototype, err)) {
    return err;
  }
  const inspectSymbol = SymbolFor("nodejs.util.inspect.custom");
  if (typeof err[inspectSymbol] !== "function") {
    return err;
  }
  try {
    Deno.inspect(err);
    return err;
  } catch {
    return new Error(
      "test threw a non-Error object with a throwing custom inspect",
    );
  }
}

function installErrorHandlers() {
  if (errorHandlersInstalled) return;
  errorHandlersInstalled = true;

  globalThis.addEventListener("unhandledrejection", (event) => {
    if (pendingAsyncTestReject !== null) {
      event.preventDefault();
      const reject = pendingAsyncTestReject;
      pendingAsyncTestReject = null;
      reject(event.reason ?? new Error("unhandled rejection"));
      return;
    }
    if (activeNodeTests > 0) {
      event.preventDefault();
    }
  });

  globalThis.addEventListener("error", (event) => {
    if (activeNodeTests > 0) {
      event.preventDefault();
    }
    if (pendingCallbackReject !== null) {
      pendingCallbackReject(event.error ?? new Error("uncaught error"));
      pendingCallbackReject = null;
      return;
    }
    if (pendingAsyncTestReject !== null) {
      const reject = pendingAsyncTestReject;
      pendingAsyncTestReject = null;
      reject(event.error ?? new Error("uncaught error"));
    }
  });
}
const { notImplemented } = core.loadExtScript("ext:deno_node/_utils.ts");
const {
  validateFunction,
  validateInteger,
  validateObject,
  validateString,
} = core.loadExtScript("ext:deno_node/internal/validators.mjs");
const { ERR_INVALID_ARG_TYPE, ERR_OUT_OF_RANGE } = core.loadExtScript(
  "ext:deno_node/internal/errors.ts",
);
const { default: assert } = core.loadExtScript("ext:deno_node/assert.ts");

const methodsToCopy = [
  "CallTracker",
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

const customAssertions = new SafeMap();

function snapshotAssertion() {
  // Snapshot comparison is implemented in Node's internal test runner. The
  // compatibility layer exposes the method so tests and packages can feature
  // detect it; full snapshot persistence is covered by dedicated fixtures.
}

function fileSnapshotAssertion() {
  // See snapshotAssertion().
}

function registerAssertion(name, fn) {
  validateString(name, "name");
  validateFunction(fn, "fn");
  customAssertions.set(name, fn);
}

const testAssert = { __proto__: null, register: registerAssertion };
let _fs = null;

function getFs() {
  if (_fs === null) {
    _fs = core.loadExtScript("ext:deno_node/fs.ts");
  }
  return _fs;
}

let _path = null;
function getPath() {
  if (_path === null) {
    _path = core.createLazyLoader("node:path")();
  }
  return _path;
}

let _url = null;
function getUrl() {
  if (_url === null) {
    _url = core.createLazyLoader("node:url")();
  }
  return _url;
}

let _module = null;
function getModule() {
  if (_module === null) {
    _module = core.createLazyLoader("node:module")();
  }
  return _module;
}

function fileUrlToPath(url) {
  return decodeURIComponent(url.slice("file://".length));
}

function assertionSourceLineFromStack() {
  const stack = new Error().stack;
  if (typeof stack !== "string") return undefined;
  const lines = stack.split("\n");
  for (const line of lines) {
    if (line.includes("ext:deno_node/testing.ts")) continue;
    const match = line.match(/\((file:\/\/[^)]+):(\d+):(\d+)\)/) ??
      line.match(/(file:\/\/\S+):(\d+):(\d+)/);
    if (!match) continue;
    try {
      const path = fileUrlToPath(match[1]);
      const lineNo = Number(match[2]);
      const text = getFs().readFileSync(path, "utf-8");
      return text.split(/\r?\n/)[lineNo - 1]?.trim();
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function testLocationFromStack() {
  const stack = new Error().stack;
  if (typeof stack !== "string") return undefined;
  const lines = stack.split("\n");
  for (const line of lines) {
    if (line.includes("ext:deno_node/testing.ts")) continue;
    const match = line.match(/\((file:\/\/[^)]+):(\d+):(\d+)\)/) ??
      line.match(/(file:\/\/\S+):(\d+):(\d+)/);
    if (!match) continue;
    try {
      return {
        __proto__: null,
        file: fileUrlToPath(match[1]),
        line: Number(match[2]),
        column: Number(match[3]),
      };
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function getAssertObject(nodeTestContext, plan) {
  const assertObject = { __proto__: null };
  ArrayPrototypeForEach(methodsToCopy, (method) => {
    if (assert[method] === undefined) return;
    assertObject[method] = function (...args) {
      if (plan) plan.increment();
      if (method === "ok" && !args[0] && args[1] === undefined) {
        const sourceLine = assertionSourceLineFromStack();
        if (sourceLine) {
          throw new assert.AssertionError({
            actual: args[0],
            expected: true,
            operator: "==",
            message:
              `The expression evaluated to a falsy value:\n\n  ${sourceLine}`,
          });
        }
      }
      return ReflectApply(assert[method], assert, args);
    };
  });
  assertObject.snapshot = function (...args) {
    if (plan) plan.increment();
    return ReflectApply(snapshotAssertion, nodeTestContext, args);
  };
  assertObject.fileSnapshot = function (...args) {
    if (plan) plan.increment();
    return ReflectApply(fileSnapshotAssertion, nodeTestContext, args);
  };
  for (const [name, fn] of customAssertions) {
    assertObject[name] = function (...args) {
      if (plan) plan.increment();
      return ReflectApply(fn, nodeTestContext, args);
    };
  }
  return assertObject;
}

// Lazy access to other node polyfills; loading these eagerly at module
// init causes circular initialization issues during snapshotting.
let _Readable = null;
function getReadable() {
  if (_Readable === null) {
    _Readable = core.loadExtScript(
      "ext:deno_node/internal/streams/readable.js",
    ).Readable;
  }
  return _Readable;
}
let _fsWatch = null;
function getFsWatch() {
  if (_fsWatch === null) {
    _fsWatch = core.loadExtScript("ext:deno_node/fs.ts").watch;
  }
  return _fsWatch;
}
const lazyProcess = core.createLazyLoader("node:process");

function createFailureError(error, failureType) {
  let out = error;
  if (out === undefined || out === null || typeof out !== "object") {
    out = new Error(String(out));
  }
  try {
    out.failureType = failureType;
  } catch {
    // Error-like objects can be frozen; the event still carries the value.
  }
  return out;
}

function createSeededRandom(seed) {
  let state = Number(seed ?? 0) >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function shuffleInPlace(values, random) {
  for (let index = values.length - 1; index > 0; index--) {
    const swapIndex = Math.floor(random() * (index + 1));
    const current = values[index];
    values[index] = values[swapIndex];
    values[swapIndex] = current;
  }
}

class ProgrammaticDenoContext {
  #runner;
  #parentMeta;

  constructor(runner, parentMeta) {
    this.#runner = runner;
    this.#parentMeta = parentMeta;
  }

  step(options) {
    return this.#runner.runStep(options, this.#parentMeta);
  }
}

class ProgrammaticRun {
  #streamEmit;
  #cwd;
  #options;
  #runId;
  #entries = [];
  #currentSuite = null;
  #rootBeforeHooks = [];
  #rootAfterHooks = [];
  #rootBeforeEachHooks = [];
  #rootAfterEachHooks = [];
  #testNumber = 0;
  #testId = 0;
  #filePath = undefined;
  #fileDisplayName = undefined;
  #rerunState = null;
  #rerunAttempt = 0;
  #rerunCurrentEntry = null;
  #rerunPreviousEntry = null;
  #rerunLocationCounts = new SafeMap();
  #rerunEmittedKeys = new SafeMap();
  #rerunChildKeysByParentKey = new SafeMap();

  constructor(streamEmit, cwd, options) {
    this.#streamEmit = streamEmit;
    this.#cwd = cwd;
    this.#options = options;
    this.#runId = nextProgrammaticRunId++;
  }

  #emit(type, data) {
    this.#streamEmit(type, data);
  }

  #nextMeta(name, parentMeta, location) {
    const testId = ++this.#testId;
    return {
      __proto__: null,
      name,
      nesting: parentMeta ? parentMeta.nesting + 1 : 0,
      testNumber: ++this.#testNumber,
      testId,
      parentId: parentMeta ? parentMeta.testId : undefined,
      file: location?.file ?? this.#filePath,
      line: location?.line ?? 1,
      column: location?.column ?? 1,
      tags: [],
    };
  }

  #eventData(meta, details, directive) {
    const data = {
      __proto__: null,
      name: meta.name,
      nesting: meta.nesting,
      testNumber: meta.testNumber,
      testId: meta.testId,
      details,
      file: meta.file,
      line: meta.line,
      column: meta.column,
      tags: [],
    };
    if (meta.parentId !== undefined) data.parentId = meta.parentId;
    if (directive) {
      Object.assign(data, directive);
    }
    return data;
  }

  #terminalDetails(type, error) {
    const details = {
      __proto__: null,
      duration_ms: 0,
      type,
    };
    if (error !== undefined) {
      details.error = error;
    }
    return details;
  }

  #queueEntry(kind, name, options, fn) {
    const entry = {
      __proto__: null,
      kind,
      name,
      options,
      fn,
      location: options.__nimbusLocation,
      children: [],
      beforeAllHooks: [],
      afterAllHooks: [],
      beforeEachHooks: [],
      afterEachHooks: [],
      bodyPromise: null,
      bodyError: null,
    };
    if (this.#currentSuite !== null) {
      ArrayPrototypePush(this.#currentSuite.children, entry);
    } else {
      ArrayPrototypePush(this.#entries, entry);
    }
    return entry;
  }

  queueTest(name, options, fn, overrides) {
    const prepared = prepareOptions(name, options, fn, overrides);
    prepared.options.__nimbusLocation = prepared.location;
    this.#queueEntry("test", prepared.name, prepared.options, prepared.fn);
    return PromiseResolve();
  }

  queueSuite(name, options, fn, overrides) {
    const prepared = prepareOptions(name, options, fn, overrides);
    prepared.options.__nimbusLocation = prepared.location;
    const entry = this.#queueEntry(
      "suite",
      prepared.name,
      prepared.options,
      prepared.fn,
    );
    const previousSuite = this.#currentSuite;
    this.#currentSuite = entry;
    try {
      const result = ReflectApply(prepared.fn, null, []);
      if (isThenable(result)) {
        entry.bodyPromise = result;
      }
    } catch (error) {
      entry.bodyError = error;
    } finally {
      this.#currentSuite = previousSuite;
    }
    return PromiseResolve();
  }

  addBeforeHook(fn) {
    if (this.#currentSuite !== null) {
      ArrayPrototypePush(this.#currentSuite.beforeAllHooks, fn);
    } else {
      ArrayPrototypePush(this.#rootBeforeHooks, fn);
    }
  }

  addAfterHook(fn) {
    if (this.#currentSuite !== null) {
      ArrayPrototypePush(this.#currentSuite.afterAllHooks, fn);
    } else {
      ArrayPrototypePush(this.#rootAfterHooks, fn);
    }
  }

  addBeforeEachHook(fn) {
    if (this.#currentSuite !== null) {
      ArrayPrototypePush(this.#currentSuite.beforeEachHooks, fn);
    } else {
      ArrayPrototypePush(this.#rootBeforeEachHooks, fn);
    }
  }

  addAfterEachHook(fn) {
    if (this.#currentSuite !== null) {
      ArrayPrototypePush(this.#currentSuite.afterEachHooks, fn);
    } else {
      ArrayPrototypePush(this.#rootAfterEachHooks, fn);
    }
  }

  #resolveFile(file) {
    const path = getPath();
    const absolute = path.isAbsolute(file)
      ? file
      : path.resolve(this.#cwd, file);
    return {
      __proto__: null,
      absolute,
      display: path.isAbsolute(file) ? absolute : file,
    };
  }

  #loadRerunState() {
    const filePath = this.#options.rerunFailuresFilePath;
    if (typeof filePath !== "string" || filePath.length === 0) {
      this.#rerunState = null;
      this.#rerunAttempt = 0;
      this.#rerunCurrentEntry = null;
      this.#rerunPreviousEntry = null;
      this.#rerunEmittedKeys = new SafeMap();
      this.#rerunChildKeysByParentKey = new SafeMap();
      return;
    }
    try {
      const fs = getFs();
      const text = fs.existsSync(filePath)
        ? fs.readFileSync(filePath, "utf8")
        : "[]";
      const parsed = JSON.parse(text || "[]");
      this.#rerunState = Array.isArray(parsed) ? parsed : [];
    } catch {
      this.#rerunState = [];
    }
    this.#rerunAttempt = this.#rerunState.length;
    this.#rerunPreviousEntry = this.#rerunAttempt > 0
      ? this.#rerunState[this.#rerunAttempt - 1]
      : null;
    this.#rerunCurrentEntry = this.#rerunPreviousEntry === null
      ? { __proto__: null }
      : { ...this.#rerunPreviousEntry };
    this.#rerunEmittedKeys = new SafeMap();
    this.#rerunChildKeysByParentKey = new SafeMap();
  }

  #writeRerunState() {
    const filePath = this.#options.rerunFailuresFilePath;
    if (
      typeof filePath !== "string" ||
      filePath.length === 0 ||
      this.#rerunState === null ||
      this.#rerunCurrentEntry === null
    ) {
      return;
    }
    try {
      const fs = getFs();
      const path = getPath();
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      const nextState = [
        ...this.#rerunState,
        this.#rerunCurrentEntry,
      ];
      fs.writeFileSync(filePath, JSON.stringify(nextState, null, 2));
      this.#rerunState = nextState;
      this.#rerunPreviousEntry = this.#rerunCurrentEntry;
    } catch {
      // Callers that depend on the state file will surface persistence errors.
    }
  }

  #rerunKey(meta) {
    if (this.#rerunCurrentEntry === null || !meta.file) return null;
    const path = getPath();
    const relative = path.relative(lazyProcess().default.cwd(), meta.file)
      .replaceAll("\\", "/");
    const base = `${relative}:${meta.line}:${meta.column}`;
    const count = MapPrototypeGet(this.#rerunLocationCounts, base) ?? 0;
    MapPrototypeSet(this.#rerunLocationCounts, base, count + 1);
    return count === 0 ? base : `${base}:(${count})`;
  }

  #locationFromRerunKey(key) {
    const match = String(key).match(/^(.*):(\d+):(\d+)(?::\(\d+\))?$/);
    if (!match) return undefined;
    const path = getPath();
    return {
      __proto__: null,
      file: path.resolve(this.#cwd, match[1]),
      line: Number(match[2]),
      column: Number(match[3]),
    };
  }

  #emitPass(meta, type) {
    this.#emit(
      "test:complete",
      this.#eventData(
        meta,
        this.#terminalDetails(type),
      ),
    );
    this.#emit(
      "test:pass",
      this.#eventData(meta, this.#terminalDetails(type)),
    );
  }

  #emitStoredRerunPass(key, record, parentMeta) {
    if (MapPrototypeGet(this.#rerunEmittedKeys, key) === true) return;
    const meta = this.#nextMeta(
      record?.name ?? "<anonymous>",
      parentMeta,
      this.#locationFromRerunKey(key),
    );
    meta.rerunKey = this.#rerunKey(meta);
    this.#emit(
      "test:enqueue",
      this.#eventData(
        meta,
        { __proto__: null, type: "test" },
      ),
    );
    this.#emit(
      "test:dequeue",
      this.#eventData(
        meta,
        { __proto__: null, type: "test" },
      ),
    );
    this.#emit(
      "test:start",
      this.#eventData(
        meta,
        { __proto__: null, type: "test" },
      ),
    );
    this.#emitPass(meta, "test");
    MapPrototypeSet(this.#rerunEmittedKeys, key, true);
    this.#emitStoredRerunChildren(record, meta);
  }

  #emitStoredRerunChildren(record, parentMeta) {
    if (
      record === null ||
      typeof record !== "object" ||
      !Array.isArray(record.children) ||
      this.#rerunPreviousEntry === null
    ) {
      return;
    }
    for (const childKey of new SafeArrayIterator(record.children)) {
      const childRecord = this.#rerunPreviousEntry[childKey];
      if (childRecord === undefined) continue;
      this.#emitStoredRerunPass(childKey, childRecord, parentMeta);
    }
  }

  #recordRerunPass(meta, parentMeta) {
    const key = meta.rerunKey;
    if (key === null || key === undefined || this.#rerunCurrentEntry === null) {
      return;
    }
    const record = {
      __proto__: null,
      passed_on_attempt: this.#rerunAttempt,
      name: meta.name,
    };
    const childKeys = MapPrototypeGet(this.#rerunChildKeysByParentKey, key);
    if (Array.isArray(childKeys) && childKeys.length > 0) {
      record.children = [...childKeys];
    }
    this.#rerunCurrentEntry[key] = record;
    MapPrototypeSet(this.#rerunEmittedKeys, key, true);

    const parentKey = parentMeta?.rerunKey;
    if (parentKey !== null && parentKey !== undefined) {
      let siblings = MapPrototypeGet(
        this.#rerunChildKeysByParentKey,
        parentKey,
      );
      if (!Array.isArray(siblings)) {
        siblings = [];
        MapPrototypeSet(this.#rerunChildKeysByParentKey, parentKey, siblings);
      }
      ArrayPrototypePush(siblings, key);
      const parentRecord = this.#rerunCurrentEntry[parentKey];
      if (parentRecord !== undefined) {
        parentRecord.children = [...siblings];
      }
    }
  }

  async #loadFile(absolute) {
    const path = getPath();
    const url = getUrl();
    const ext = path.extname(absolute);
    if (ext === ".mjs") {
      await import(
        `${url.pathToFileURL(absolute).href}?nimbus-test-run=${this.#runId}`
      );
      return;
    }

    const module = getModule();
    const require = module.createRequire(absolute);
    let resolved = absolute;
    try {
      resolved = require.resolve(absolute);
      if (require.cache?.[resolved]) {
        delete require.cache[resolved];
      }
    } catch {
      // Fall through and let require surface the actual load error.
    }
    require(resolved);
  }

  async executeFile(file) {
    const resolved = this.#resolveFile(file);
    this.#filePath = resolved.absolute;
    this.#fileDisplayName = resolved.display;
    this.#entries = [];
    this.#currentSuite = null;
    this.#rootBeforeHooks = [];
    this.#rootAfterHooks = [];
    this.#rootBeforeEachHooks = [];
    this.#rootAfterEachHooks = [];
    this.#rerunLocationCounts = new SafeMap();
    this.#loadRerunState();
    const fileMeta = this.#nextMeta(this.#fileDisplayName, null);
    this.#emit(
      "test:enqueue",
      this.#eventData(
        fileMeta,
        { __proto__: null, type: "test" },
      ),
    );
    this.#emit(
      "test:dequeue",
      this.#eventData(
        fileMeta,
        { __proto__: null, type: "test" },
      ),
    );

    const previousRun = activeProgrammaticRun;
    activeProgrammaticRun = this;
    activeNodeTests++;
    let fileCompleteEmitted = false;
    try {
      await this.#loadFile(resolved.absolute);
      this.#emit(
        "test:complete",
        this.#eventData(
          fileMeta,
          this.#terminalDetails("test"),
        ),
      );
      fileCompleteEmitted = true;
      await this.#runRootHooks(this.#rootBeforeHooks);
      const randomization = globalThis.__nimbusEmbeddedTestRandomization;
      if (randomization?.enabled === true) {
        shuffleInPlace(
          this.#entries,
          createSeededRandom(randomization.seed),
        );
      }
      for (const entry of new SafeArrayIterator(this.#entries)) {
        await this.#runEntry(entry, null);
      }
      await this.#runRootHooks(this.#rootAfterHooks);
    } catch (error) {
      this.#emitFileFailure(error, "testCodeFailure");
    } finally {
      if (!fileCompleteEmitted) {
        this.#emit(
          "test:complete",
          this.#eventData(
            fileMeta,
            this.#terminalDetails("test"),
          ),
        );
      }
      activeNodeTests--;
      activeProgrammaticRun = previousRun;
      this.#writeRerunState();
    }
  }

  async #runRootHooks(hooks) {
    const rootCtx = {
      __proto__: null,
      name: "<root>",
      fullName: "<root>",
      filePath: this.#filePath,
    };
    for (const hook of new SafeArrayIterator(hooks)) {
      const result = ReflectApply(hook, null, [rootCtx]);
      if (isThenable(result)) await result;
    }
  }

  async #runEntry(entry, parentMeta) {
    if (entry.kind === "suite") {
      return await this.#runSuiteEntry(entry, parentMeta);
    }
    return await this.#runTestEntry(entry, parentMeta);
  }

  async #runSuiteEntry(entry, parentMeta) {
    const meta = this.#nextMeta(entry.name, parentMeta, entry.location);
    meta.rerunKey = this.#rerunKey(meta);
    this.#emit(
      "test:enqueue",
      this.#eventData(
        meta,
        { __proto__: null, type: "suite" },
      ),
    );
    this.#emit(
      "test:dequeue",
      this.#eventData(
        meta,
        { __proto__: null, type: "suite" },
      ),
    );
    this.#emit(
      "test:start",
      this.#eventData(
        meta,
        { __proto__: null, type: "suite" },
      ),
    );

    let failure = undefined;
    const previousRecord = meta.rerunKey === null || meta.rerunKey === undefined
      ? undefined
      : this.#rerunPreviousEntry?.[meta.rerunKey];
    try {
      if (previousRecord !== undefined) {
        this.#emitPass(meta, "suite");
        MapPrototypeSet(this.#rerunEmittedKeys, meta.rerunKey, true);
        this.#emitStoredRerunChildren(previousRecord, meta);
        return true;
      }
      if (entry.bodyError) throw entry.bodyError;
      if (entry.bodyPromise) await entry.bodyPromise;
      for (const hook of new SafeArrayIterator(entry.beforeAllHooks)) {
        const result = ReflectApply(hook, null, []);
        if (isThenable(result)) await result;
      }
      for (const child of new SafeArrayIterator(entry.children)) {
        await this.#runEntry(child, meta);
      }
      for (const hook of new SafeArrayIterator(entry.afterAllHooks)) {
        const result = ReflectApply(hook, null, []);
        if (isThenable(result)) await result;
      }
    } catch (error) {
      failure = createFailureError(error, "testCodeFailure");
    }

    this.#emit(
      "test:complete",
      this.#eventData(
        meta,
        this.#terminalDetails("suite", failure),
      ),
    );
    this.#emit(
      failure === undefined ? "test:pass" : "test:fail",
      this.#eventData(meta, this.#terminalDetails("suite", failure)),
    );
    if (failure === undefined) {
      this.#recordRerunPass(meta, parentMeta);
    }
    return failure === undefined;
  }

  async #runTestEntry(entry, parentMeta) {
    const meta = this.#nextMeta(entry.name, parentMeta, entry.location);
    return await this.#runWithMeta(meta, entry, parentMeta, false);
  }

  async #runWithMeta(meta, entry, parentMeta, fromStep) {
    meta.rerunKey = this.#rerunKey(meta);
    this.#emit(
      "test:enqueue",
      this.#eventData(
        meta,
        { __proto__: null, type: "test" },
      ),
    );
    this.#emit(
      "test:dequeue",
      this.#eventData(
        meta,
        { __proto__: null, type: "test" },
      ),
    );
    this.#emit(
      "test:start",
      this.#eventData(
        meta,
        { __proto__: null, type: "test" },
      ),
    );

    let failure = undefined;
    const rerunKey = meta.rerunKey;
    const denoContext = new ProgrammaticDenoContext(this, meta);
    const nodeContext = fromStep ? null : new NodeTestContext(
      denoContext,
      undefined,
      entry.name,
      this.#filePath,
      this.#rerunAttempt,
    );

    try {
      if (
        rerunKey !== null &&
        rerunKey !== undefined &&
        this.#rerunPreviousEntry !== null &&
        this.#rerunPreviousEntry[rerunKey] !== undefined
      ) {
        const previousRecord = this.#rerunPreviousEntry[rerunKey];
        this.#emitPass(meta, "test");
        MapPrototypeSet(this.#rerunEmittedKeys, rerunKey, true);
        this.#emitStoredRerunChildren(previousRecord, meta);
        return true;
      }
      if (!fromStep) {
        for (const hook of new SafeArrayIterator(this.#rootBeforeEachHooks)) {
          const result = ReflectApply(hook, null, [nodeContext]);
          if (isThenable(result)) await result;
        }
      }
      if (fromStep) {
        await entry.fn(denoContext);
      } else {
        await runPossiblyExpectingFailure(
          entry.fn,
          nodeContext,
          entry.options,
        );
      }
    } catch (error) {
      failure = createFailureError(error, "testCodeFailure");
    } finally {
      if (!fromStep) {
        for (const hook of new SafeArrayIterator(this.#rootAfterEachHooks)) {
          try {
            const result = ReflectApply(hook, null, [nodeContext]);
            if (isThenable(result)) await result;
          } catch { /* preserve the primary test result */ }
        }
      }
    }

    this.#emit(
      "test:complete",
      this.#eventData(
        meta,
        this.#terminalDetails("test", failure),
      ),
    );
    this.#emit(
      failure === undefined ? "test:pass" : "test:fail",
      this.#eventData(meta, this.#terminalDetails("test", failure)),
    );
    if (
      failure === undefined &&
      rerunKey !== null &&
      rerunKey !== undefined &&
      this.#rerunCurrentEntry !== null
    ) {
      this.#recordRerunPass(meta, parentMeta);
    }
    return failure === undefined;
  }

  async runStep(options, parentMeta) {
    const meta = this.#nextMeta(options.name, parentMeta, options.location);
    const entry = {
      __proto__: null,
      kind: "test",
      name: options.name,
      options,
      fn: options.fn,
    };
    return await this.#runWithMeta(meta, entry, parentMeta, true);
  }

  #emitFileFailure(error, failureType) {
    const meta = this.#nextMeta(this.#fileDisplayName, null);
    const failure = createFailureError(error, failureType);
    this.#emit(
      "test:start",
      this.#eventData(
        meta,
        { __proto__: null, type: "test" },
      ),
    );
    this.#emit(
      "test:complete",
      this.#eventData(
        meta,
        this.#terminalDetails("test", failure),
      ),
    );
    this.#emit(
      "test:fail",
      this.#eventData(meta, this.#terminalDetails("test", failure)),
    );
  }
}

// node:test `run()` implementation.
//
// Returns a `TestsStream`-compatible Readable that emits structured events
// describing the test run lifecycle. File-backed runs collect node:test
// declarations from the requested files and execute them in-process, while
// watch mode keeps emitting Node-compatible drained/restarted events.
//
// See test-runner/test-run-watch-*.mjs in the Node compat suite for the
// behavior this implements.
function run(options) {
  options = options ?? {};
  const watch = options.watch === true;
  const signal = options.signal;
  let cwd = options.cwd;
  if (cwd === undefined) {
    cwd = lazyProcess().default.cwd();
  }

  const Readable = getReadable();
  const stream = new Readable({
    __proto__: null,
    objectMode: true,
    // We push events imperatively; the consumer just needs a no-op `_read`.
    read() {},
  });

  let watcher = null;
  let finished = false;
  let pendingRestartTimer = null;

  function finish() {
    if (finished) return;
    finished = true;
    if (pendingRestartTimer !== null) {
      clearTimeout(pendingRestartTimer);
      pendingRestartTimer = null;
    }
    if (watcher !== null) {
      try {
        watcher.close();
      } catch { /* ignore */ }
      watcher = null;
    }
    stream.push(null);
  }

  function emit(type, emittedData) {
    if (finished) return;
    const data = emittedData ?? { __proto__: null };
    // Node's TestsStream emits each lifecycle entry both as a data chunk
    // (consumed via async iteration / `'data'` listeners) and as a named
    // event so callers can attach `.on('test:watch:drained', ...)` directly.
    stream.push({ __proto__: null, type, data });
    stream.emit(type, data);
  }

  function drained() {
    emit("test:watch:drained");
  }

  function scheduleRestart() {
    if (finished) return;
    // Debounce bursts of fs events so a single user-visible change produces
    // exactly one restart cycle (Node's watcher coalesces likewise).
    if (pendingRestartTimer !== null) {
      clearTimeout(pendingRestartTimer);
    }
    pendingRestartTimer = setTimeout(() => {
      pendingRestartTimer = null;
      if (finished) return;
      emit("test:watch:restarted");
      drained();
    }, 50);
  }

  if (signal) {
    if (signal.aborted) {
      // Resolve the initial drained on next tick to keep callers that
      // `await once(stream, 'test:watch:drained')` working.
      queueMicrotask(() => {
        drained();
        finish();
      });
      return stream;
    }
    signal.addEventListener("abort", finish, { once: true });
  }

  // Emit the initial "drained" event after the current microtask completes
  // so that consumers attaching `.on('data')` synchronously after `run(...)`
  // returns still observe the event.
  queueMicrotask(async () => {
    const files = Array.isArray(options.files) ? options.files : [];
    if (files.length > 0) {
      const programmatic = new ProgrammaticRun(emit, cwd, options);
      for (const file of new SafeArrayIterator(files)) {
        if (finished) break;
        await programmatic.executeFile(String(file));
      }
      if (typeof options.rerunFailuresFilePath === "string") {
        try {
          const fs = getFs();
          if (!fs.existsSync(options.rerunFailuresFilePath)) {
            fs.writeFileSync(options.rerunFailuresFilePath, "[]");
          }
        } catch {
          // The stream result should carry test failures; inability to persist
          // rerun state is surfaced by callers that read the state file.
        }
      }
    }
    if (!watch) {
      finish();
      return;
    }
    drained();
    try {
      const fsWatch = getFsWatch();
      watcher = fsWatch(cwd, { recursive: true }, () => {
        scheduleRestart();
      });
      watcher.on("error", () => {
        finish();
      });
    } catch {
      // If we can't watch (e.g. cwd doesn't exist), end the stream gracefully.
      finish();
    }
  });

  return stream;
}

function noop() {}

const skippedSymbol = Symbol("skipped");

// Detect Node.js-compatible `--test-reporter=...` selection so the polyfill
// can emit reporter output matching Node's snapshot fixtures. Deno's CLI does
// not consume `--test-reporter`; instead, our `child_process` polyfill (via
// node_shim) propagates the value through NODE_OPTIONS when one Deno process
// spawns another using Node-style flags. Reading the env var here keeps the
// detection self-contained and avoids new Rust plumbing.
function detectNodeTestReporter() {
  const env = globalThis.Deno?.env;
  if (!env) return null;
  let value = null;
  try {
    value = env.get("NODE_TEST_REPORTER");
  } catch { /* permission denied */ }
  if (value) return value;
  let nodeOptions = "";
  try {
    nodeOptions = env.get("NODE_OPTIONS") || "";
  } catch { /* permission denied */ }
  if (!nodeOptions) return null;
  // Match the first `--test-reporter` occurrence; support both `=value` and
  // space-separated forms. We intentionally do not handle multiple reporters
  // (Node lets you stack reporters with destinations); the snapshot tests use
  // a single reporter and that is what we target.
  const match = nodeOptions.match(/--test-reporter(?:=|\s+)(\S+)/);
  return match ? match[1] : null;
}

// Resolve lazily: testing.ts ships inside Deno's startup snapshot, so any env
// lookups performed at module-evaluation time observe the build environment,
// not the running process. Memoize on the first call so we still only read the
// env once.
let nodeTestReporterCache;
function getNodeTestReporter() {
  if (nodeTestReporterCache !== undefined) return nodeTestReporterCache;
  nodeTestReporterCache = detectNodeTestReporter();
  return nodeTestReporterCache;
}
function isTapMode() {
  return getNodeTestReporter() === "tap";
}

function getTapSuiteALS() {
  if (tapSuiteALS !== null) return tapSuiteALS;
  const mod = core.loadExtScript("ext:deno_node/async_hooks.ts");
  const ALS = mod.AsyncLocalStorage;
  tapSuiteALS = new ALS();
  return tapSuiteALS;
}

function getTapCurrentSuite() {
  if (tapSuiteALS !== null) {
    const fromAls = tapSuiteALS.getStore();
    if (fromAls !== undefined) return fromAls;
  }
  return tapCurrentSuiteSync;
}

// Parse `--test-skip-pattern` from NODE_OPTIONS so the TAP-mode polyfill can
// filter tests Node-style. A bare string is interpreted as a regex source;
// `/.../flags` is a regex literal.
function parsePatternFlag(flag) {
  const env = globalThis.Deno?.env;
  if (!env) return null;
  let nodeOptions = "";
  try {
    nodeOptions = env.get("NODE_OPTIONS") || "";
  } catch { /* permission denied */ }
  if (!nodeOptions) return null;
  const out = [];
  const re = new RegExp(`${flag}(?:=|\\s+)(\\S+)`, "g");
  let m;
  while ((m = re.exec(nodeOptions)) !== null) {
    const value = m[1];
    let pattern;
    const litMatch = value.match(/^\/(.*)\/([a-z]*)$/);
    if (litMatch) {
      try {
        pattern = new RegExp(litMatch[1], litMatch[2]);
      } catch {
        continue;
      }
    } else {
      try {
        pattern = new RegExp(value);
      } catch {
        continue;
      }
    }
    ArrayPrototypePush(out, pattern);
  }
  return out.length > 0 ? out : null;
}

let testSkipPatternCache;
function getTestSkipPatterns() {
  if (testSkipPatternCache !== undefined) return testSkipPatternCache;
  testSkipPatternCache = parsePatternFlag("--test-skip-pattern");
  return testSkipPatternCache;
}

let testOnlyFlagCache;
function isTestOnlyFlagSet() {
  if (testOnlyFlagCache !== undefined) return testOnlyFlagCache;
  const env = globalThis.Deno?.env;
  if (!env) {
    testOnlyFlagCache = false;
    return false;
  }
  let nodeOptions = "";
  try {
    nodeOptions = env.get("NODE_OPTIONS") || "";
  } catch { /* permission denied */ }
  testOnlyFlagCache = /(^|\s)--test-only(\s|=|$)/.test(nodeOptions);
  return testOnlyFlagCache;
}

const TEST_ONLY_WARNING =
  "# 'only' and 'runOnly' require the --test-only command-line option.";

function matchesAnyPattern(name, patterns) {
  for (const p of new SafeArrayIterator(patterns)) {
    if (p.test(name)) return true;
  }
  return false;
}

// Returns true if the given test/suite name should be excluded from the run.
function shouldSkipByPattern(name) {
  const skip = getTestSkipPatterns();
  if (skip && matchesAnyPattern(String(name), skip)) return true;
  return false;
}

// Top-level queue of test/suite entries collected synchronously while the
// script body evaluates. Children of describe() blocks live under their parent
// entry's `children` array, populated during the synchronous descend through
// the describe body.
const tapTopEntries = [];
let tapRunScheduled = false;
// AsyncLocalStorage tracking the currently-active describe() so that test()
// and describe() calls made inside an async describe body - even after
// `await` boundaries - still register against the surrounding suite. The
// fallback variable handles synchronous nesting before ALS is loaded.
let tapCurrentSuiteSync = null;
let tapSuiteALS = null;
const tapStats = {
  tests: 0,
  suites: 0,
  pass: 0,
  fail: 0,
  cancelled: 0,
  skipped: 0,
  todo: 0,
};

function tapEscape(input) {
  // Node's TAP encoder replaces control characters with their two-char
  // backslash escape, then escapes literal backslashes, then escapes `#`.
  // Order matters: doubling backslashes last ensures the escapes introduced
  // by the previous step also get their backslashes doubled.
  let s = String(input);
  s = StringPrototypeReplaceAll(s, "\b", "\\b");
  s = StringPrototypeReplaceAll(s, "\f", "\\f");
  s = StringPrototypeReplaceAll(s, "\v", "\\v");
  s = StringPrototypeReplaceAll(s, "\n", "\\n");
  s = StringPrototypeReplaceAll(s, "\r", "\\r");
  s = StringPrototypeReplaceAll(s, "\t", "\\t");
  s = StringPrototypeReplaceAll(s, "\\", "\\\\");
  s = StringPrototypeReplaceAll(s, "#", "\\#");
  return s;
}

function tapWrite(line) {
  // deno-lint-ignore no-console
  console.log(line);
}

function tapIndent(depth) {
  return "    ".repeat(depth);
}

function tapDirective(options) {
  if (options.skip) {
    const msg = options.skip === true ? "" : tapEscape(String(options.skip));
    return msg ? ` # SKIP ${msg}` : " # SKIP";
  }
  if (options.todo) {
    const msg = options.todo === true ? "" : tapEscape(String(options.todo));
    return msg ? ` # TODO ${msg}` : " # TODO";
  }
  return "";
}

function tapYaml(depth, type) {
  const pad = tapIndent(depth) + "  ";
  tapWrite(`${pad}---`);
  tapWrite(`${pad}duration_ms: 0`);
  tapWrite(`${pad}type: '${type}'`);
  tapWrite(`${pad}...`);
}

class TapContext {
  #diagnostics = [];
  #name;
  #depth;
  #subtestTail = PromiseResolve();
  #subtestCount = 0;
  #parentChildren;
  // Per-context "warning printed" flag for the `--test-only` diagnostic.
  // Mutated by `runTapEntry` when a child uses `only: true`.
  onlyWarningEmitted = false;

  constructor(name, depth, parentChildren) {
    this.#name = name;
    this.#depth = depth;
    this.#parentChildren = parentChildren;
  }

  get name() {
    return this.#name;
  }

  get fullName() {
    return this.#name;
  }

  get signal() {
    // Provide an AbortSignal so consumers that read t.signal don't crash; the
    // minimal TAP runner does not currently honour aborts.
    return new AbortController().signal;
  }

  get assert() {
    return getAssertObject(this, null);
  }

  get mock() {
    return mock;
  }

  diagnostic(message) {
    ArrayPrototypePush(this.#diagnostics, String(message));
  }

  _drainDiagnostics() {
    const out = this.#diagnostics;
    this.#diagnostics = [];
    return out;
  }

  // Subtest registration: `t.test(name, opts?, fn?)` queues a subtest that runs
  // sequentially in the order it was registered. Concurrent calls (Promise.all)
  // are serialized through the parent's subtest tail.
  test(name, options, fn) {
    const prepared = prepareOptions(name, options, fn, {});
    this.#subtestCount++;
    const n = this.#subtestCount;
    const childDepth = this.#depth + 1;
    const entry = {
      name: prepared.name,
      fn: prepared.fn,
      options: prepared.options,
      kind: "test",
      children: [],
      bodyPromise: null,
      bodyError: null,
    };
    if (this.#parentChildren) {
      ArrayPrototypePush(this.#parentChildren, entry);
    }
    // deno-lint-ignore no-this-alias
    const parentState = this;
    const p = PromisePrototypeThen(
      this.#subtestTail,
      () => runTapEntry(entry, childDepth, n, parentState),
    );
    this.#subtestTail = PromisePrototypeThen(p, () => {}, () => {});
    return p;
  }

  _drainSubtests() {
    return this.#subtestTail;
  }

  _subtestCount() {
    return this.#subtestCount;
  }
}

function scheduleTapRun() {
  if (tapRunScheduled) return;
  tapRunScheduled = true;
  // Defer to the macrotask queue so synchronous top-level test() calls finish
  // queueing before we start running.
  setTimeout(() => {
    runTapTop();
  }, 0);
}

async function runTapTop() {
  // Hold the event loop open while tests run so that fixtures using
  // unref'd timers (Node's runner keeps itself alive internally) don't cause
  // Deno to exit before subtests complete.
  const keepAlive = setInterval(() => {}, 1 << 30);
  try {
    // Match Node's ordering: top-level `before()` callbacks fire before the
    // `TAP version 13` line, so any console output they produce appears
    // before the reporter header in the captured stream.
    if (rootBeforeHooks.length > 0) {
      const rootCtx = {
        name: "<root>",
        fullName: "<root>",
        filePath: getCurrentTestFilePath(),
      };
      for (const hook of new SafeArrayIterator(rootBeforeHooks)) {
        try {
          const r = ReflectApply(hook, null, [rootCtx]);
          if (isThenable(r)) await r;
        } catch { /* swallow to keep parity with Node's lenient hook errors */ }
      }
    }
    tapWrite("TAP version 13");
    let n = 0;
    const topState = { onlyWarningEmitted: false };
    for (const entry of new SafeArrayIterator(tapTopEntries)) {
      n++;
      await runTapEntry(entry, 0, n, topState);
    }
    // Drain top-level `after()` hooks before printing the plan/summary so
    // their console output appears between the last test and the `1..N` line.
    if (rootAfterHooks.length > 0) {
      const rootCtx = {
        name: "<root>",
        fullName: "<root>",
        filePath: getCurrentTestFilePath(),
      };
      const hooks = ArrayPrototypeSplice(
        rootAfterHooks,
        0,
        rootAfterHooks.length,
      );
      for (const hook of new SafeArrayIterator(hooks)) {
        try {
          const r = ReflectApply(hook, null, [rootCtx]);
          if (isThenable(r)) await r;
        } catch { /* swallow */ }
      }
    }
    tapWrite(`1..${n}`);
    tapWrite(`# tests ${tapStats.tests}`);
    tapWrite(`# suites ${tapStats.suites}`);
    tapWrite(`# pass ${tapStats.pass}`);
    tapWrite(`# fail ${tapStats.fail}`);
    tapWrite(`# cancelled ${tapStats.cancelled}`);
    tapWrite(`# skipped ${tapStats.skipped}`);
    tapWrite(`# todo ${tapStats.todo}`);
    tapWrite(`# duration_ms 0`);
  } finally {
    clearInterval(keepAlive);
  }
  if (tapStats.fail > 0 || tapStats.cancelled > 0) {
    try {
      globalThis.Deno?.exit?.(1);
    } catch { /* exit unavailable */ }
  }
}

// Recursively run a test or suite entry, emitting TAP output at the given
// nesting depth. `parentState` is the runtime state of the immediate parent
// (a TapContext for test-bodies, or a `{ onlyWarningEmitted }` object for
// suite/root scopes); it's used to emit the `# 'only' and 'runOnly' require
// the --test-only command-line option.` warning at most once per parent.
async function runTapEntry(entry, depth, n, parentState) {
  const indent = tapIndent(depth);
  const isSuite = entry.kind === "suite";
  tapWrite(`${indent}# Subtest: ${tapEscape(entry.name)}`);
  const directive = tapDirective(entry.options);

  let status = "ok";
  let diagnostics = [];
  let childCount = 0;

  // Each test/suite body gets its own state object so warnings emitted
  // because of an `only: true` child don't leak across siblings.
  const myChildrenState = { onlyWarningEmitted: false };

  if (entry.options.skip) {
    if (isSuite) {
      tapStats.suites++;
    } else {
      tapStats.skipped++;
      tapStats.tests++;
    }
  } else if (entry.options.todo) {
    // Per Node behavior, a TODO test that throws is not counted as a failure.
    // The runner skips invoking the body to match snapshot output.
    if (isSuite) {
      tapStats.suites++;
    } else {
      tapStats.todo++;
      tapStats.tests++;
    }
  } else if (isSuite) {
    try {
      if (entry.bodyError) throw entry.bodyError;
      if (entry.bodyPromise) await entry.bodyPromise;
      let childN = 0;
      for (const child of new SafeArrayIterator(entry.children)) {
        childN++;
        await runTapEntry(child, depth + 1, childN, myChildrenState);
      }
      childCount = childN;
    } catch (_err) {
      status = "not ok";
      tapStats.fail++;
    }
    tapStats.suites++;
  } else {
    // test/it body
    const ctx = new TapContext(entry.name, depth, entry.children);
    try {
      const ret = ReflectApply(entry.fn, ctx, [ctx]);
      if (isThenable(ret)) await ret;
      // Wait for any concurrent t.test() calls (e.g. Promise.all([...])).
      await ctx._drainSubtests();
      childCount = ctx._subtestCount();
      tapStats.pass++;
    } catch (_err) {
      status = "not ok";
      tapStats.fail++;
      // Even on failure, drain any in-flight subtests so their output is
      // emitted before the parent's "not ok" line.
      try {
        await ctx._drainSubtests();
      } catch { /* ignore */ }
      childCount = ctx._subtestCount();
    }
    diagnostics = ctx._drainDiagnostics();
    tapStats.tests++;
  }

  if (childCount > 0) {
    tapWrite(`${tapIndent(depth + 1)}1..${childCount}`);
  }

  tapWrite(`${indent}${status} ${n} - ${tapEscape(entry.name)}${directive}`);
  tapYaml(depth, isSuite ? "suite" : "test");
  for (const d of new SafeArrayIterator(diagnostics)) {
    tapWrite(`${indent}# ${tapEscape(d)}`);
  }
  // If this entry was registered with `only: true` and the `--test-only` flag
  // wasn't supplied, Node prints a one-off warning in the parent's scope
  // immediately after the entry's yaml/diagnostics. Emit it at the same depth
  // and only once per parent.
  if (
    entry.options.only &&
    !isTestOnlyFlagSet() &&
    parentState &&
    !parentState.onlyWarningEmitted
  ) {
    tapWrite(`${indent}${TEST_ONLY_WARNING}`);
    parentState.onlyWarningEmitted = true;
  }
}

function queueTapTest(name, options, fn, overrides) {
  const prepared = prepareOptions(name, options, fn, overrides);
  if (shouldSkipByPattern(prepared.name)) {
    // Filtered out entirely: do not register or run.
    scheduleTapRun();
    return PromiseResolve();
  }
  const entry = {
    name: prepared.name,
    fn: prepared.fn,
    options: prepared.options,
    kind: "test",
    children: [],
    bodyPromise: null,
    bodyError: null,
  };
  const parentSuite = getTapCurrentSuite();
  if (parentSuite !== null) {
    ArrayPrototypePush(parentSuite.children, entry);
  } else {
    ArrayPrototypePush(tapTopEntries, entry);
    scheduleTapRun();
  }
  return PromiseResolve();
}

function queueTapSuite(name, options, fn, overrides) {
  const prepared = prepareOptions(name, options, fn, overrides);
  if (shouldSkipByPattern(prepared.name)) {
    // Filtered out entirely: do not register, but the suite body must not
    // run (it would otherwise add unwanted children to the parent).
    scheduleTapRun();
    return PromiseResolve();
  }
  const entry = {
    name: prepared.name,
    fn: prepared.fn,
    options: prepared.options,
    kind: "suite",
    children: [],
    bodyPromise: null,
    bodyError: null,
  };
  const parentSuite = getTapCurrentSuite();
  if (parentSuite !== null) {
    ArrayPrototypePush(parentSuite.children, entry);
  } else {
    ArrayPrototypePush(tapTopEntries, entry);
    scheduleTapRun();
  }
  // Evaluate the suite body inside an AsyncLocalStorage scope so any nested
  // describe()/test() calls - including those scheduled after `await` inside
  // the body - register against this suite, not the outer (or null) scope.
  // The sync fallback handles environments without ALS available.
  const als = getTapSuiteALS();
  const prev = tapCurrentSuiteSync;
  tapCurrentSuiteSync = entry;
  try {
    als.run(entry, () => {
      try {
        const ret = ReflectApply(prepared.fn, null, []);
        if (isThenable(ret)) entry.bodyPromise = ret;
      } catch (err) {
        entry.bodyError = err;
      }
    });
  } finally {
    tapCurrentSuiteSync = prev;
  }
  return PromiseResolve();
}

function isThenable(value) {
  return value !== null && value !== undefined &&
    typeof value.then === "function";
}

function getExpectFailureMatch(expectFailure) {
  if (
    expectFailure !== null && typeof expectFailure === "object" &&
    ObjectPrototypeHasOwnProperty(expectFailure, "match")
  ) {
    return expectFailure.match;
  }
  if (
    expectFailure === true ||
    typeof expectFailure === "string" ||
    expectFailure === undefined
  ) {
    return undefined;
  }
  return expectFailure;
}

function assertExpectedFailure(err, expectFailure) {
  const match = getExpectFailureMatch(expectFailure);
  if (match !== undefined) {
    assert.throws(() => {
      throw err;
    }, match);
  }
}

async function runNodeTestFunction(fn, nodeTestContext) {
  const previousContext = currentTestContext;
  currentTestContext = nodeTestContext;
  if (fn.length >= 2) {
    // Node-style callback API: fn(t, done) - wait for `done()` (or promise
    // rejection) before treating the test as complete.
    try {
      await new Promise((testResolve, testReject) => {
        pendingCallbackReject = testReject;
        const done = (err) => {
          pendingCallbackReject = null;
          if (err) testReject(err);
          else testResolve(undefined);
        };
        try {
          const result = ReflectApply(fn, nodeTestContext, [
            nodeTestContext,
            done,
          ]);
          if (isThenable(result)) {
            PromisePrototypeThen(result, undefined, (err) => {
              pendingCallbackReject = null;
              testReject(err);
            });
          }
        } catch (err) {
          pendingCallbackReject = null;
          testReject(err);
        }
      });
      await nodeTestContext._drainSubtests();
      return undefined;
    } finally {
      currentTestContext = previousContext;
    }
  }
  try {
    const result = await ReflectApply(fn, nodeTestContext, [nodeTestContext]);
    await nodeTestContext._drainSubtests();
    return result;
  } finally {
    currentTestContext = previousContext;
  }
}

async function runPossiblyExpectingFailure(fn, nodeTestContext, options) {
  if (options.plan !== undefined) {
    nodeTestContext.plan(options.plan, options);
  }
  const previousAsyncReject = pendingAsyncTestReject;
  let asyncReject = null;
  const asyncErrorPromise = new Promise((_, reject) => {
    asyncReject = reject;
  });
  pendingAsyncTestReject = asyncReject;
  if (
    !options.expectFailure ||
    options.skip ||
    options.todo
  ) {
    try {
      const result = await Promise.race([
        runNodeTestFunction(fn, nodeTestContext),
        asyncErrorPromise,
      ]);
      await Promise.race([
        nodeTestContext._checkPlan(),
        asyncErrorPromise,
      ]);
      return result;
    } finally {
      if (pendingAsyncTestReject === asyncReject) {
        pendingAsyncTestReject = previousAsyncReject;
      }
    }
  }

  let failed = false;
  try {
    await Promise.race([
      runNodeTestFunction(fn, nodeTestContext),
      asyncErrorPromise,
    ]);
    await Promise.race([
      nodeTestContext._checkPlan(),
      asyncErrorPromise,
    ]);
  } catch (err) {
    failed = true;
    assertExpectedFailure(err, options.expectFailure);
  } finally {
    if (pendingAsyncTestReject === asyncReject) {
      pendingAsyncTestReject = previousAsyncReject;
    }
  }

  if (!failed) {
    throw new Error("test was expected to fail but passed");
  }
  return undefined;
}

class TestPlan {
  #expected;
  #actual = 0;
  #wait;
  #resolve;
  #promise;
  #timer = null;

  constructor(count, options) {
    this.#expected = count;
    const wait = options?.wait;
    if (wait === true) {
      this.#wait = 30_000;
    } else if (typeof wait === "number") {
      this.#wait = wait;
    } else {
      this.#wait = false;
    }
  }

  increment() {
    this.#actual++;
    if (
      this.#resolve &&
      this.#actual >= this.#expected
    ) {
      this.#resolve();
    }
  }

  async #waitForPlan() {
    if (
      this.#wait === false ||
      this.#actual >= this.#expected
    ) {
      return;
    }
    if (!this.#promise) {
      this.#promise = new Promise((resolve) => {
        this.#resolve = resolve;
        this.#timer = setTimeout(resolve, this.#wait);
      });
    }
    await this.#promise;
    if (this.#timer !== null) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
  }

  async check() {
    await this.#waitForPlan();
    if (this.#actual !== this.#expected) {
      throw new Error(
        `plan expected ${this.#expected} assertion(s) but received ${this.#actual}`,
      );
    }
  }
}

class NodeTestContext {
  #denoContext;
  #afterHooks = [];
  #beforeHooks = [];
  #parent;
  #skipped = false;
  #name;
  #abortController = new AbortController();
  #plan;
  #planAssert;
  #beforeEachHooks = [];
  #afterEachHooks = [];
  #filePath;
  #subtestPromises = [];
  #subtestFailures = 0;
  #subtestTail = PromiseResolve();
  #attempt;

  constructor(t, parent, name, filePath, attempt) {
    this.#denoContext = t;
    this.#parent = parent;
    this.#name = name;
    this.#filePath = filePath ?? parent?.filePath ?? getCurrentTestFilePath();
    this.#attempt = attempt ?? parent?.attempt ?? 0;
  }

  get [skippedSymbol]() {
    return this.#skipped || (this.#parent?.[skippedSymbol] ?? false);
  }

  get assert() {
    if (this.#plan) {
      if (!this.#planAssert) {
        this.#planAssert = getAssertObject(this, this.#plan);
      }
      return this.#planAssert;
    }
    return getAssertObject(this, null);
  }

  plan(count, options) {
    validateInteger(count, "count", 1);
    if (options !== undefined) {
      validateObject(options, "options");
      if (
        options.wait !== undefined &&
        typeof options.wait !== "boolean" &&
        typeof options.wait !== "number"
      ) {
        throw new ERR_INVALID_ARG_TYPE(
          "options.wait",
          ["boolean", "number"],
          options.wait,
        );
      }
    }
    this.#plan = new TestPlan(count, options);
  }

  async _checkPlan() {
    if (this.#plan) await this.#plan.check();
  }

  async _drainSubtests() {
    for (const promise of new SafeArrayIterator(this.#subtestPromises)) {
      await promise;
    }
    if (this.#subtestFailures > 0) {
      throw new Error("subtests failed");
    }
  }

  get signal() {
    return this.#abortController.signal;
  }

  get name() {
    return this.#name;
  }

  get fullName() {
    if (this.#parent) {
      return this.#parent.fullName + " > " + this.#name;
    }
    return this.#name;
  }

  get filePath() {
    return this.#filePath;
  }

  get passed() {
    return false;
  }

  get attempt() {
    return this.#attempt;
  }

  diagnostic(message) {
    // deno-lint-ignore no-console
    console.log("DIAGNOSTIC:", message);
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
    if (this.#plan) this.#plan.increment();
    // deno-lint-ignore no-this-alias
    const parentContext = this;
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
    const stepPromise = PromisePrototypeThen(
      this.#subtestTail,
      () =>
        this.#denoContext.step({
          name: prepared.name,
          fn: async (denoTestContext) => {
            const newNodeTextContext = new NodeTestContext(
              denoTestContext,
              parentContext,
              prepared.name,
              undefined,
              parentContext.attempt,
            );
            try {
              await before();
              for (
                const hook of new SafeArrayIterator(
                  parentContext.#beforeEachHooks,
                )
              ) {
                await hook();
              }
              await runPossiblyExpectingFailure(
                prepared.fn,
                newNodeTextContext,
                prepared.options,
              );
              await after();
            } catch (err) {
              if (!newNodeTextContext[skippedSymbol]) {
                throw err;
              }
              try {
                await after();
              } catch { /* ignore, test is already failing */ }
            } finally {
              for (
                const hook of new SafeArrayIterator(
                  parentContext.#afterEachHooks,
                )
              ) {
                await hook();
              }
            }
          },
          ignore: !!prepared.options.todo || !!prepared.options.skip,
          location: prepared.location,
          sanitizeExit: false,
          sanitizeOps: false,
          sanitizeResources: false,
        }),
    );
    this.#subtestTail = PromisePrototypeThen(stepPromise, () => {}, () => {});
    ArrayPrototypePush(
      this.#subtestPromises,
      PromisePrototypeThen(
        stepPromise,
        (passed) => {
          if (passed === false) this.#subtestFailures++;
        },
        (error) => {
          this.#subtestFailures++;
          throw error;
        },
      ),
    );
    return PromisePrototypeThen(stepPromise, () => undefined);
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

  beforeEach(fn, _options) {
    if (typeof fn !== "function") {
      throw new TypeError("beforeEach() requires a function");
    }
    ArrayPrototypePush(this.#beforeEachHooks, fn);
  }

  afterEach(fn, _options) {
    if (typeof fn !== "function") {
      throw new TypeError("afterEach() requires a function");
    }
    ArrayPrototypePush(this.#afterEachHooks, fn);
  }
}

let currentSuite = null;

const rootBeforeHooks = [];
const rootAfterHooks = [];
const rootBeforeEachHooks = [];
const rootAfterEachHooks = [];
let rootBeforeRan = false;

async function runRootBeforeOnce() {
  if (rootBeforeRan) return;
  rootBeforeRan = true;
  if (rootBeforeHooks.length === 0) return;
  const rootCtx = {
    name: "<root>",
    fullName: "<root>",
    filePath: getCurrentTestFilePath(),
  };
  for (const hook of new SafeArrayIterator(rootBeforeHooks)) {
    await hook(rootCtx);
  }
}

async function runRootAfterIfDone() {
  if (activeNodeTests !== 0) return;
  if (rootAfterHooks.length === 0) return;
  const rootCtx = {
    name: "<root>",
    fullName: "<root>",
    filePath: getCurrentTestFilePath(),
  };
  // Snapshot and clear so we only run once even if more tests get queued.
  const hooks = ArrayPrototypeSplice(rootAfterHooks, 0, rootAfterHooks.length);
  for (const hook of new SafeArrayIterator(hooks)) {
    try {
      await hook(rootCtx);
    } catch { /* ignore */ }
  }
}

class TestSuite {
  #denoTestContext;
  nodeTestContext;
  entries = [];
  beforeAllHooks = [];
  afterAllHooks = [];
  beforeEachHooks = [];
  afterEachHooks = [];

  constructor(t, nodeTestContext) {
    this.#denoTestContext = t;
    this.nodeTestContext = nodeTestContext;
  }

  addTest(name, options, fn, overrides) {
    const prepared = prepareOptions(name, options, fn, overrides);
    const beforeEach = this.beforeEachHooks;
    const afterEach = this.afterEachHooks;
    const suiteNodeContext = this.nodeTestContext;
    ArrayPrototypePush(this.entries, {
      name: prepared.name,
      fn: async (denoTestContext) => {
        const newNodeTextContext = new NodeTestContext(
          denoTestContext,
          suiteNodeContext,
          prepared.name,
        );
        try {
          for (const hook of new SafeArrayIterator(beforeEach)) {
            await hook(newNodeTextContext);
          }
          return await runPossiblyExpectingFailure(
            prepared.fn,
            newNodeTextContext,
            prepared.options,
          );
        } catch (err) {
          if (newNodeTextContext[skippedSymbol]) {
            return undefined;
          } else {
            throw err;
          }
        } finally {
          for (const hook of new SafeArrayIterator(afterEach)) {
            try {
              await hook(newNodeTextContext);
            } catch { /* ignore */ }
          }
        }
      },
      ignore: !!prepared.options.todo || !!prepared.options.skip,
    });
  }

  addSuite(name, options, fn, overrides) {
    const prepared = prepareOptions(name, options, fn, overrides);
    const { promise, resolve } = Promise.withResolvers();
    const parentSuiteContext = this.nodeTestContext;
    ArrayPrototypePush(this.entries, {
      name: prepared.name,
      fn: wrapSuiteFn(prepared.fn, resolve, prepared.name, parentSuiteContext),
      ignore: !!prepared.options.todo || !!prepared.options.skip,
    });
    return promise;
  }

  async execute() {
    for (const entry of new SafeArrayIterator(this.entries)) {
      await this.#denoTestContext.step({
        name: entry.name,
        fn: entry.fn,
        ignore: entry.ignore,
        sanitizeExit: false,
        sanitizeOps: false,
        sanitizeResources: false,
      });
    }
  }
}

function prepareOptions(name, options, fn, overrides) {
  const location = testLocationFromStack();
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
  validateTestOptions(finalOptions);

  if (typeof fn !== "function") {
    fn = noop;
  }

  if (typeof name !== "string" || name === "") {
    name = fn.name || "<anonymous>";
  }

  return { fn, options: finalOptions, name, location };
}

function validateTestOptions(options) {
  if (
    options.timeout !== undefined &&
    options.timeout !== null
  ) {
    if (typeof options.timeout !== "number") {
      throw new ERR_INVALID_ARG_TYPE(
        "options.timeout",
        "number",
        options.timeout,
      );
    }
    if (
      Number.isNaN(options.timeout) ||
      options.timeout < 0 ||
      (
        options.timeout !== Infinity &&
        options.timeout > 2 ** 32 - 1
      )
    ) {
      throw new ERR_OUT_OF_RANGE(
        "options.timeout",
        ">= 0 && <= 4294967295",
        options.timeout,
      );
    }
  }

  if (
    options.concurrency !== undefined &&
    options.concurrency !== null &&
    typeof options.concurrency !== "boolean"
  ) {
    if (typeof options.concurrency !== "number") {
      throw new ERR_INVALID_ARG_TYPE(
        "options.concurrency",
        ["boolean", "number"],
        options.concurrency,
      );
    }
    if (
      !Number.isInteger(options.concurrency) ||
      options.concurrency < 1 ||
      options.concurrency > 2 ** 31
    ) {
      throw new ERR_OUT_OF_RANGE(
        "options.concurrency",
        ">= 1 && <= 2147483648",
        options.concurrency,
      );
    }
  }
}

function wrapTestFn(fn, resolve, name, options) {
  return async function (t) {
    const nodeTestContext = new NodeTestContext(t, undefined, name);
    let beforeEachOk = false;
    try {
      await runRootBeforeOnce();
      for (const hook of new SafeArrayIterator(rootBeforeEachHooks)) {
        await hook(nodeTestContext);
      }
      beforeEachOk = true;
      await runPossiblyExpectingFailure(fn, nodeTestContext, options);
    } catch (err) {
      if (!nodeTestContext[skippedSymbol]) {
        throw sanitizeThrowValue(err);
      }
    } finally {
      if (beforeEachOk) {
        for (const hook of new SafeArrayIterator(rootAfterEachHooks)) {
          try {
            await hook(nodeTestContext);
          } catch { /* swallow to match node behavior on hook error */ }
        }
      }
      activeNodeTests--;
      await runRootAfterIfDone();
      resolve();
    }
  };
}

function prepareDenoTest(name, options, fn, overrides) {
  const prepared = prepareOptions(name, options, fn, overrides);

  activeNodeTests++;

  const denoTestOptions = {
    name: prepared.name,
    fn: wrapTestFn(prepared.fn, noop, prepared.name, prepared.options),
    only: prepared.options.only,
    ignore: !!prepared.options.todo || !!prepared.options.skip,
    sanitizeOnly: false,
    sanitizeExit: false,
    sanitizeOps: false,
    sanitizeResources: false,
  };
  Deno.test(denoTestOptions);
  // Node resolves the returned promise on test completion, but the
  // Deno runner only executes registered tests after the module
  // finishes evaluating, so top-level `await test(...)` deadlocks.
  // Resolve immediately to unblock; the test still runs and is
  // reported normally. Trade-off: code that awaits `test()` for
  // sequencing (`await test('a'); await test('b')`) sees them run
  // out of order.
  return PromiseResolve();
}

function wrapSuiteFn(fn, resolve, name, parentNodeContext) {
  return async function (t) {
    const isTopLevel = parentNodeContext === undefined;
    if (isTopLevel) await runRootBeforeOnce();
    const suiteNodeContext = new NodeTestContext(t, parentNodeContext, name);
    const prevSuite = currentSuite;
    const suite = currentSuite = new TestSuite(t, suiteNodeContext);
    try {
      fn(suiteNodeContext);
    } finally {
      currentSuite = prevSuite;
    }
    try {
      for (const hook of new SafeArrayIterator(suite.beforeAllHooks)) {
        await hook();
      }
      await suite.execute();
    } finally {
      try {
        for (const hook of new SafeArrayIterator(suite.afterAllHooks)) {
          await hook();
        }
      } finally {
        if (isTopLevel) {
          activeNodeTests--;
          await runRootAfterIfDone();
        }
        resolve();
      }
    }
  };
}

function prepareDenoTestForSuite(name, options, fn, overrides) {
  const prepared = prepareOptions(name, options, fn, overrides);

  activeNodeTests++;

  const denoTestOptions = {
    name: prepared.name,
    fn: wrapSuiteFn(prepared.fn, noop, prepared.name, undefined),
    only: prepared.options.only,
    ignore: !!prepared.options.todo || !!prepared.options.skip,
    sanitizeOnly: false,
    sanitizeExit: false,
    sanitizeOps: false,
    sanitizeResources: false,
  };
  Deno.test(denoTestOptions);
  // See `prepareDenoTest` for the Node-divergence trade-off; top-level
  // `await suite(...)` would deadlock if we waited for completion.
  return PromiseResolve();
}

function test(name, options, fn, overrides) {
  installErrorHandlers();
  if (activeProgrammaticRun !== null) {
    return activeProgrammaticRun.queueTest(name, options, fn, overrides);
  }
  if (isTapMode()) {
    return queueTapTest(name, options, fn, overrides);
  }
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

test.expectFailure = function expectFailure(name, options, fn) {
  return test(name, options, fn, { expectFailure: true });
};

function suite(name, options, fn, overrides) {
  installErrorHandlers();
  if (activeProgrammaticRun !== null) {
    return activeProgrammaticRun.queueSuite(name, options, fn, overrides);
  }
  if (isTapMode()) {
    return queueTapSuite(name, options, fn, overrides);
  }
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

const it = test;
const describe = suite;

function before(fn, _options) {
  if (typeof fn !== "function") {
    throw new TypeError("before() requires a function argument");
  }
  if (activeProgrammaticRun !== null) {
    activeProgrammaticRun.addBeforeHook(fn);
    return;
  }
  if (isTapMode()) {
    const tapSuite = getTapCurrentSuite();
    if (tapSuite !== null) {
      ArrayPrototypePush(tapSuite.beforeAllHooks ??= [], fn);
      return;
    }
    ArrayPrototypePush(rootBeforeHooks, fn);
    // A bare top-level `before()` with no tests must still produce TAP
    // output (`before` runs, then `TAP version 13`, then `1..0`).
    scheduleTapRun();
    return;
  }
  if (currentSuite) {
    ArrayPrototypePush(currentSuite.beforeAllHooks, fn);
    return;
  }
  ArrayPrototypePush(rootBeforeHooks, fn);
}

function after(fn, _options) {
  if (typeof fn !== "function") {
    throw new TypeError("after() requires a function argument");
  }
  if (activeProgrammaticRun !== null) {
    activeProgrammaticRun.addAfterHook(fn);
    return;
  }
  if (isTapMode()) {
    const tapSuite = getTapCurrentSuite();
    if (tapSuite !== null) {
      ArrayPrototypePush(tapSuite.afterAllHooks ??= [], fn);
      return;
    }
    ArrayPrototypePush(rootAfterHooks, fn);
    scheduleTapRun();
    return;
  }
  if (currentSuite) {
    ArrayPrototypePush(currentSuite.afterAllHooks, fn);
    return;
  }
  ArrayPrototypePush(rootAfterHooks, fn);
}

function beforeEach(fn, _options) {
  if (typeof fn !== "function") {
    throw new TypeError("beforeEach() requires a function argument");
  }
  if (activeProgrammaticRun !== null) {
    activeProgrammaticRun.addBeforeEachHook(fn);
    return;
  }
  if (currentSuite) {
    ArrayPrototypePush(currentSuite.beforeEachHooks, fn);
    return;
  }
  ArrayPrototypePush(rootBeforeEachHooks, fn);
}

function afterEach(fn, _options) {
  if (typeof fn !== "function") {
    throw new TypeError("afterEach() requires a function argument");
  }
  if (activeProgrammaticRun !== null) {
    activeProgrammaticRun.addAfterEachHook(fn);
    return;
  }
  if (currentSuite) {
    ArrayPrototypePush(currentSuite.afterEachHooks, fn);
    return;
  }
  ArrayPrototypePush(rootAfterEachHooks, fn);
}

test.it = test;
test.describe = suite;
test.suite = suite;
test.before = before;
test.after = after;
test.beforeEach = beforeEach;
test.afterEach = afterEach;

const activeMocks = [];

class MockFunctionContext {
  #calls = [];
  #implementation;
  #restore;
  #times;
  #onceImplementations = new SafeMap();

  constructor(implementation, restore, times) {
    this.#implementation = implementation;
    this.#restore = restore;
    this.#times = times;
  }

  get calls() {
    return this.#calls;
  }

  callCount() {
    return this.#calls.length;
  }

  mockImplementation(implementation) {
    validateFunction(implementation, "implementation");
    this.#implementation = implementation;
  }

  mockImplementationOnce(implementation, onCall) {
    validateFunction(implementation, "implementation");
    if (onCall !== undefined) {
      validateInteger(onCall, "onCall", 0);
    }
    const call = onCall ?? this.#calls.length;
    MapPrototypeSet(this.#onceImplementations, call, implementation);
  }

  resetCalls() {
    ArrayPrototypeSplice(this.#calls, 0, this.#calls.length);
  }

  restore() {
    if (this.#restore) {
      this.#restore();
      this.#restore = undefined;
    }
    this._restored = true;
    const idx = ArrayPrototypeIndexOf(activeMocks, this);
    if (idx !== -1) {
      ArrayPrototypeSplice(activeMocks, idx, 1);
    }
  }

  _recordCall(thisArg, args, result, error, target) {
    ArrayPrototypePush(this.#calls, {
      arguments: args,
      error,
      result,
      stack: new Error(),
      target,
      this: thisArg,
    });
  }

  _shouldMock() {
    if (this._restored) return false;
    if (this.#times === undefined) return true;
    return this.#calls.length < this.#times;
  }

  _getImplementation() {
    return this.#implementation;
  }

  _nextImpl() {
    const nextCall = this.#calls.length;
    const onceImpl = MapPrototypeGet(this.#onceImplementations, nextCall);
    if (onceImpl) {
      MapPrototypeDelete(this.#onceImplementations, nextCall);
      return onceImpl;
    }
    return this.#implementation;
  }
}

function createMockFunction(original, implementation, ctx) {
  const mockFn = function (...args) {
    const newTarget = new.target;
    const isCtor = newTarget !== undefined;
    // The IIFE wrapping this module is sloppy, so a plain call leaks
    // globalThis as `this`. Match strict-mode/Node semantics.
    const thisArg = !isCtor && this === globalThis ? undefined : this;
    const impl = ctx._shouldMock()
      ? (ctx._nextImpl() ?? implementation ?? original)
      : original;

    let result;
    let error;

    // If called directly (not via subclass), use the original constructor
    // so the produced instance has its prototype, and so call.target reports
    // the user's class (not the mock wrapper).
    const ctorTarget = isCtor && newTarget === mockFn ? impl : newTarget;
    try {
      if (isCtor) {
        result = impl ? ReflectConstruct(impl, args, ctorTarget) : undefined;
      } else {
        result = impl ? ReflectApply(impl, thisArg, args) : undefined;
      }
    } catch (e) {
      error = e;
      ctx._recordCall(
        isCtor ? thisArg : thisArg,
        args,
        undefined,
        error,
        ctorTarget,
      );
      throw e;
    }

    ctx._recordCall(
      isCtor ? result : thisArg,
      args,
      result,
      undefined,
      ctorTarget,
    );
    return result;
  };

  ObjectDefineProperty(mockFn, "mock", {
    __proto__: null,
    value: ctx,
    writable: false,
    enumerable: false,
    configurable: false,
  });

  return mockFn;
}

function findPropertyDescriptor(obj, name) {
  let current = obj;
  while (current !== null && current !== undefined) {
    const desc = ObjectGetOwnPropertyDescriptor(current, name);
    if (desc) return desc;
    current = ObjectGetPrototypeOf(current);
  }
  return undefined;
}

function mockMethodImpl(object, methodName, implementation, options) {
  if (
    implementation !== null && typeof implementation === "object" &&
    typeof implementation !== "function"
  ) {
    options = implementation;
    implementation = undefined;
  }

  const descriptor = findPropertyDescriptor(object, methodName);
  if (!descriptor) {
    throw new TypeError(
      `Cannot mock property '${String(methodName)}' because it does not exist`,
    );
  }

  const isGetter = options?.getter ?? false;
  const isSetter = options?.setter ?? false;

  let original;
  if (isGetter) {
    original = descriptor.get;
  } else if (isSetter) {
    original = descriptor.set;
  } else {
    original = descriptor.value;
  }

  if (typeof original !== "function") {
    throw new TypeError(
      `Cannot mock property '${
        String(methodName)
      }' because it is not a function`,
    );
  }

  const restore = () => {
    ObjectDefineProperty(object, methodName, descriptor);
  };

  const impl = implementation === undefined ? original : implementation;
  const ctx = new MockFunctionContext(impl, restore, options?.times);
  ArrayPrototypePush(activeMocks, ctx);

  const mockFn = createMockFunction(original, impl, ctx);

  const mockDescriptor = {
    configurable: descriptor.configurable,
    enumerable: descriptor.enumerable,
  };

  if (isGetter) {
    mockDescriptor.get = mockFn;
    mockDescriptor.set = descriptor.set;
  } else if (isSetter) {
    mockDescriptor.get = descriptor.get;
    mockDescriptor.set = mockFn;
  } else {
    mockDescriptor.writable = descriptor.writable;
    mockDescriptor.value = mockFn;
  }

  ObjectDefineProperty(object, methodName, mockDescriptor);

  return mockFn;
}

const mock = {
  fn: (original, implementation, options) => {
    if (original !== null && typeof original === "object") {
      options = original;
      original = undefined;
      implementation = undefined;
    } else if (implementation !== null && typeof implementation === "object") {
      options = implementation;
      implementation = original;
    }

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
    return mockFn;
  },

  getter: (object, methodName, implementation, options) => {
    if (implementation !== null && typeof implementation === "object") {
      options = implementation;
      implementation = undefined;
    }
    return mockMethodImpl(object, methodName, implementation, {
      ...options,
      getter: true,
    });
  },

  method: (object, methodName, implementation, options) => {
    return mockMethodImpl(object, methodName, implementation, options);
  },

  reset: () => {
    ArrayPrototypeForEach(activeMocks, (ctx) => {
      ctx.resetCalls();
    });
  },

  restoreAll: () => {
    while (activeMocks.length > 0) {
      const ctx = activeMocks[activeMocks.length - 1];
      ctx.restore();
    }
  },

  setter: (object, methodName, implementation, options) => {
    if (implementation !== null && typeof implementation === "object") {
      options = implementation;
      implementation = undefined;
    }
    return mockMethodImpl(object, methodName, implementation, {
      ...options,
      setter: true,
    });
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
test.before = before;
test.after = after;
test.beforeEach = beforeEach;
test.afterEach = afterEach;
test.run = run;
test.assert = testAssert;
test.getTestContext = getTestContext;

return {
  run,
  test,
  suite,
  it,
  describe,
  before,
  after,
  beforeEach,
  afterEach,
  mock,
  assert: testAssert,
  getTestContext,
  default: test,
};
})();
