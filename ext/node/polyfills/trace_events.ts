// Copyright 2018-2026 the Deno authors. MIT license.

// TODO(petamoriken): enable prefer-primordials for node polyfills
// deno-lint-ignore-file prefer-primordials

(function () {
const { core } = __bootstrap;
const { ERR_TRACE_EVENTS_CATEGORY_REQUIRED } = core.loadExtScript(
  "ext:deno_node/internal/errors.ts",
);
const { validateObject, validateStringArray } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);
const lazyBindingMod = core.createLazyLoader(
  "ext:deno_node/internal_binding/mod.ts",
);

function getProc() {
  // deno-lint-ignore no-process-global
  return typeof process !== "undefined" ? process : undefined;
}

// Each isolate (main + each worker thread) writes its own slice of trace
// events. The main thread, on exit, aggregates any worker slices left in cwd
// into a single `node_trace.${rotation}.log` so consumers see one combined
// file (matching Node's process-wide TracingController behavior).
// Resolved on first use rather than at module-load time so that worker_threads
// bootstrap (which sets up threadId/isMainThread) has finished by the time we
// read those fields.
let _wtExports = null;
function getWorkerThreadsExports() {
  if (_wtExports !== null) return _wtExports;
  try {
    _wtExports = core.loadExtScript("ext:deno_node/worker_threads.ts");
  } catch {
    _wtExports = {};
  }
  return _wtExports;
}

function getThreadId() {
  const wt = getWorkerThreadsExports();
  const tid = wt?.threadId ?? wt?.default?.threadId;
  return typeof tid === "number" ? tid : 0;
}

function isMainThreadProc() {
  const wt = getWorkerThreadsExports();
  const isMain = wt?.isMainThread ?? wt?.default?.isMainThread;
  if (typeof isMain === "boolean") return isMain;
  return getThreadId() === 0;
}

function workerSliceFilename(pid, tid) {
  return `.deno_trace_events_${pid}_t${tid}.json`;
}

const kCategories = Symbol("categories");
const kEnabled = Symbol("enabled");

const kMaxTracingCount = 10;

// Phase codes per V8/Chrome trace format.
const PHASE_NESTABLE_ASYNC_BEGIN = 98; // 'b'
const PHASE_NESTABLE_ASYNC_END = 101; // 'e'

const enabledTracingObjects = new Set();
const categoryBuffers = new Map();
const categoryRefCounts = new Map();
const recordedEvents = [];
const inspectorTracingSessions = new Set();
let asyncHooksRefcount = 0;
let exitHandlerRegistered = false;
let commandLineTracingInitialized = false;
let commandLineTracing = null;
let mainTraceFilename = null;
let originalSetTimeout = null;
let originalSetInterval = null;
let originalSetImmediate = null;
let traceIdCounter = 0;

function getCategoryEnabledBuffer(category) {
  let buf = categoryBuffers.get(category);
  if (buf === undefined) {
    buf = new Uint8Array(1);
    categoryBuffers.set(category, buf);
  }
  return buf;
}

function isTraceCategoryEnabled(category) {
  return getCategoryEnabledBuffer(category)[0] > 0;
}

function splitCategories(categories) {
  if (typeof categories !== "string" || categories.length === 0) {
    return [];
  }
  return categories.split(",").filter((category) => category.length > 0);
}

function isEventCategoryEnabled(categories) {
  return splitCategories(categories).some(isTraceCategoryEnabled);
}

function categorySetMatches(categories, enabledCategories) {
  return splitCategories(categories).some((category) =>
    enabledCategories.has(category)
  );
}

function categoriesFromExecArgv() {
  const args = getProc()?.execArgv;
  if (!Array.isArray(args)) return [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--trace-event-categories") {
      return splitCategories(args[i + 1]);
    }
    if (
      typeof arg === "string" &&
      arg.startsWith("--trace-event-categories=")
    ) {
      return splitCategories(arg.slice("--trace-event-categories=".length));
    }
  }
  return [];
}

function ensureCommandLineTracingEnabled() {
  if (commandLineTracingInitialized) return;
  commandLineTracingInitialized = true;
  const categories = categoriesFromExecArgv();
  if (categories.length === 0) return;
  try {
    commandLineTracing = createTracing({ categories });
    commandLineTracing.enable();
  } catch {
    commandLineTracing = null;
  }
}

function incrementCategory(category) {
  const prev = categoryRefCounts.get(category) ?? 0;
  const next = prev + 1;
  categoryRefCounts.set(category, next);
  const buf = getCategoryEnabledBuffer(category);
  buf[0] = next > 255 ? 255 : next;
  if (prev === 0) {
    synthesizeCategoryStartupEvents(category);
  }
  if (category === "node.async_hooks") {
    asyncHooksRefcount++;
    if (asyncHooksRefcount === 1) installAsyncHooksTimerTracing();
  }
}

function decrementCategory(category) {
  const prev = categoryRefCounts.get(category) ?? 0;
  const next = prev > 0 ? prev - 1 : 0;
  if (next === 0) {
    categoryRefCounts.delete(category);
  } else {
    categoryRefCounts.set(category, next);
  }
  const buf = getCategoryEnabledBuffer(category);
  buf[0] = next > 255 ? 255 : next;
  if (category === "node.async_hooks") {
    if (asyncHooksRefcount > 0) asyncHooksRefcount--;
    if (asyncHooksRefcount === 0) uninstallAsyncHooksTimerTracing();
  }
}

class Tracing {
  constructor(categories) {
    this[kCategories] = categories;
    this[kEnabled] = false;
  }

  enable() {
    if (!this[kEnabled]) {
      this[kEnabled] = true;
      for (const category of this[kCategories]) {
        incrementCategory(category);
      }
      enabledTracingObjects.add(this);
      if (enabledTracingObjects.size > kMaxTracingCount) {
        const p = getProc();
        if (p && p.emitWarning) {
          p.emitWarning(
            "Possible trace_events memory leak detected. There are more than " +
              `${kMaxTracingCount} enabled Tracing objects.`,
          );
        }
      }
      ensureExitHandlerInstalled();
    }
  }

  disable() {
    if (this[kEnabled]) {
      this[kEnabled] = false;
      for (const category of this[kCategories]) {
        decrementCategory(category);
      }
      enabledTracingObjects.delete(this);
    }
  }

  get enabled() {
    return this[kEnabled];
  }

  get categories() {
    return this[kCategories].join(",");
  }
}

function createTracing(options) {
  validateObject(options, "options");
  validateStringArray(options.categories, "options.categories");
  if (options.categories.length <= 0) {
    throw new ERR_TRACE_EVENTS_CATEGORY_REQUIRED();
  }
  return new Tracing(options.categories);
}

function getEnabledCategories() {
  ensureCommandLineTracingEnabled();
  const seen = new Set();
  for (const tracing of enabledTracingObjects) {
    for (const category of tracing[kCategories]) {
      seen.add(category);
    }
  }
  if (seen.size === 0) {
    return undefined;
  }
  return [...seen].join(",");
}

function nowMicros() {
  return Math.trunc(performance.now() * 1000);
}

function trace(phase, category, name, id, scope) {
  const categoryEnabled = isEventCategoryEnabled(category);
  if (!categoryEnabled && inspectorTracingSessions.size === 0) {
    return;
  }
  const ph = String.fromCharCode(phase);
  const p = getProc();
  const event = {
    pid: p ? p.pid : 0,
    tid: getThreadId(),
    ts: nowMicros(),
    ph,
    cat: category,
    name,
  };
  if (id !== undefined && id !== null) {
    event.id = "0x" + Number(id).toString(16);
  }
  if (scope !== undefined && scope !== null) {
    event.args = typeof scope === "object" ? { data: scope } : { scope };
  } else {
    event.args = {};
  }
  if (categoryEnabled) {
    recordedEvents.push(event);
    ensureExitHandlerInstalled();
    flushCurrentTraceFile();
  }
  for (const session of inspectorTracingSessions) {
    if (categorySetMatches(category, session.categories)) {
      session.events.push(event);
    }
  }
}

function synthesizeCategoryStartupEvents(category) {
  if (category === "node.bootstrap") {
    for (
      const name of [
        "environment",
        "nodeStart",
        "v8Start",
        "loopStart",
        "loopExit",
        "bootstrapComplete",
      ]
    ) {
      recordSyntheticTraceEvent(category, name);
    }
  } else if (category === "node.environment") {
    for (
      const name of [
        "Environment",
        "RunAndClearNativeImmediates",
        "CheckImmediate",
        "RunTimers",
        "BeforeExit",
        "RunCleanup",
        "AtExit",
      ]
    ) {
      recordSyntheticTraceEvent(category, name);
    }
  } else if (category === "node.console") {
    installConsoleTracing();
  }
}

function recordSyntheticTraceEvent(category, name, phase = "i", args = {}) {
  const p = getProc();
  recordedEvents.push({
    pid: p ? p.pid : 0,
    tid: getThreadId(),
    ts: nowMicros(),
    ph: phase,
    cat: category,
    name,
    args,
  });
  ensureExitHandlerInstalled();
  flushCurrentTraceFile();
}

let consoleTracingInstalled = false;
function installConsoleTracing() {
  if (consoleTracingInstalled) return;
  consoleTracingInstalled = true;
  const target = globalThis.console;
  if (!target || typeof target !== "object") return;
  const counts = new Map();
  const originalCount = target.count?.bind(target);
  const originalCountReset = target.countReset?.bind(target);
  const originalTime = target.time?.bind(target);
  const originalTimeLog = target.timeLog?.bind(target);
  const originalTimeEnd = target.timeEnd?.bind(target);
  if (typeof originalCount === "function") {
    target.count = function count(label = "default") {
      const key = String(label);
      const next = (counts.get(key) ?? 0) + 1;
      counts.set(key, next);
      recordSyntheticTraceEvent("node.console", `count::${key}`, "C", {
        data: next,
      });
      return originalCount.apply(this, arguments);
    };
  }
  if (typeof originalCountReset === "function") {
    target.countReset = function countReset(label = "default") {
      const key = String(label);
      counts.set(key, 0);
      recordSyntheticTraceEvent("node.console", `count::${key}`, "C", {
        data: 0,
      });
      return originalCountReset.apply(this, arguments);
    };
  }
  if (typeof originalTime === "function") {
    target.time = function time(label = "default") {
      const key = String(label);
      recordSyntheticTraceEvent("node.console", `time::${key}`, "b");
      return originalTime.apply(this, arguments);
    };
  }
  if (typeof originalTimeLog === "function") {
    target.timeLog = function timeLog(label = "default") {
      const key = String(label);
      recordSyntheticTraceEvent("node.console", `time::${key}`, "n");
      return originalTimeLog.apply(this, arguments);
    };
  }
  if (typeof originalTimeEnd === "function") {
    target.timeEnd = function timeEnd(label = "default") {
      const key = String(label);
      recordSyntheticTraceEvent("node.console", `time::${key}`, "e");
      return originalTimeEnd.apply(this, arguments);
    };
  }
}

function startInspectorTracing(categories) {
  const session = {
    categories: new Set(categories),
    events: [],
  };
  inspectorTracingSessions.add(session);
  return session;
}

function stopInspectorTracing(session) {
  if (!session || !inspectorTracingSessions.has(session)) return [];
  inspectorTracingSessions.delete(session);
  return session.events.slice();
}

function writeTraceFile() {
  const p = getProc();
  const pid = p ? p.pid : 0;
  if (isMainThreadProc()) {
    writeMainTraceFile(pid, true);
  } else {
    writeWorkerSliceFile(pid);
  }
}

function flushCurrentTraceFile() {
  const p = getProc();
  const pid = p ? p.pid : 0;
  if (isMainThreadProc()) {
    writeMainTraceFile(pid, false);
  } else {
    writeWorkerSliceFile(pid);
  }
}

let _fsExports = null;
function getFs() {
  if (_fsExports !== null) return _fsExports;
  try {
    _fsExports = core.loadExtScript("ext:deno_node/fs.ts");
  } catch {
    _fsExports = {};
  }
  return _fsExports;
}

function writeMainTraceFile(pid, includeWorkerSlices) {
  const fs = getFs();
  const allEvents = recordedEvents.slice();
  if (includeWorkerSlices) {
    // Pull in any worker-thread slices written by this process before exit.
    let entries;
    const traceDir = traceDirectory();
    try {
      entries = fs.readdirSync(traceDir);
    } catch {
      entries = [];
    }
    const prefix = `.deno_trace_events_${pid}_t`;
    for (const entryName of entries) {
      if (typeof entryName !== "string") continue;
      if (!entryName.startsWith(prefix) || !entryName.endsWith(".json")) {
        continue;
      }
      try {
        const text = fs.readFileSync(tracePath(entryName), "utf-8");
        const slice = JSON.parse(text);
        if (slice && Array.isArray(slice.traceEvents)) {
          for (const ev of slice.traceEvents) allEvents.push(ev);
        }
      } catch {
        // Skip unreadable / partial slice files.
      }
      try {
        fs.unlinkSync(tracePath(entryName));
      } catch {
        // Best-effort cleanup.
      }
    }
  }
  if (allEvents.length === 0) return;
  const filename = getMainTraceFilename();
  try {
    fs.writeFileSync(filename, JSON.stringify({ traceEvents: allEvents }));
  } catch {
    // Best-effort exit-time write.
  }
}

function getMainTraceFilename() {
  if (mainTraceFilename !== null) return mainTraceFilename;
  let rotation = 1;
  mainTraceFilename = tracePath(`node_trace.${rotation}.log`);
  while (existsSync(mainTraceFilename) && rotation < 1000) {
    rotation++;
    mainTraceFilename = tracePath(`node_trace.${rotation}.log`);
  }
  return mainTraceFilename;
}

function writeWorkerSliceFile(pid) {
  if (recordedEvents.length === 0) return;
  const filename = tracePath(workerSliceFilename(pid, getThreadId()));
  try {
    getFs().writeFileSync(
      filename,
      JSON.stringify({ traceEvents: recordedEvents }),
    );
  } catch {
    // Best-effort exit-time write.
  }
}

function traceDirectory() {
  const p = getProc();
  const traceDir = p?.env?.DENO_NODE_TRACE_EVENT_DIRECTORY;
  if (typeof traceDir === "string" && traceDir.length > 0) {
    return traceDir;
  }
  return ".";
}

function tracePath(name) {
  const dir = traceDirectory();
  if (dir === ".") return name;
  return `${dir.replace(/[\\/]$/, "")}/${name}`;
}

function existsSync(path) {
  try {
    getFs().statSync(path);
    return true;
  } catch {
    return false;
  }
}

function ensureExitHandlerInstalled() {
  if (exitHandlerRegistered) return;
  const p = getProc();
  exitHandlerRegistered = true;
  if (p && p.on) {
    p.on("exit", writeTraceFile);
  }
  try {
    globalThis.addEventListener("unload", writeTraceFile);
  } catch {
    // Not every embedder exposes unload events.
  }
}

function installAsyncHooksTimerTracing() {
  if (originalSetTimeout !== null) return;
  originalSetTimeout = globalThis.setTimeout;
  originalSetInterval = globalThis.setInterval;
  originalSetImmediate = globalThis.setImmediate;

  globalThis.setTimeout = function (cb, ms, ...args) {
    if (typeof cb !== "function") {
      return originalSetTimeout(cb, ms, ...args);
    }
    const id = ++traceIdCounter;
    trace(PHASE_NESTABLE_ASYNC_BEGIN, "node,node.async_hooks", "Timeout", id);
    const wrapped = function () {
      try {
        return cb.apply(this, arguments);
      } finally {
        trace(
          PHASE_NESTABLE_ASYNC_END,
          "node,node.async_hooks",
          "Timeout",
          id,
        );
      }
    };
    return originalSetTimeout(wrapped, ms, ...args);
  };

  if (typeof originalSetImmediate === "function") {
    globalThis.setImmediate = function (cb, ...args) {
      if (typeof cb !== "function") {
        return originalSetImmediate(cb, ...args);
      }
      const id = ++traceIdCounter;
      trace(
        PHASE_NESTABLE_ASYNC_BEGIN,
        "node,node.async_hooks",
        "Immediate",
        id,
      );
      const wrapped = function () {
        try {
          return cb.apply(this, arguments);
        } finally {
          trace(
            PHASE_NESTABLE_ASYNC_END,
            "node,node.async_hooks",
            "Immediate",
            id,
          );
        }
      };
      return originalSetImmediate(wrapped, ...args);
    };
  }
}

function uninstallAsyncHooksTimerTracing() {
  if (originalSetTimeout === null) return;
  globalThis.setTimeout = originalSetTimeout;
  globalThis.setInterval = originalSetInterval;
  if (originalSetImmediate !== null) {
    globalThis.setImmediate = originalSetImmediate;
  }
  originalSetTimeout = null;
  originalSetInterval = null;
  originalSetImmediate = null;
}

// Expose trace + getCategoryEnabledBuffer on the internalBinding('trace_events')
// surface so the Node test fixtures that go through `internal/test/binding`
// observe the same state as the public API.
try {
  const binding = lazyBindingMod().getBinding("trace_events");
  if (binding && typeof binding === "object") {
    binding.getCategoryEnabledBuffer = getCategoryEnabledBuffer;
    binding.isTraceCategoryEnabled = isTraceCategoryEnabled;
    binding.trace = trace;
  }
} catch {
  // best-effort: binding registry may not be available in all contexts
}

return {
  default: {
    createTracing,
    getEnabledCategories,
  },
  createTracing,
  getEnabledCategories,
  isTraceCategoryEnabled,
  startInspectorTracing,
  stopInspectorTracing,
};
})();
