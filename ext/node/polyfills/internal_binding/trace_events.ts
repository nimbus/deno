// Copyright 2018-2026 the Deno authors. MIT license.

type TraceEvent = {
  pid: number;
  tid: number;
  ts: number;
  ph: string;
  cat: string;
  name: string;
  id?: string;
  args: Record<string, unknown>;
};

function splitTraceCategories(value: string): string[] {
  return value
    .split(",")
    .map((category) => category.trim())
    .filter((category) => category.length > 0 && category !== "\"\"");
}

function getExecArgv(): string[] {
  return Array.isArray(globalThis.process?.execArgv)
    ? globalThis.process.execArgv
    : [];
}

function getConfiguredTraceCategories(): string[] {
  const execArgv = getExecArgv();
  for (let index = 0; index < execArgv.length; index++) {
    const arg = execArgv[index];
    if (arg === "--trace-events-enabled") {
      return ["v8", "node", "node.async_hooks"];
    }
    if (arg === "--trace-event-categories") {
      const value = execArgv[index + 1];
      return typeof value === "string" ? splitTraceCategories(value) : [];
    }
    if (arg.startsWith("--trace-event-categories=")) {
      return splitTraceCategories(arg.slice("--trace-event-categories=".length));
    }
  }
  return [];
}

function getTraceFilePattern(): string {
  const execArgv = getExecArgv();
  for (let index = 0; index < execArgv.length; index++) {
    const arg = execArgv[index];
    if (arg === "--trace-event-file-pattern") {
      const value = execArgv[index + 1];
      return typeof value === "string" && value.length > 0
        ? value
        : "node_trace.${rotation}.log";
    }
    if (arg.startsWith("--trace-event-file-pattern=")) {
      const value = arg.slice("--trace-event-file-pattern=".length);
      return value.length > 0 ? value : "node_trace.${rotation}.log";
    }
  }
  return "node_trace.${rotation}.log";
}

const dynamicCategoryRefCounts = new Map<string, number>();
const collectedTraceEvents: TraceEvent[] = [];
const inspectorTraceSessions = new Map<number, {
  categories: string[];
  events: TraceEvent[];
}>();
let metadataSeeded = false;
let exitHookInstalled = false;
let nextInspectorTraceSessionId = 1;

function getActiveCategories(): string[] {
  const categories = [...getConfiguredTraceCategories()];
  for (const [category, count] of dynamicCategoryRefCounts) {
    if (count > 0 && !categories.includes(category)) {
      categories.push(category);
    }
  }
  return categories;
}

function isTraceOutputRequested(): boolean {
  const execArgv = getExecArgv();
  return execArgv.some((arg) =>
    arg === "--trace-events-enabled" ||
    arg === "--trace-event-categories" ||
    arg.startsWith("--trace-event-categories=") ||
    arg === "--trace-event-file-pattern" ||
    arg.startsWith("--trace-event-file-pattern=")
  );
}

function resolveTraceFilePath(): string {
  const pattern = getTraceFilePattern()
    .replaceAll("${rotation}", "1")
    .replaceAll("${pid}", String(globalThis.process?.pid ?? 0));
  const cwd = typeof globalThis.process?.cwd === "function"
    ? globalThis.process.cwd()
    : ".";
  if (pattern.startsWith("/")) {
    return pattern;
  }
  return cwd.endsWith("/") ? `${cwd}${pattern}` : `${cwd}/${pattern}`;
}

function ensureParentDirectory(filePath: string) {
  const separatorIndex = filePath.lastIndexOf("/");
  if (separatorIndex <= 0) {
    return;
  }
  Deno.mkdirSync(filePath.slice(0, separatorIndex), { recursive: true });
}

function pushMetadata(name: string, args: Record<string, unknown>) {
  collectedTraceEvents.push({
    pid: globalThis.process?.pid ?? 0,
    tid: 0,
    ts: 0,
    ph: "M",
    cat: "__metadata",
    name,
    args,
  });
}

function seedMetadata() {
  if (metadataSeeded) {
    return;
  }
  metadataSeeded = true;

  pushMetadata("thread_name", {
    name: "JavaScriptMainThread",
  });
  pushMetadata("thread_name", {
    name: "PlatformWorkerThread",
  });
  pushMetadata("version", {
    node: globalThis.process?.versions?.node,
  });
  pushMetadata("process_name", {
    name: globalThis.process?.title || "node",
  });
  pushMetadata("node", {
    process: {
      versions: {
        http_parser: globalThis.process?.versions?.http_parser,
        llhttp: globalThis.process?.versions?.llhttp,
        node: globalThis.process?.versions?.node,
        v8: globalThis.process?.versions?.v8,
        uv: globalThis.process?.versions?.uv,
        zlib: globalThis.process?.versions?.zlib,
        ares: globalThis.process?.versions?.ares,
        modules: globalThis.process?.versions?.modules,
        nghttp2: globalThis.process?.versions?.nghttp2,
        napi: globalThis.process?.versions?.napi,
        openssl: globalThis.process?.versions?.openssl,
      },
      arch: globalThis.process?.arch,
      platform: globalThis.process?.platform,
      release: {
        name: globalThis.process?.release?.name,
        lts: globalThis.process?.release?.lts,
      },
    },
  });
}

function flushTraceFile() {
  if (!metadataSeeded && !isTraceOutputRequested()) {
    return;
  }

  seedMetadata();
  const traceFilePath = resolveTraceFilePath();
  const payload = JSON.stringify({ traceEvents: collectedTraceEvents });
  try {
    ensureParentDirectory(traceFilePath);
    Deno.writeTextFileSync(traceFilePath, payload);
  } catch {
    // Keep exit-time tracing best-effort so non-file-focused fixtures don't
    // fail only because a transient cwd/tmpdir path disappeared during teardown.
  }
}

function ensureTraceLifecycle() {
  if (!isTraceOutputRequested()) {
    return;
  }
  seedMetadata();
  if (exitHookInstalled) {
    return;
  }
  exitHookInstalled = true;
  globalThis.process?.once?.("exit", flushTraceFile);
}

function normalizePhase(phase: number | string): string {
  if (typeof phase === "number") {
    return String.fromCharCode(phase);
  }
  return typeof phase === "string" && phase.length > 0 ? phase[0] : "I";
}

function encodeTraceId(id: unknown): string | undefined {
  if (typeof id === "number" && Number.isFinite(id)) {
    return `0x${id.toString(16)}`;
  }
  return undefined;
}

export class CategorySet {
  #categories: string[];
  #enabled = false;

  constructor(categories: string[]) {
    this.#categories = [...categories];
  }

  enable() {
    if (this.#enabled) {
      return;
    }
    this.#enabled = true;
    ensureTraceLifecycle();
    for (const category of this.#categories) {
      dynamicCategoryRefCounts.set(
        category,
        (dynamicCategoryRefCounts.get(category) ?? 0) + 1,
      );
    }
  }

  disable() {
    if (!this.#enabled) {
      return;
    }
    this.#enabled = false;
    for (const category of this.#categories) {
      const nextCount = (dynamicCategoryRefCounts.get(category) ?? 0) - 1;
      if (nextCount <= 0) {
        dynamicCategoryRefCounts.delete(category);
      } else {
        dynamicCategoryRefCounts.set(category, nextCount);
      }
    }
  }
}

export function getEnabledCategories(): string | undefined {
  const categories = getActiveCategories();
  return categories.length > 0 ? categories.join(",") : undefined;
}

export function isTraceCategoryEnabled(category: string): boolean {
  return getActiveCategories().includes(category);
}

function cloneTraceEvent(event: TraceEvent): TraceEvent {
  return {
    ...event,
    args: { ...event.args },
  };
}

function getMatchingInspectorTraceSessions(category: string) {
  const matches: { categories: string[]; events: TraceEvent[] }[] = [];
  for (const session of inspectorTraceSessions.values()) {
    if (session.categories.includes(category)) {
      matches.push(session);
    }
  }
  return matches;
}

export function startInspectorTracing(categories: string[]): number {
  const id = nextInspectorTraceSessionId++;
  inspectorTraceSessions.set(id, {
    categories: categories.filter((category) =>
      typeof category === "string" && category.length > 0
    ),
    events: [],
  });
  return id;
}

export function stopInspectorTracing(id: number): TraceEvent[] {
  const session = inspectorTraceSessions.get(id);
  if (!session) {
    return [];
  }
  inspectorTraceSessions.delete(id);
  return session.events.map(cloneTraceEvent);
}

export function trace(
  phase: number | string,
  category: string,
  name: string,
  id?: number,
  data?: unknown,
) {
  ensureTraceLifecycle();
  const matchingInspectorSessions = getMatchingInspectorTraceSessions(category);
  const collectForTraceFile = isTraceCategoryEnabled(category);
  if (!collectForTraceFile && matchingInspectorSessions.length === 0) {
    return;
  }

  const event = {
    pid: globalThis.process?.pid ?? 0,
    tid: 0,
    ts: Date.now() * 1000,
    ph: normalizePhase(phase),
    cat: category,
    name,
    id: encodeTraceId(id),
    args: data && typeof data === "object" ? { data } : {},
  };

  if (collectForTraceFile) {
    collectedTraceEvents.push(cloneTraceEvent(event));
  }
  for (const session of matchingInspectorSessions) {
    session.events.push(cloneTraceEvent(event));
  }
}

ensureTraceLifecycle();
