// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Node.js contributors. All rights reserved. MIT License.

// The Node.js fatal exception report: what `node` writes to stderr when an
// exception or a promise rejection is not handled. Port of
// `ReportFatalException` in src/node_errors.cc, of the `afterInspector` stack
// enhancer in lib/internal/errors.js, and of the 'exit' step of
// `process._fatalException` in lib/internal/process/execution.js.

(function () {
const { core, internals, primordials } = __bootstrap;
const {
  op_exit,
  op_node_error_arrow,
  op_node_fatal_message_arrow,
  op_set_exit_code,
} = core.ops;
const {
  ArrayPrototypeFilter,
  ArrayPrototypeJoin,
  Error,
  MathMax,
  Number,
  RegExpPrototypeTest,
  SafeRegExp,
  String,
  StringPrototypeIndexOf,
  StringPrototypeLastIndexOf,
  StringPrototypeSlice,
  StringPrototypeSplit,
} = primordials;

const lazyProcess = core.createLazyLoader("node:process");

// Stack lines of runtime internals that Node.js does not have.
const kInternalFrameRe = new SafeRegExp(
  "^\\s*(?:\\x1b\\[[0-9;]*m)*\\s*at .*(?:__node_internal_|eventLoopTick|" +
    "denoErrorToNodeError|__drainNextTickAndMacrotasks)",
);

// The module that the runtime makes from the code of `-e` or of stdin.
const kEvalModuleRe = new SafeRegExp("/\\$deno\\$(?:eval|stdin)\\.[a-z]+$");

/**
 * The arrow of an exception: the `file:line` header, the source line and a
 * caret underline, each followed by a newline.
 */
interface ErrorArrow {
  /**
   * The arrow that Node.js prints above the trace of an object. `null` when
   * the stack of the object already holds its arrow (an error that escaped
   * `node:vm`).
   */
  arrow?: string | null;
  /**
   * The arrow that Node.js prints first, after an empty line: the arrow of a
   * primitive or of an object that is not an error.
   */
  leading?: string;
}

/**
 * Returns the arrow of `error`, like `AppendExceptionLine` in its fatal mode.
 */
function getErrorArrow(error: unknown): ErrorArrow {
  const stored = op_node_error_arrow(error);
  if (stored !== undefined) {
    return { arrow: stored };
  }
  const isNativeError = core.isNativeError(error);
  let source = op_node_fatal_message_arrow(error);
  if (source === undefined && isNativeError) {
    source = getConstructionSiteArrow(error);
  }
  if (source === undefined) {
    return {};
  }
  source = toNodeArrow(source);
  if (source === undefined) {
    return {};
  }
  return isNativeError ? { arrow: source } : { leading: source };
}

// Node.js uses the location of the V8 message of the exception. When the
// runtime recorded no location, use the location where the error was
// constructed, which is the location of the message of a rejected promise.
function getConstructionSiteArrow(error: Error): string | undefined {
  let jsError;
  try {
    jsError = core.destructureError(error);
  } catch {
    return undefined;
  }
  const { frames, sourceLine, sourceLineFrameIndex } = jsError;
  if (sourceLine == null || sourceLineFrameIndex == null) {
    return undefined;
  }
  const frame = frames[sourceLineFrameIndex];
  let arrow = `${frame.fileName}:${frame.lineNumber}\n${sourceLine}\n`;
  if (frame.columnNumber == null || frame.columnNumber < 1) {
    return arrow;
  }
  const start = frame.columnNumber - 1;
  if (start >= sourceLine.length) {
    return arrow;
  }
  for (let i = 0; i < start; i++) {
    arrow += sourceLine[i] === "\t" ? "\t" : " ";
  }
  return arrow + "^\n";
}

// A CommonJS module is compiled with a file URL, but Node.js names it by its
// path. An ES module keeps its file URL, like in Node.js. Returns `undefined`
// for the module of `-e` or of stdin: Node.js names it `[eval]` and points at
// the throw site, but the runtime knows only where the error was constructed.
function toNodeArrow(arrow: string): string | undefined {
  const headerEnd = StringPrototypeIndexOf(arrow, "\n");
  const lineStart = StringPrototypeLastIndexOf(arrow, ":", headerEnd);
  if (headerEnd === -1 || lineStart === -1) {
    return arrow;
  }
  const scriptName = StringPrototypeSlice(arrow, 0, lineStart);
  if (RegExpPrototypeTest(kEvalModuleRe, scriptName)) {
    return undefined;
  }
  const path = internals.getCjsScriptPath?.(scriptName);
  return path === undefined
    ? arrow
    : path + StringPrototypeSlice(arrow, lineStart);
}

function toStringOrPlaceholder(value: unknown): string {
  if (typeof value === "symbol") {
    return "<toString() threw exception>";
  }
  try {
    return String(value);
  } catch {
    return "<toString() threw exception>";
  }
}

function inspectFatalException(error: object, colors: boolean): unknown {
  let originalStack;
  try {
    originalStack = (error as Error).stack;
  } catch {
    // Keep `undefined`.
  }
  try {
    const { inspect } = core.loadExtScript(
      "ext:deno_node/internal/util/inspect.mjs",
    );
    return inspect(error, {
      colors,
      customInspect: false,
      depth: MathMax(inspect.defaultOptions.depth, 5),
    });
  } catch {
    return originalStack;
  }
}

function hideInternalFrames(trace: string): string {
  const lines = StringPrototypeSplit(trace, "\n");
  return ArrayPrototypeJoin(
    ArrayPrototypeFilter(
      lines,
      (line: string) => !RegExpPrototypeTest(kInternalFrameRe, line),
    ),
    "\n",
  );
}

interface FatalExceptionOptions {
  /** The arrow of the error, as returned by `getErrorArrow`. */
  arrow?: ErrorArrow;
  /** Whether to color the inspected error. */
  colors?: boolean;
  /** The Node.js version for the footer, for example `v24.0.0`. */
  version: string;
}

/**
 * Formats `error` like the report that Node.js writes to stderr when `error`
 * is fatal. The result ends with a newline.
 */
function formatFatalException(
  error: unknown,
  options: FatalExceptionOptions,
): string {
  const { arrow, leading } = options.arrow ?? getErrorArrow(error);
  // Node.js names its own executable, which is `node`. The executable of the
  // runtime does not take Node.js options, so name `node` too.
  const hint =
    "(Use `node --trace-uncaught ...` to show where the exception was thrown)\n";
  let report = leading === undefined ? "" : "\n" + leading;
  if (
    error === null || (typeof error !== "object" && typeof error !== "function")
  ) {
    report += toStringOrPlaceholder(error) + "\n" + hint;
  } else {
    const trace = inspectFatalException(error, options.colors ?? false);
    const prefix = typeof arrow === "string" ? arrow + "\n" : "";
    if (typeof trace === "string" && trace.length > 0) {
      report += `${prefix}${hideInternalFrames(trace)}\n`;
    } else {
      let message;
      let name;
      try {
        message = (error as Error).message;
        name = (error as Error).name;
      } catch {
        // Print the error as is.
      }
      report += message === undefined || name === undefined
        ? toStringOrPlaceholder(error) + "\n"
        : `${prefix}${name}: ${message}\n`;
      report += hint;
    }
  }
  return report + `\nNode.js ${options.version}\n`;
}

/**
 * Handles an exception that is about to terminate a program that runs as a
 * Node.js entry: emits 'exit', writes the Node.js report to stderr and exits
 * with `process.exitCode`, or 1. If it throws, the runtime reports the
 * exception in the Deno format.
 */
function reportFatalException(error: unknown): never {
  const process = lazyProcess().default;
  try {
    if (!process._exiting) {
      process._exiting = true;
      process.exitCode = 1;
      process.emit("exit", 1);
    }
  } catch {
    // Nothing to be done about it at this point.
  }

  let colors = false;
  try {
    const { shouldColorize } = core.loadExtScript(
      "ext:deno_node/internal/util/colorize.mjs",
    );
    const { inspect } = core.loadExtScript(
      "ext:deno_node/internal/util/inspect.mjs",
    );
    colors = shouldColorize(process.stderr) || !!inspect.defaultOptions.colors;
  } catch {
    // Report without colors.
  }

  const report = formatFatalException(error, {
    colors,
    version: process.version,
  });
  core.print(report, true);

  let exitCode = 1;
  try {
    if (process.exitCode != null) {
      exitCode = Number(process.exitCode);
    }
  } catch {
    // Keep 1.
  }
  op_set_exit_code(exitCode);
  op_exit();
  throw new Error("unreachable");
}

return {
  formatFatalException,
  getErrorArrow,
  reportFatalException,
};
})();
