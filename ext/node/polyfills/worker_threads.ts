// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

import { core, internals, primordials } from "ext:core/mod.js";
import {
  op_create_worker,
  op_host_get_worker_cpu_usage,
  op_host_post_message,
  op_host_post_message_raw,
  op_host_recv_ctrl,
  op_host_recv_ctrl_sync,
  op_host_recv_message,
  op_host_recv_message_sync,
  op_host_terminate_worker,
  op_mark_as_untransferable,
  op_message_port_recv_message_sync,
  op_worker_get_resource_limits,
  op_worker_threads_filename,
} from "ext:core/ops";
import {
  deserializeJsMessageData,
  MessageChannel,
  MessagePort,
  MessagePortIdSymbol,
  MessagePortPrototype,
  MessagePortReceiveMessageOnPortSymbol,
  nodeWorkerThreadCloseCb,
  nodeWorkerThreadCloseCbInvoked,
  refMessagePort,
  serializeJsMessageData,
  unrefParentPort,
} from "ext:deno_web/13_message_port.js";
import * as webidl from "ext:deno_webidl/00_webidl.js";
import { notImplemented } from "ext:deno_node/_utils.ts";
import {
  ERR_INVALID_ARG_TYPE,
  ERR_INVALID_URL_SCHEME,
  ERR_OUT_OF_RANGE,
  ERR_WORKER_INVALID_EXEC_ARGV,
  ERR_WORKER_NOT_RUNNING,
  ERR_WORKER_PATH,
} from "ext:deno_node/internal/errors.ts";
import {
  validateArray,
  validateObject,
} from "ext:deno_node/internal/validators.mjs";
import {
  emitDestroy as emitAsyncDestroy,
  emitInit as emitAsyncInit,
  getDefaultTriggerAsyncId,
  newAsyncId,
} from "ext:deno_node/internal/async_hooks.ts";
import { CustomEvent } from "ext:deno_web/02_event.js";
import { EventEmitter } from "node:events";
import { Readable, Writable } from "node:stream";
import {
  BroadcastChannel as WebBroadcastChannel,
  refBroadcastChannel,
} from "ext:deno_web/01_broadcast_channel.js";
import { untransferableSymbol } from "ext:deno_node/internal_binding/util.ts";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";

const {
  ArrayFrom,
  ArrayIsArray,
  Error,
  EvalError,
  FunctionPrototypeCall,
  NumberIsFinite,
  NumberIsNaN,
  ObjectCreate,
  ObjectDefineProperty,
  ObjectHasOwn,
  ObjectKeys,
  ObjectPrototypeIsPrototypeOf,
  PromiseReject,
  PromiseResolve,
  SafeMap,
  SafeRegExp,
  SafeSet,
  SafeWeakMap,
  String,
  StringPrototypeIndexOf,
  StringPrototypeSlice,
  StringPrototypeSplit,
  StringPrototypeStartsWith,
  StringPrototypeTrim,
  SyntaxError,
  Symbol,
  SymbolAsyncDispose,
  SymbolFor,
  SymbolIterator,
  TypeError,
  URIError,
  RangeError,
  ReferenceError,
  Float64Array,
  FunctionPrototypeBind,
} = primordials;

// Map error names to native constructors so that worker error events
// preserve err.constructor (e.g. SyntaxError, TypeError).
const nativeErrorConstructors: Record<string, ErrorConstructor> = {
  __proto__: null as unknown as ErrorConstructor,
  Error,
  EvalError,
  RangeError,
  ReferenceError,
  SyntaxError,
  TypeError,
  URIError,
};

const workerCpuUsageBuffer = new Float64Array(2);

const debugWorkerThreads = false;
function debugWT(...args) {
  if (debugWorkerThreads) {
    // deno-lint-ignore prefer-primordials no-console
    console.log(...args);
  }
}

interface WorkerOnlineMsg {
  type: "WORKER_ONLINE";
}

function isWorkerOnlineMsg(data: unknown): data is WorkerOnlineMsg {
  return typeof data === "object" && data !== null &&
    ObjectHasOwn(data, "type") &&
    (data as { "type": unknown })["type"] === "WORKER_ONLINE";
}

interface WorkerStdioMsg {
  type: "WORKER_STDERR" | "WORKER_STDOUT";
  // deno-lint-ignore no-explicit-any
  data: any;
}

interface WorkerStdinMsg {
  type: "WORKER_STDIN";
  // deno-lint-ignore no-explicit-any
  data: any;
}

interface WorkerStdinEndMsg {
  type: "WORKER_STDIN_END";
}

function isWorkerStdinMsg(data: unknown): data is WorkerStdinMsg {
  return typeof data === "object" && data !== null &&
    ObjectHasOwn(data, "type") &&
    (data as { "type": unknown })["type"] === "WORKER_STDIN";
}

function isWorkerStdinEndMsg(data: unknown): data is WorkerStdinEndMsg {
  return typeof data === "object" && data !== null &&
    ObjectHasOwn(data, "type") &&
    (data as { "type": unknown })["type"] === "WORKER_STDIN_END";
}

function isWorkerStderrMsg(data: unknown): data is WorkerStdioMsg {
  return typeof data === "object" && data !== null &&
    ObjectHasOwn(data, "type") &&
    (data as { "type": unknown })["type"] === "WORKER_STDERR";
}

function isWorkerStdoutMsg(data: unknown): data is WorkerStdioMsg {
  return typeof data === "object" && data !== null &&
    ObjectHasOwn(data, "type") &&
    (data as { "type": unknown })["type"] === "WORKER_STDOUT";
}

// Flags that are valid Node.js environment flags but not allowed in workers
// because they affect per-process state.
const workerDisallowedFlags = new SafeSet([
  "--title",
  "--redirect-warnings",
  "--trace-event-file-pattern",
  "--trace-event-categories",
  "--trace-events-enabled",
  "--diagnostic-dir",
  "--report-signal",
  "--report-filename",
  "--report-dir",
  "--report-directory",
  "--report-compact",
  "--report-on-signal",
  "--report-on-fatalerror",
  "--report-uncaught-exception",
]);

export interface WorkerOptions {
  // only for typings
  argv?: unknown[];
  env?: Record<string, unknown>;
  execArgv?: string[];
  stdin?: boolean;
  stdout?: boolean;
  stderr?: boolean;
  trackUnmanagedFds?: boolean;
  resourceLimits?: {
    maxYoungGenerationSizeMb?: number;
    maxOldGenerationSizeMb?: number;
    codeRangeSizeMb?: number;
    stackSizeMb?: number;
  };
  // deno-lint-ignore prefer-primordials
  eval?: boolean;
  transferList?: Transferable[];
  workerData?: unknown;
  name?: string;
}

const privateWorkerRef = Symbol("privateWorkerRef");
const privateNodeMessagePortRef = Symbol("privateNodeMessagePortRef");
const privateNodeMessagePortListeners = Symbol("privateNodeMessagePortListeners");
const privateNodeMessagePortQueue = Symbol("privateNodeMessagePortQueue");
const privateNodeMessagePortPumpInstalled = Symbol(
  "privateNodeMessagePortPumpInstalled",
);
class NodeWorker extends EventEmitter {
  #id = 0;
  #name = "";
  #refed = true;
  #messagePromise = undefined;
  #controlPromise = undefined;
  #messageLoopPromise = undefined;
  #controlSyncPollScheduled = false;
  #pendingMessages: unknown[] = [];
  #workerOnline = false;
  #exited = false;
  #asyncResourceHandle:
    | {
      hasRef: () => boolean | undefined;
      ref: () => unknown;
      unref: () => unknown;
    }
    | null = null;
  #asyncResourceId = 0;
  #asyncResourceRefState: boolean | undefined = undefined;
  #asyncResourceCleanupScheduled = false;
  // "RUNNING" | "CLOSED" | "TERMINATED"
  // "TERMINATED" means that any controls or messages received will be
  // discarded. "CLOSED" means that we have received a control
  // indicating that the worker is no longer running, but there might
  // still be messages left to receive.
  #status = "RUNNING";

  // https://nodejs.org/api/worker_threads.html#workerthreadid
  threadId = this.#id;
  // https://nodejs.org/api/worker_threads.html#workerresourcelimits
  resourceLimits: WorkerOptions["resourceLimits"] = {};
  // https://nodejs.org/api/worker_threads.html#workerstdin
  stdin: Writable | null = null;
  // https://nodejs.org/api/worker_threads.html#workerstdout
  stdout: Readable = new Readable({ read() {} });
  // https://nodejs.org/api/worker_threads.html#workerstderr
  stderr: Readable = new Readable({ read() {} });

  constructor(specifier: URL | string, options?: WorkerOptions) {
    super();

    const isUrlSpecifier = specifier instanceof URL;
    if (typeof specifier !== "string" && !isUrlSpecifier) {
      throw new ERR_INVALID_ARG_TYPE("filename", ["string", "URL"], specifier);
    }

    if (options?.execArgv) {
      validateArray(options.execArgv, "options.execArgv");
      if (options.execArgv.length > 0) {
        const invalidFlags = [];
        for (let i = 0; i < options.execArgv.length; i++) {
          const flag = options.execArgv[i];
          // Items that don't start with '-' are arguments to the
          // preceding flag (e.g. "--conditions node"), not flags.
          if (!StringPrototypeStartsWith(flag, "-")) {
            continue;
          }
          if (!process.allowedNodeEnvironmentFlags.has(flag)) {
            invalidFlags[invalidFlags.length] = flag;
            continue;
          }
          const eqIdx = StringPrototypeIndexOf(flag, "=");
          const flagName = eqIdx === -1
            ? flag
            : StringPrototypeSlice(flag, 0, eqIdx);
          if (workerDisallowedFlags.has(flagName)) {
            invalidFlags[invalidFlags.length] = flag;
          }
        }
        if (invalidFlags.length > 0) {
          throw new ERR_WORKER_INVALID_EXEC_ARGV(invalidFlags);
        }
      }
    }

    if (options?.env) {
      const nodeOptions = options.env.NODE_OPTIONS;
      if (typeof nodeOptions === "string" && nodeOptions.length > 0) {
        // Parse NODE_OPTIONS and validate each flag
        const parts = StringPrototypeSplit(
          StringPrototypeTrim(nodeOptions),
          new SafeRegExp("\\s+"),
        );
        let hasInvalid = false;
        for (let i = 0; i < parts.length; i++) {
          const part = parts[i];
          if (StringPrototypeStartsWith(part, "-")) {
            if (
              !process.allowedNodeEnvironmentFlags.has(part) ||
              workerDisallowedFlags.has(part)
            ) {
              hasInvalid = true;
              break;
            }
          }
        }
        if (hasInvalid) {
          throw new ERR_WORKER_INVALID_EXEC_ARGV(
            [nodeOptions],
            "invalid NODE_OPTIONS env variable",
          );
        }
      }
    }

    if (isUrlSpecifier) {
      if (
        !(specifier.protocol === "data:" || specifier.protocol === "file:")
      ) {
        throw new ERR_INVALID_URL_SCHEME(["file", "data"]);
      }
    } else if (typeof specifier === "string" && !options?.eval) {
      // Node.js requires string specifiers to be absolute paths or
      // relative paths starting with './' or '../'. URLs passed as
      // strings must be wrapped with `new URL`.
      if (
        StringPrototypeStartsWith(specifier, "file://") ||
        StringPrototypeStartsWith(specifier, "data:") ||
        StringPrototypeStartsWith(specifier, "http://") ||
        StringPrototypeStartsWith(specifier, "https://")
      ) {
        throw new ERR_WORKER_PATH(specifier);
      }
      const path = specifier;
      if (
        !StringPrototypeStartsWith(path, "/") &&
        !StringPrototypeStartsWith(path, "./") &&
        !StringPrototypeStartsWith(path, "../") &&
        !StringPrototypeStartsWith(path, ".\\") &&
        !StringPrototypeStartsWith(path, "..\\")
      ) {
        // On Windows, also allow drive-letter absolute paths (e.g. C:\...)
        const isWindowsAbsolute = path.length >= 3 && path[1] === ":" &&
          (path[2] === "\\" || path[2] === "/");
        if (!isWindowsAbsolute) {
          throw new ERR_WORKER_PATH(specifier);
        }
      }
    }

    // Serialize workerData before resolving the filename so that
    // DataCloneError is thrown before file-not-found errors,
    // matching Node.js behavior.

    // Handle the `env` option following Node.js semantics:
    // - undefined/null: snapshot current process.env (isolated copy)
    // - SHARE_ENV: worker shares the parent's OS environment
    // - object: use that object, coercing values to strings
    // - anything else: throw ERR_INVALID_ARG_TYPE
    // See https://github.com/denoland/deno/issues/23522.
    let env_ = undefined;
    const envOpt = options?.env;
    if (envOpt === SHARE_ENV) {
      const installSharedEnv = (globalThis as typeof globalThis & {
        __neovexInstallSharedWorkerEnvProxy?: () => void;
      }).__neovexInstallSharedWorkerEnvProxy;
      if (typeof installSharedEnv === "function") {
        installSharedEnv();
      }
    }
    if (envOpt != null && envOpt !== SHARE_ENV) {
      if (typeof envOpt !== "object") {
        throw new ERR_INVALID_ARG_TYPE(
          "options.env",
          ["object", "undefined", "null", "worker_threads.SHARE_ENV"],
          envOpt,
        );
      }
      // Snapshot the provided env, coercing values to strings like Node.js.
      // This also handles passing `process.env` (a Proxy in Deno) by
      // producing a plain object that can be structured-cloned.
      const envObj = {};
      const keys = ObjectKeys(envOpt);
      for (let i = 0; i < keys.length; i++) {
        envObj[keys[i]] = String(envOpt[keys[i]]);
      }
      env_ = envObj;
    } else if (envOpt !== SHARE_ENV) {
      // Default: snapshot current process.env so the worker gets an
      // isolated copy, not a live reference to the OS environment.
      // Wrap in try/catch because accessing process.env requires
      // --allow-env permission in Deno. If unavailable, fall back to
      // shared OS env (env_ stays undefined).
      try {
        const envObj = {};
        const keys = ObjectKeys(process.env);
        for (let i = 0; i < keys.length; i++) {
          envObj[keys[i]] = process.env[keys[i]];
        }
        env_ = envObj;
      } catch {
        // No env permission - worker will share the OS environment.
      }
    }
    // When envOpt === SHARE_ENV, env_ stays undefined and the worker
    // will use the default process.env backed by Deno.env (shared OS env).

    // Handle the `argv` option: must be an array or undefined.
    // Values are coerced to strings like Node.js does.
    let argv_: string[] | undefined = undefined;
    if (options?.argv != null) {
      if (!ArrayIsArray(options.argv)) {
        throw new ERR_INVALID_ARG_TYPE(
          "options.argv",
          "Array",
          options.argv,
        );
      }
      argv_ = [];
      for (let i = 0; i < options.argv.length; i++) {
        argv_[i] = String(options.argv[i]);
      }
    }

    const resourceLimits_ = options?.resourceLimits ?? undefined;

    const serializedWorkerMetadata = serializeJsMessageData({
      workerData: options?.workerData,
      environmentData: environmentData,
      env: env_,
      shareEnv: envOpt === SHARE_ENV,
      argv: argv_,
      execArgv: options?.execArgv ?? [],
      name: this.#name,
      isEval: !!options?.eval,
      isWorkerThread: true,
      hasStdin: !!options?.stdin,
      resourceLimits: resourceLimits_,
    }, options?.transferList ?? []);

    let sourceCode = "";
    let hasSourceCode = false;

    if (options?.eval) {
      if (typeof specifier !== "string") {
        throw new TypeError(
          "The property 'options.eval' must be false when 'filename' is not a string.",
        );
      }
      const code = specifier;
      // Node.js runs eval workers as CJS (sloppy mode).
      // Pass as source code for execute_script (sloppy mode).
      // `require` is already available from the Node worker bootstrap.
      // See: https://github.com/denoland/deno/issues/26739
      sourceCode = `var __filename = ${
        // deno-lint-ignore prefer-primordials
        JSON.stringify(process.cwd() + "/[worker eval]")};\n` +
        `var __dirname = ${
          // deno-lint-ignore prefer-primordials
          JSON.stringify(process.cwd())};\n` +
        `var module = { exports: {} };\n` +
        `var exports = module.exports;\n` +
        code;
      hasSourceCode = true;
      specifier = `data:text/javascript,`;
    } else if (!(isUrlSpecifier && specifier.protocol === "data:")) {
      // deno-lint-ignore prefer-primordials
      specifier = specifier.toString();
      if (
        StringPrototypeStartsWith(specifier, "./") ||
        StringPrototypeStartsWith(specifier, "../") ||
        StringPrototypeStartsWith(specifier, ".\\") ||
        StringPrototypeStartsWith(specifier, "..\\")
      ) {
        specifier = new URL(
          specifier,
          pathToFileURL(process.cwd() + "/"),
        );
      }
      specifier = op_worker_threads_filename(specifier) ?? specifier;
    }

    // TODO(bartlomieu): this doesn't match the Node.js behavior, it should be
    // `[worker {threadId}] {name}` or empty string.
    let name = StringPrototypeTrim(options?.name ?? "");
    if (options?.eval) {
      name = "[worker eval]";
    }
    this.#name = name;

    const id = op_create_worker(
      {
        // deno-lint-ignore prefer-primordials
        specifier: specifier.toString(),
        hasSourceCode,
        sourceCode,
        permissions: null,
        name: this.#name,
        workerType: "node",
        closeOnIdle: true,
        resourceLimits: resourceLimits_,
      },
      serializedWorkerMetadata,
    );
    this.#id = id;
    this.threadId = id;
    this.#installAsyncResourceHandle();

    if (resourceLimits_) {
      this.resourceLimits = { ...resourceLimits_ };
    }

    if (options?.stdin) {
      // deno-lint-ignore no-this-alias
      const worker = this;
      this.stdin = new Writable({
        write(chunk, _encoding, callback) {
          try {
            worker.postMessage({
              type: "WORKER_STDIN",
              data: chunk,
            });
            callback();
          } catch (err) {
            callback(err);
          }
        },
        final(callback) {
          try {
            worker.postMessage({
              type: "WORKER_STDIN_END",
            });
            callback();
          } catch (err) {
            callback(err);
          }
        },
      });
    }

    this.#pollControl();
    this.#messageLoopPromise = this.#pollMessages();
    process.nextTick(() => process.emit("worker", this));
  }

  #installAsyncResourceHandle() {
    this.#asyncResourceRefState = true;
    const handle = {
      hasRef: () => this.#asyncResourceRefState,
      ref: () => {
        this.ref();
        return handle;
      },
      unref: () => {
        this.unref();
        return handle;
      },
    };
    this.#asyncResourceHandle = handle;
    this.#asyncResourceId = newAsyncId();
    emitAsyncInit(
      this.#asyncResourceId,
      "WORKER",
      getDefaultTriggerAsyncId(),
      handle,
    );
  }

  #scheduleAsyncResourceCleanup() {
    if (this.#asyncResourceCleanupScheduled || this.#asyncResourceHandle === null) {
      return;
    }
    this.#asyncResourceCleanupScheduled = true;
    const asyncId = this.#asyncResourceId;
    setTimeout(() => {
      this.#asyncResourceRefState = undefined;
      emitAsyncDestroy(asyncId);
    }, 0);
  }

  #drainPendingMessages() {
    while (this.#pendingMessages.length > 0 && this.listenerCount("message") > 0) {
      this.emit("message", this.#pendingMessages.shift());
    }
  }

  #shouldUnrefParentOps() {
    return !this.#refed && this.#workerOnline;
  }

  [privateWorkerRef](ref) {
    if (ref === this.#refed) {
      return;
    }
    this.#refed = ref;
    this.#asyncResourceRefState = ref;
    if (ref) {
      if (this.#controlPromise) {
        core.refOpPromise(this.#controlPromise);
      }
      if (this.#messagePromise) {
        core.refOpPromise(this.#messagePromise);
      }
      this.#scheduleControlSyncPoll();
    } else if (this.#shouldUnrefParentOps()) {
      if (this.#controlPromise) {
        core.unrefOpPromise(this.#controlPromise);
      }
      if (this.#messagePromise) {
        core.unrefOpPromise(this.#messagePromise);
      }
    }
  }

  #handleError(err) {
    this.emit("error", err);
  }

  #closeStdio() {
    if (!this.stdout.readableEnded) {
      FunctionPrototypeCall(Readable.prototype.push, this.stdout, null);
    }
    if (!this.stderr.readableEnded) {
      FunctionPrototypeCall(Readable.prototype.push, this.stderr, null);
    }
  }

  async #handleControlEvent(type, data) {
    switch (type) {
      case 1: { // TerminalError
        this.#status = "CLOSED";
        this.#closeStdio();
        if (this.listenerCount("error") > 0) {
          const errMsg = data.errorMessage ?? data.message;
          const errName = data.name;
          let err;
          if (errName === "ERR_WORKER_OUT_OF_MEMORY") {
            err = new Error(errMsg);
            err.code = errName;
            err.name = "Error";
          } else {
            const Ctor = nativeErrorConstructors[errName] ?? Error;
            err = new Ctor(errMsg);
          }
          err.stack = undefined;
          this.emit("error", err);
        }
        await this.#messageLoopPromise;
        this.resourceLimits = {};
        if (!this.#exited) {
          this.#exited = true;
          this.#scheduleAsyncResourceCleanup();
          this.emit("exit", data.exitCode ?? 1);
        }
        return true;
      }
      case 2: { // Error
        this.#handleError(data);
        return false;
      }
      case 3: { // Close
        debugWT(`Host got "close" message from worker: ${this.#name}`);
        this.#status = "CLOSED";
        this.#closeStdio();
        await this.#messageLoopPromise;
        this.resourceLimits = {};
        if (!this.#exited) {
          this.#exited = true;
          this.#scheduleAsyncResourceCleanup();
          this.emit("exit", data ?? 0);
        }
        return true;
      }
      default: {
        throw new Error(`Unknown worker event: "${type}"`);
      }
    }
  }

  #scheduleControlSyncPoll() {
    if (this.#controlSyncPollScheduled || this.#status !== "RUNNING" || !this.#refed) {
      return;
    }
    this.#controlSyncPollScheduled = true;
    setTimeout(async () => {
      this.#controlSyncPollScheduled = false;
      if (this.#status !== "RUNNING" || !this.#refed) {
        return;
      }
      const controlEvent = op_host_recv_ctrl_sync(this.#id);
      if (controlEvent !== null) {
        const { 0: type, 1: data } = controlEvent;
        await this.#handleControlEvent(type, data);
      }
      if (this.#status === "RUNNING" && this.#refed) {
        this.#scheduleControlSyncPoll();
      }
    }, 0);
  }

  #pollControl = async () => {
    while (this.#status === "RUNNING") {
      this.#controlPromise = op_host_recv_ctrl(this.#id);
      if (this.#shouldUnrefParentOps()) {
        core.unrefOpPromise(this.#controlPromise);
      }
      const { 0: type, 1: data } = await this.#controlPromise;

      if (this.#status !== "RUNNING") {
        return;
      }

      if (await this.#handleControlEvent(type, data)) {
        return;
      }
    }
  };

  #dispatchWorkerThreadMessage(data) {
    let message, _transferables;
    try {
      const v = deserializeJsMessageData(data);
      message = v[0];
      _transferables = v[1];
    } catch (err) {
      this.emit("messageerror", err);
      return false;
    }
    if (
      // only emit "online" event once, and since the message
      // has to come before user messages, we are safe to assume
      // it came from us
      !this.#workerOnline && isWorkerOnlineMsg(message)
    ) {
      this.#workerOnline = true;
      if (!this.#refed) {
        if (this.#controlPromise) {
          core.unrefOpPromise(this.#controlPromise);
        }
        if (this.#messagePromise) {
          core.unrefOpPromise(this.#messagePromise);
        }
      }
      this.emit("online");
    } else if (isWorkerStdoutMsg(message)) {
      FunctionPrototypeCall(
        Readable.prototype.push,
        this.stdout,
        message.data,
      );
    } else if (isWorkerStderrMsg(message)) {
      FunctionPrototypeCall(
        Readable.prototype.push,
        this.stderr,
        message.data,
      );
    } else {
      if (this.listenerCount("message") === 0) {
        this.#pendingMessages.push(message);
      } else {
        this.emit("message", message);
      }
    }
    return true;
  }

  #pollMessages = async () => {
    while (this.#status !== "TERMINATED") {
      this.#messagePromise = op_host_recv_message(this.#id);
      if (this.#shouldUnrefParentOps()) {
        core.unrefOpPromise(this.#messagePromise);
      }
      const data = await this.#messagePromise;
      if (data === null) {
        if (this.#status === "RUNNING") {
          this.#status = "CLOSED";
          this.#closeStdio();
          this.resourceLimits = {};
          if (!this.#exited) {
            this.#exited = true;
            this.#scheduleAsyncResourceCleanup();
            this.emit("exit", 0);
          }
        }
        return;
      }
      if (this.#status === "TERMINATED") {
        return;
      }
      if (!this.#dispatchWorkerThreadMessage(data)) return;
      // Sync drain: process a limited batch of already-queued messages
      // without going through the async op machinery. The batch limit
      // prevents starvation of the event loop when message handlers
      // synchronously post new messages (e.g. ping-pong patterns).
      for (let i = 0; i < 1000 && this.#status !== "TERMINATED"; i++) {
        const syncData = op_host_recv_message_sync(this.#id);
        if (syncData === null) break;
        if (!this.#dispatchWorkerThreadMessage(syncData)) return;
      }
    }
  };

  postMessage(message, transferOrOptions = { __proto__: null }) {
    const prefix = "Failed to execute 'postMessage' on 'MessagePort'";
    webidl.requiredArguments(arguments.length, 1, prefix);
    if (this.#status !== "RUNNING") return;
    // Fast path: no transferables
    if (
      transferOrOptions === undefined ||
      transferOrOptions === null ||
      (arguments.length <= 1)
    ) {
      op_host_post_message_raw(
        this.#id,
        core.serialize(message),
      );
      return;
    }
    message = webidl.converters.any(message);
    let options;
    if (
      webidl.type(transferOrOptions) === "Object" &&
      transferOrOptions !== undefined &&
      transferOrOptions[SymbolIterator] !== undefined
    ) {
      const transfer = webidl.converters["sequence<object>"](
        transferOrOptions,
        prefix,
        "Argument 2",
      );
      options = { transfer };
    } else {
      options = webidl.converters.StructuredSerializeOptions(
        transferOrOptions,
        prefix,
        "Argument 2",
      );
    }
    const { transfer } = options;
    const data = serializeJsMessageData(message, transfer);
    op_host_post_message(this.#id, data);
  }

  // https://nodejs.org/api/worker_threads.html#workerterminate
  terminate() {
    if (this.#status === "TERMINATED") {
      return PromiseResolve(undefined);
    }

    this.#status = "TERMINATED";
    if (this.#controlPromise) {
      core.unrefOpPromise(this.#controlPromise);
    }
    if (this.#messagePromise) {
      core.unrefOpPromise(this.#messagePromise);
    }
    op_host_terminate_worker(this.#id);
    this.#closeStdio();

    if (!this.#exited) {
      this.#exited = true;
      this.#scheduleAsyncResourceCleanup();
      this.emit("exit", 1);
      return PromiseResolve(1);
    }

    // Worker already exited - Node.js returns undefined in this case
    // (the internal handle is already null).
    return PromiseResolve(undefined);
  }

  async [SymbolAsyncDispose]() {
    await this.terminate();
  }

  addListener(
    eventName: string | symbol,
    listener: (...args: unknown[]) => unknown,
  ) {
    super.addListener(eventName, listener);
    if (eventName === "message") {
      this.#drainPendingMessages();
    }
    return this;
  }

  on(eventName: string | symbol, listener: (...args: unknown[]) => unknown) {
    return this.addListener(eventName, listener);
  }

  once(eventName: string | symbol, listener: (...args: unknown[]) => unknown) {
    super.once(eventName, listener);
    if (eventName === "message") {
      this.#drainPendingMessages();
    }
    return this;
  }

  ref() {
    this[privateWorkerRef](true);
  }

  unref() {
    this[privateWorkerRef](false);
  }

  cpuUsage(prevValue?: { user: number; system: number }) {
    if (prevValue != null && !NumberIsNaN(prevValue)) {
      validateObject(prevValue, "prevValue");
      if (typeof prevValue.user !== "number") {
        throw new ERR_INVALID_ARG_TYPE(
          "prevValue.user",
          "number",
          prevValue.user,
        );
      }
      if (!NumberIsFinite(prevValue.user) || prevValue.user < 0) {
        throw new ERR_OUT_OF_RANGE(
          "prevValue.user",
          ">= 0 && <= 2^53",
          prevValue.user,
        );
      }
      if (typeof prevValue.system !== "number") {
        throw new ERR_INVALID_ARG_TYPE(
          "prevValue.system",
          "number",
          prevValue.system,
        );
      }
      if (!NumberIsFinite(prevValue.system) || prevValue.system < 0) {
        throw new ERR_OUT_OF_RANGE(
          "prevValue.system",
          ">= 0 && <= 2^53",
          prevValue.system,
        );
      }
    }

    if (this.#status !== "RUNNING") {
      return PromiseReject(new ERR_WORKER_NOT_RUNNING());
    }

    op_host_get_worker_cpu_usage(this.#id, workerCpuUsageBuffer);
    const user = workerCpuUsageBuffer[0];
    const system = workerCpuUsageBuffer[1];
    if (prevValue) {
      return PromiseResolve({
        user: user - prevValue.user,
        system: system - prevValue.system,
      });
    }
    return PromiseResolve({ user, system });
  }

  // https://nodejs.org/api/worker_threads.html#workerthreadname
  get threadName(): string | null {
    if (this.#exited) {
      return null;
    }
    return this.#name;
  }

  readonly getHeapSnapshot = () =>
    notImplemented("Worker.prototype.getHeapSnapshot");
  // fake performance
  readonly performance = globalThis.performance;
}

export let isMainThread;
export let resourceLimits;
export let threadName: string = "";

let threadId = 0;
let workerData: unknown = null;
let environmentData = new SafeMap();

// Like https://github.com/nodejs/node/blob/48655e17e1d84ba5021d7a94b4b88823f7c9c6cf/lib/internal/event_target.js#L611
interface NodeEventTarget extends
  Pick<
    EventEmitter,
    "eventNames" | "listenerCount" | "emit" | "removeAllListeners"
  > {
  setMaxListeners(n: number): void;
  getMaxListeners(): number;
  // deno-lint-ignore no-explicit-any
  off(eventName: string, listener: (...args: any[]) => void): NodeEventTarget;
  // deno-lint-ignore no-explicit-any
  on(eventName: string, listener: (...args: any[]) => void): NodeEventTarget;
  // deno-lint-ignore no-explicit-any
  once(eventName: string, listener: (...args: any[]) => void): NodeEventTarget;
  addListener: NodeEventTarget["on"];
  removeListener: NodeEventTarget["off"];
}

interface ParentPort extends NodeEventTarget {
  postMessage(message: unknown, transferOrOptions?: unknown): void;
  addEventListener(
    name: string,
    listener: EventListenerOrEventListenerObject,
    options?: boolean | AddEventListenerOptions,
  ): void;
  removeEventListener(
    name: string,
    listener: EventListenerOrEventListenerObject,
  ): void;
  onmessage: ((ev: Event) => void) | null;
  // deno-lint-ignore no-explicit-any
  emit(...args: any[]): any;
  removeAllListeners(): void;
  setMaxListeners(n: number): void;
  getMaxListeners(): number;
  eventNames(): string[];
  listenerCount(): number;
  unref(): void;
  ref(): void;
  [key: symbol]: unknown;
}

// deno-lint-ignore no-explicit-any
let parentPort: ParentPort = null as any;

internals.__initWorkerThreads = (
  runningOnMainThread: boolean,
  workerId,
  maybeWorkerMetadata,
  moduleSpecifier,
) => {
  isMainThread = runningOnMainThread;
  internals.__isWorkerThread = !runningOnMainThread;

  defaultExport.isMainThread = isMainThread;

  if (isMainThread) {
    resourceLimits = {};
    defaultExport.resourceLimits = resourceLimits;
  }

  if (!isMainThread) {
    // TODO(bartlomieju): this is a really hacky way to provide
    // require in worker_threads - this should be rewritten to use proper
    // CJS/ESM loading
    if (moduleSpecifier) {
      globalThis.require = createRequire(
        StringPrototypeStartsWith(moduleSpecifier, "data:")
          ? `${Deno.cwd()}/[worker eval]`
          : moduleSpecifier,
      );
    }

    const listeners = new SafeWeakMap<
      // deno-lint-ignore no-explicit-any
      (...args: any[]) => void,
      // deno-lint-ignore no-explicit-any
      (ev: any) => any
    >();

    // Create parentPort as a separate object that delegates to the web
    // worker's native APIs. We capture the native methods here (before
    // user code runs) so that user code overriding globalThis.postMessage
    // (e.g. Emscripten/z3-solver) doesn't cause infinite recursion.
    const nativePostMessage = FunctionPrototypeBind(
      globalThis.postMessage,
      globalThis,
    );
    const nativeAddEventListener = FunctionPrototypeBind(
      globalThis.addEventListener,
      globalThis,
    );
    const nativeRemoveEventListener = FunctionPrototypeBind(
      globalThis.removeEventListener,
      globalThis,
    );
    // Track message listener count to prevent double delivery.
    // When parentPort message listeners exist, suppress the web IDL
    // onmessage handler (globalThis.onmessage) since both would fire
    // for the same MessageEvent.
    let messageListenerCount = 0;
    // Track Web API message listeners to prevent underflow on
    // double-remove (same concern as the Node-style off() path).
    const webMessageListeners = new SafeSet();

    parentPort = ObjectCreate(null) as ParentPort;
    parentPort.postMessage = function (message, transferOrOptions?) {
      return nativePostMessage(message, transferOrOptions);
    };
    parentPort.addEventListener = function (name, listener, options?) {
      nativeAddEventListener(name, listener, options);
      if (name === "message" && !webMessageListeners.has(listener)) {
        webMessageListeners.add(listener);
        messageListenerCount++;
      }
    };
    parentPort.removeEventListener = function (name, listener) {
      nativeRemoveEventListener(name, listener);
      if (name === "message" && webMessageListeners.has(listener)) {
        webMessageListeners.delete(listener);
        messageListenerCount--;
      }
    };
    // Delegate parentPort.onmessage to globalThis.onmessage so that
    // setting parentPort.onmessage = handler works like the old code
    // where parentPort === globalThis.
    ObjectDefineProperty(parentPort, "onmessage", {
      __proto__: null,
      get() {
        return globalThis.onmessage;
      },
      set(handler) {
        globalThis.onmessage = handler;
      },
      configurable: true,
      enumerable: true,
    });

    // Only intercept globalThis.onmessage for Node worker threads
    // (not plain Deno web workers) to prevent double message delivery
    // when both parentPort.on('message') and self.onmessage are set.
    if (maybeWorkerMetadata) {
      let storedOnmessage: ((ev: Event) => void) | null = null;
      // Dynamically add/remove the forwarding listener so we don't
      // keep a permanent "message" listener on globalThis. A permanent
      // listener would make hasMessageEventListener() always true and
      // prevent the worker from exiting.
      let onmessageForwarder: ((ev: Event) => void) | null = null;
      ObjectDefineProperty(globalThis, "onmessage", {
        __proto__: null,
        get() {
          return storedOnmessage;
        },
        set(handler) {
          // Remove old forwarder if any
          if (onmessageForwarder) {
            nativeRemoveEventListener("message", onmessageForwarder);
            onmessageForwarder = null;
          }
          storedOnmessage = handler;
          // Add forwarder only when a handler is set
          if (typeof handler === "function") {
            onmessageForwarder = (ev: Event) => {
              if (messageListenerCount > 0) return;
              if (typeof storedOnmessage === "function") {
                storedOnmessage(ev);
              }
            };
            nativeAddEventListener("message", onmessageForwarder);
          }
        },
        configurable: true,
        enumerable: true,
      });
    }

    threadId = workerId;
    let isWorkerThread = false;
    if (maybeWorkerMetadata) {
      const { 0: metadata, 1: _ } = maybeWorkerMetadata;
      workerData = metadata.workerData;
      environmentData = metadata.environmentData;
      isWorkerThread = metadata.isWorkerThread;
      threadName = metadata.name ?? "";
      const env = metadata.env;
      if (env) {
        process.env = env;
        if (globalThis.process && typeof globalThis.process === "object") {
          globalThis.process.env = env;
        }
        if (
          internals.nodeGlobals?.process &&
          typeof internals.nodeGlobals.process === "object"
        ) {
          internals.nodeGlobals.process.env = env;
        }
      }
      if (globalThis.process !== process) {
        globalThis.process = process;
      }

      // Get resolved resource limits from the Rust side (includes V8
      // defaults for unspecified fields), matching Node.js behavior.
      const resolvedLimits = op_worker_get_resource_limits();
      if (resolvedLimits) {
        resourceLimits = resolvedLimits;
      } else {
        resourceLimits = {};
      }
      defaultExport.resourceLimits = resourceLimits;

      // Set process.argv for worker threads.
      // In Node.js, worker process.argv is [execPath, scriptPath, ...argv].
      if (isWorkerThread) {
        let scriptPath;
        if (metadata.isEval) {
          scriptPath = "[worker eval]";
        } else if (
          moduleSpecifier &&
          StringPrototypeStartsWith(moduleSpecifier, "file:")
        ) {
          scriptPath = fileURLToPath(moduleSpecifier);
        } else {
          scriptPath = moduleSpecifier ?? "";
        }
        process.argv = [process.execPath, scriptPath];
        if (metadata.argv) {
          for (let i = 0; i < metadata.argv.length; i++) {
            process.argv[i + 2] = metadata.argv[i];
          }
        }

        // Set process.execArgv for worker threads.
        if (metadata.execArgv) {
          process.execArgv = metadata.execArgv;
          for (let i = 0; i < metadata.execArgv.length; i++) {
            if (metadata.execArgv[i] === "--trace-warnings") {
              process.traceProcessWarnings = true;
            }
          }
        }

        // Replace process.stdin with a Readable that receives
        // data from the parent via WORKER_STDIN messages.
        if (metadata.hasStdin) {
          const workerStdin = new Readable({ read() {} });
          process.stdin = workerStdin;

          // Register an early listener to intercept stdin messages
          // before any user-registered handlers. Remove the listener
          // once stdin ends so the worker can exit cleanly.
          const stdinHandler = (ev) => {
            const msg = ev.data;
            if (isWorkerStdinMsg(msg)) {
              // deno-lint-ignore prefer-primordials
              workerStdin.push(msg.data);
              ev.stopImmediatePropagation();
            } else if (isWorkerStdinEndMsg(msg)) {
              // deno-lint-ignore prefer-primordials
              workerStdin.push(null);
              parentPort.removeEventListener("message", stdinHandler);
              ev.stopImmediatePropagation();
            }
          };
          parentPort.addEventListener("message", stdinHandler);
        }

        // Forward stdout writes to the parent so worker.stdout
        // is readable from the host side.
        const origStdoutWrite = FunctionPrototypeBind(
          process.stdout.write,
          process.stdout,
        );
        process.stdout.write = function (chunk, encoding, callback) {
          parentPort.postMessage({
            type: "WORKER_STDOUT",
            data: chunk,
          });
          return FunctionPrototypeCall(
            origStdoutWrite,
            process.stdout,
            chunk,
            encoding,
            callback,
          );
        };

        // Forward stderr writes to the parent so worker.stderr
        // is readable from the host side.
        const origStderrWrite = FunctionPrototypeBind(
          process.stderr.write,
          process.stderr,
        );
        process.stderr.write = function (chunk, encoding, callback) {
          parentPort.postMessage({
            type: "WORKER_STDERR",
            data: chunk,
          });
          return FunctionPrototypeCall(
            origStderrWrite,
            process.stderr,
            chunk,
            encoding,
            callback,
          );
        };
      }
    }
    defaultExport.workerData = workerData;
    defaultExport.parentPort = parentPort;
    defaultExport.threadId = threadId;
    defaultExport.threadName = threadName;

    patchMessagePortIfFound(workerData);

    parentPort.off = parentPort.removeListener = function (
      name,
      listener,
    ) {
      if (listeners.has(listener)) {
        nativeRemoveEventListener(name, listeners.get(listener)!);
        listeners.delete(listener);
        if (name === "message") messageListenerCount--;
      }
      return parentPort;
    };
    parentPort.on = parentPort.addListener = function (
      name,
      listener,
    ) {
      // deno-lint-ignore no-explicit-any
      const _listener = (ev: any) => {
        const message = ev.data;
        patchMessagePortIfFound(message);
        return listener(message);
      };
      listeners.set(listener, _listener);
      nativeAddEventListener(name, _listener);
      if (name === "message") messageListenerCount++;
      return parentPort;
    };

    parentPort.once = function (name, listener) {
      // deno-lint-ignore no-explicit-any
      const _listener = (ev: any) => {
        listeners.delete(listener);
        if (name === "message") messageListenerCount--;
        const message = ev.data;
        patchMessagePortIfFound(message);
        return listener(message);
      };
      listeners.set(listener, _listener);
      nativeAddEventListener(name, _listener, { once: true });
      if (name === "message") messageListenerCount++;
      return parentPort;
    };

    // mocks
    parentPort.setMaxListeners = () => {};
    parentPort.getMaxListeners = () => Infinity;
    parentPort.eventNames = () => [""];
    parentPort.listenerCount = () => 0;

    parentPort.emit = () => notImplemented("parentPort.emit");
    parentPort.removeAllListeners = () =>
      notImplemented("parentPort.removeAllListeners");

    nativeAddEventListener("offline", () => {
      parentPort.emit("close");
    });
    parentPort.unref = () => {
      parentPort[unrefParentPort] = true;
      // Also set on globalThis so runtime/js/99_main.js event loop
      // check (globalThis[unrefParentPort]) still works.
      globalThis[unrefParentPort] = true;
    };
    parentPort.ref = () => {
      parentPort[unrefParentPort] = false;
      globalThis[unrefParentPort] = false;
    };

    if (isWorkerThread) {
      // Notify the host that the worker is online
      parentPort.postMessage(
        {
          type: "WORKER_ONLINE",
        } satisfies WorkerOnlineMsg,
      );
    }
  }
};

export function getEnvironmentData(key: unknown) {
  return environmentData.get(key);
}

export function setEnvironmentData(key: unknown, value?: unknown) {
  if (value === undefined) {
    environmentData.delete(key);
  } else {
    environmentData.set(key, value);
  }
}

export const SHARE_ENV = SymbolFor("nodejs.worker_threads.SHARE_ENV");
export function markAsUntransferable(obj: object) {
  if (core.isArrayBuffer(obj)) {
    op_mark_as_untransferable(obj as ArrayBuffer);
  }
}
export function moveMessagePortToContext() {
  notImplemented("moveMessagePortToContext");
}

/**
 * @param { MessagePort } port
 * @returns {object | undefined}
 */
export function receiveMessageOnPort(port: MessagePort): object | undefined {
  if (!(ObjectPrototypeIsPrototypeOf(MessagePortPrototype, port))) {
    const err = new TypeError(
      'The "port" argument must be a MessagePort instance',
    );
    err["code"] = "ERR_INVALID_ARG_TYPE";
    throw err;
  }
  port[MessagePortReceiveMessageOnPortSymbol] = true;
  const data = op_message_port_recv_message_sync(port[MessagePortIdSymbol]);
  if (data === null) return undefined;
  const message = deserializeJsMessageData(data)[0];
  patchMessagePortIfFound(message);
  return { message };
}

class NodeMessageChannel {
  port1: MessagePort;
  port2: MessagePort;

  constructor() {
    const { port1, port2 } = new MessageChannel();
    this.port1 = webMessagePortToNodeMessagePort(port1);
    this.port2 = webMessagePortToNodeMessagePort(port2);

    // When one port is closed, the paired port should also receive
    // a 'close' event (matching Node.js behavior).
    const origClose1 = FunctionPrototypeBind(port1.close, port1);
    const origClose2 = FunctionPrototypeBind(port2.close, port2);

    port1.close = (...args) => {
      origClose1(...args);
      if (!port2[nodeWorkerThreadCloseCbInvoked]) {
        port2[nodeWorkerThreadCloseCbInvoked] = true;
        port2.dispatchEvent(new Event("close"));
      }
    };
    port2.close = (...args) => {
      origClose2(...args);
      if (!port1[nodeWorkerThreadCloseCbInvoked]) {
        port1[nodeWorkerThreadCloseCbInvoked] = true;
        port1.dispatchEvent(new Event("close"));
      }
    };
  }
}

const listeners = new SafeWeakMap<
  // deno-lint-ignore no-explicit-any
  (...args: any[]) => void,
  // deno-lint-ignore no-explicit-any
  (ev: any) => any
>();

function createNodeMessagePortArgTypeError(message: string) {
  const err = new TypeError(message);
  err.code = "ERR_INVALID_ARG_TYPE";
  return err;
}

function normalizeNodeMessagePortTransferArg(transferOrOptions) {
  if (transferOrOptions === undefined || transferOrOptions === null) {
    return {
      argument: transferOrOptions,
      transferList: [],
    };
  }

  if (ArrayIsArray(transferOrOptions)) {
    return {
      argument: transferOrOptions,
      transferList: transferOrOptions,
    };
  }

  if (typeof transferOrOptions !== "object") {
    throw createNodeMessagePortArgTypeError(
      "Optional transferList argument must be an iterable",
    );
  }

  const iterator = transferOrOptions[SymbolIterator];
  if (iterator !== undefined) {
    if (typeof iterator !== "function") {
      throw createNodeMessagePortArgTypeError(
        "Optional transferList argument must be an iterable",
      );
    }
    try {
      const transferList = ArrayFrom(transferOrOptions);
      return {
        argument: transferList,
        transferList,
      };
    } catch {
      throw createNodeMessagePortArgTypeError(
        "Optional transferList argument must be an iterable",
      );
    }
  }

  const transfer = transferOrOptions.transfer;
  if (transfer === undefined) {
    return {
      argument: transferOrOptions,
      transferList: [],
    };
  }
  if (transfer === null || typeof transfer !== "object") {
    throw createNodeMessagePortArgTypeError(
      "Optional options.transfer argument must be an iterable",
    );
  }
  const transferIterator = transfer[SymbolIterator];
  if (typeof transferIterator !== "function") {
    throw createNodeMessagePortArgTypeError(
      "Optional options.transfer argument must be an iterable",
    );
  }
  try {
    const transferList = ArrayFrom(transfer);
    return {
      argument: { transfer: transferList },
      transferList,
    };
  } catch {
    throw createNodeMessagePortArgTypeError(
      "Optional options.transfer argument must be an iterable",
    );
  }
}

function ensureNodeMessagePortMessagePump(port: MessagePort) {
  if (port[privateNodeMessagePortPumpInstalled] === true) {
    return;
  }

  port[privateNodeMessagePortListeners] = [];
  port[privateNodeMessagePortQueue] = [];
  port.addEventListener("message", (ev) => {
    patchMessagePortIfFound(ev.data);
    const listeners = port[privateNodeMessagePortListeners];
    if (!ArrayIsArray(listeners) || listeners.length === 0) {
      port[privateNodeMessagePortQueue].push(ev.data);
      return;
    }

    for (let i = 0; i < listeners.length; i++) {
      listeners[i](ev.data);
    }
  });
  port.start();
  port[privateNodeMessagePortPumpInstalled] = true;
}

function drainNodeMessagePortQueue(port: MessagePort) {
  const listeners = port[privateNodeMessagePortListeners];
  const queue = port[privateNodeMessagePortQueue];
  if (!ArrayIsArray(listeners) || listeners.length === 0 || !ArrayIsArray(queue)) {
    return;
  }

  while (queue.length > 0) {
    const message = queue.shift();
    for (let i = 0; i < listeners.length; i++) {
      listeners[i](message);
    }
  }
}

if (!ObjectHasOwn(MessagePortPrototype, "ref")) {
  ObjectDefineProperty(MessagePortPrototype, "ref", {
    __proto__: null,
    value: function ref(this: MessagePort) {
      this[privateNodeMessagePortRef] = true;
      this[refMessagePort](true);
      return this;
    },
    writable: true,
    enumerable: false,
    configurable: true,
  });
}

if (!ObjectHasOwn(MessagePortPrototype, "unref")) {
  ObjectDefineProperty(MessagePortPrototype, "unref", {
    __proto__: null,
    value: function unref(this: MessagePort) {
      this[privateNodeMessagePortRef] = false;
      this[refMessagePort](false);
      return this;
    },
    writable: true,
    enumerable: false,
    configurable: true,
  });
}

if (!ObjectHasOwn(MessagePortPrototype, "hasRef")) {
  ObjectDefineProperty(MessagePortPrototype, "hasRef", {
    __proto__: null,
    value: function hasRef(this: MessagePort) {
      return this[privateNodeMessagePortRef] !== false;
    },
    writable: true,
    enumerable: false,
    configurable: true,
  });
}

delete MessagePortPrototype.addEventListener;
delete MessagePortPrototype.removeEventListener;

function webMessagePortToNodeMessagePort(port: MessagePort) {
  const nativeAddEventListener = FunctionPrototypeBind(
    port.addEventListener,
    port,
  );
  const nativeRemoveEventListener = FunctionPrototypeBind(
    port.removeEventListener,
    port,
  );
  ObjectDefineProperty(port, "addEventListener", {
    __proto__: null,
    value: (name, listener, options?) => {
      nativeAddEventListener(name, listener, options);
      if (name === "message" || name === "messageerror") {
        port.start();
      }
    },
    writable: true,
    enumerable: false,
    configurable: true,
  });
  ObjectDefineProperty(port, "removeEventListener", {
    __proto__: null,
    value: (name, listener, options?) => {
      nativeRemoveEventListener(name, listener, options);
    },
    writable: true,
    enumerable: false,
    configurable: true,
  });
  port.on = port.addListener = function (this: MessagePort, name, listener) {
    const _listener = name === "message"
      ? (message) => listener(message)
      // deno-lint-ignore no-explicit-any
      : (ev: any) => {
        if (name === "messageerror") {
          patchMessagePortIfFound(ev.data);
          listener(ev.data);
          return;
        }
        if (name === "close") {
          listener();
          return;
        }
        listener(ev.detail);
      };
    if (name == "message") {
      ensureNodeMessagePortMessagePump(port);
      port[privateNodeMessagePortListeners].push(_listener);
      drainNodeMessagePortQueue(port);
    } else if (name == "messageerror") {
      if (port.onmessageerror === null) {
        port.onmessageerror = _listener;
      } else {
        port.addEventListener("messageerror", _listener);
      }
    } else if (name == "close") {
      port.addEventListener("close", _listener);
    } else {
      port.addEventListener(name, _listener);
    }
    listeners.set(listener, _listener);
    return this;
  };
  port.off = port.removeListener = function (
    this: MessagePort,
    name,
    listener,
  ) {
    const mappedListener = listeners.get(listener)!;
    if (name == "message") {
      const nodeMessageListeners = port[privateNodeMessagePortListeners];
      if (ArrayIsArray(nodeMessageListeners)) {
        const index = nodeMessageListeners.indexOf(mappedListener);
        if (index !== -1) {
          nodeMessageListeners.splice(index, 1);
        }
      }
    } else if (name == "messageerror") {
      if (port.onmessageerror === mappedListener) {
        port.onmessageerror = null;
      } else {
        port.removeEventListener("messageerror", mappedListener);
      }
    } else if (name == "close") {
      port.removeEventListener("close", mappedListener);
    } else {
      port.removeEventListener(name, mappedListener);
    }
    listeners.delete(listener);
    return this;
  };
  port[nodeWorkerThreadCloseCb] = () => {
    port.dispatchEvent(new Event("close"));
  };
  const webClose = FunctionPrototypeBind(port.close, port);
  port.close = (callback?) => {
    const result = webClose();
    if (callback !== undefined) {
      callback();
    }
    return result;
  };
  const webPostMessage = port.postMessage;
  port.postMessage = (message, transferList) => {
    const normalizedTransfer = normalizeNodeMessagePortTransferArg(
      transferList,
    );
    for (let i = 0; i < normalizedTransfer.transferList.length; i++) {
      const item = normalizedTransfer.transferList[i];
      if (item[untransferableSymbol] === true) {
        throw new DOMException("Value not transferable", "DataCloneError");
      }
    }

    return FunctionPrototypeCall(
      webPostMessage,
      port,
      message,
      normalizedTransfer.argument,
    );
  };
  port.once = (name: string | symbol, listener) => {
    if (name === "message") {
      ensureNodeMessagePortMessagePump(port);
      const wrapped = (message) => {
        port.off(name, listener);
        listener(message);
      };
      listeners.set(listener, wrapped);
      port[privateNodeMessagePortListeners].push(wrapped);
      drainNodeMessagePortQueue(port);
      return port;
    }
    // deno-lint-ignore no-explicit-any
    const _listener = (ev: any) => {
      listeners.delete(listener);
      if (name === "messageerror") {
        patchMessagePortIfFound(ev.data);
        listener(ev.data);
        return;
      }
      if (name === "close") {
        listener();
        return;
      }
      listener(ev.detail);
    };
    listeners.set(listener, _listener);
    port.addEventListener(name, _listener, { once: true });
    return port;
  };
  port.emit = function (this: MessagePort, name, value) {
    return this.dispatchEvent(new CustomEvent(name, { detail: value }));
  };
  return port;
}

// TODO(@marvinhagemeister): Recursively iterating over all message
// properties seems slow.
// Maybe there is a way we can patch the prototype of MessagePort _only_
// inside worker_threads? For now correctness is more important than perf.
// deno-lint-ignore no-explicit-any
function patchMessagePortIfFound(data: any, seen = new SafeSet<any>()) {
  if (data === null || typeof data !== "object" || seen.has(data)) {
    return;
  }
  seen.add(data);

  if (ObjectPrototypeIsPrototypeOf(MessagePortPrototype, data)) {
    webMessagePortToNodeMessagePort(data);
  } else {
    for (const obj in data as Record<string, unknown>) {
      if (ObjectHasOwn(data, obj)) {
        patchMessagePortIfFound(data[obj], seen);
      }
    }
  }
}

class BroadcastChannel extends WebBroadcastChannel {
  ref() {
    this[refBroadcastChannel](true);
    return this;
  }

  unref() {
    this[refBroadcastChannel](false);
    return this;
  }
}

export {
  BroadcastChannel,
  MessagePort,
  NodeMessageChannel as MessageChannel,
  NodeWorker as Worker,
  parentPort,
  threadId,
  workerData,
};

const defaultExport = {
  markAsUntransferable,
  moveMessagePortToContext,
  receiveMessageOnPort,
  MessagePort,
  MessageChannel: NodeMessageChannel,
  BroadcastChannel,
  Worker: NodeWorker,
  getEnvironmentData,
  setEnvironmentData,
  SHARE_ENV,
  threadId,
  threadName,
  workerData,
  resourceLimits,
  parentPort,
  isMainThread,
};

export default defaultExport;
