// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and other Node contributors.

(function () {
const { core, primordials } = __bootstrap;
const { Array } = primordials;

const { validateFunction } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);
const { _exiting } = core.loadExtScript("ext:deno_node/_process/exiting.ts");
const {
  emitAfter,
  emitBefore,
  emitDestroy,
  drainDestroyAsyncIds,
  emitInit,
  enabledHooksExist,
  executionAsyncId,
  newAsyncId: nextAsyncId,
} = core.loadExtScript("ext:deno_node/internal/async_hooks.ts");

const {
  getAsyncContext,
} = core;

let nextTickEnabled = false;
function enableNextTick() {
  nextTickEnabled = true;

  // TODO(bartlomieju): ideally this should not be needed
  // and async hook implementation would live in core
  // Register the async hook emit functions directly with core.
  // The core drain loop calls these inline per-tick -- no indirection.
  // drainDestroyAsyncIds is called at the top of each runImmediates() pass so
  // deferred destroys flush BETWEEN immediate snapshots (Node's native
  // DestroyAsyncIdsCallback timing); see async_hooks.ts scheduleDestroyDrain.
  core.setAsyncHooksEmit(
    emitBefore,
    emitAfter,
    emitDestroy,
    drainDestroyAsyncIds,
  );

  // Override the deno_core global queueMicrotask (libs/core/01_core.js) with a
  // Node-faithful version. The core implementation enqueues the callback raw
  // and never creates an AsyncResource, so a microtask scheduled while
  // async_hooks tracking is on reads the stack-bottom triggerAsyncId (0)
  // instead of the enclosing async id. Mirrors lib/internal/process/task_queues.js
  // queueMicrotask: wrap in AsyncResource('Microtask') + runInAsyncScope when
  // hooks (or an async context) are active, otherwise keep the core fast path.
  // Loaded lazily here (at bootstrap, after all modules register) to avoid an
  // eager load-graph cycle through async_hooks.ts.
  const { AsyncResource } = core.loadExtScript(
    "ext:deno_node/async_hooks.ts",
  );
  const coreQueueMicrotask = globalThis.queueMicrotask;
  function queueMicrotask(callback: () => void) {
    validateFunction(callback, "callback");
    if (getAsyncContext() || enabledHooksExist()) {
      const asyncResource = new AsyncResource("Microtask", {
        requireManualDestroy: true,
      });
      coreQueueMicrotask(() => {
        try {
          asyncResource.runInAsyncScope(callback);
        } finally {
          asyncResource.emitDestroy();
        }
      });
    } else {
      // Fast path: no async hooks and no async context in use.
      coreQueueMicrotask(callback);
    }
  }
  globalThis.queueMicrotask = queueMicrotask;
}

// Re-export from core for consumers (e.g. timers.mjs)
const processTicksAndRejections = core.processTicksAndRejections;
const runNextTicks = core.runNextTicks;

// `nextTick()` will not enqueue any callback when the process is about to
// exit since the callback would not have a chance to be executed.
function nextTick(this: unknown, callback: () => void): void;
function nextTick<T extends Array<unknown>>(
  this: unknown,
  callback: (...args: T) => void,
  ...args: T
): void;
function nextTick<T extends Array<unknown>>(
  this: unknown,
  callback: (...args: T) => void,
  ...args: T
) {
  // If we're snapshotting we don't want to push nextTick to be run. We'll
  // enable next ticks in "__bootstrapNodeProcess()";
  if (!nextTickEnabled) {
    return;
  }

  validateFunction(callback, "callback");

  if (_exiting) {
    return;
  }

  // TODO(bartlomieju): seems superfluous if we don't depend on `arguments`
  let args_;
  switch (args.length) {
    case 0:
      break;
    case 1:
      args_ = [args[0]];
      break;
    case 2:
      args_ = [args[0], args[1]];
      break;
    case 3:
      args_ = [args[0], args[1], args[2]];
      break;
    default:
      args_ = new Array(args.length);
      for (let i = 0; i < args.length; i++) {
        args_[i] = args[i];
      }
  }

  const asyncId = nextAsyncId();
  const triggerAsyncId = executionAsyncId();
  const tickObject = {
    asyncId,
    triggerAsyncId,
    snapshot: getAsyncContext(),
    callback,
    args: args_,
  };
  emitInit(asyncId, "TickObject", triggerAsyncId, tickObject);
  if (!core.hasTickScheduled()) {
    core.setHasTickScheduled(true);
  }
  core.queueNextTick(tickObject);
}

return {
  enableNextTick,
  nextTick,
  processTicksAndRejections,
  runNextTicks,
};
})();
