// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

// TODO(petamoriken): enable prefer-primordials for node polyfills
// deno-lint-ignore-file prefer-primordials

(function () {
const { core, primordials } = __bootstrap;
const {
  validateFunction,
  validateObject,
} = core.loadExtScript("ext:deno_node/internal/validators.mjs");
const {
  ERR_ASYNC_TYPE,
  ERR_INVALID_ARG_TYPE,
  ERR_INVALID_ASYNC_ID,
} = core.loadExtScript("ext:deno_node/internal/errors.ts");
const asyncWrapBinding = core.loadExtScript(
  "ext:deno_node/internal_binding/async_wrap.ts",
);
const {
  AsyncHook,
  emitAfter,
  emitBefore,
  emitDestroy: emitDestroyHook,
  emitInit,
  enterAsyncResource,
  exitAsyncResource,
  executionAsyncId: internalExecutionAsyncId,
  triggerAsyncId: internalTriggerAsyncId,
  executionAsyncResource: internalExecutionAsyncResource,
  newAsyncId,
} = core.loadExtScript("ext:deno_node/internal/async_hooks.ts");

const {
  ObjectDefineProperties,
  ReflectApply,
  FunctionPrototypeBind,
  ArrayPrototypeUnshift,
  ObjectFreeze,
  NumberIsSafeInteger,
} = primordials;

const {
  AsyncVariable,
  getAsyncContext,
  setAsyncContext,
} = core;

// FinalizationRegistry to emit the async hook destroy callback when an
// AsyncResource is garbage collected, matching Node.js behaviour.
const asyncResourceRegistry = new FinalizationRegistry(
  (asyncId: number) => emitDestroyHook(asyncId),
);

class AsyncResource {
  type: string;
  #snapshot: unknown;
  #asyncId: number;
  #triggerAsyncId: number;

  constructor(
    type: string,
    opts: number | { triggerAsyncId?: number; requireManualDestroy?: boolean } =
      {},
  ) {
    if (typeof type !== "string") {
      throw new ERR_INVALID_ARG_TYPE("type", "string", type);
    }
    if (type.length <= 0) {
      throw new ERR_ASYNC_TYPE(type);
    }

    let triggerAsyncId: number;
    let requireManualDestroy = false;
    if (typeof opts === "number") {
      triggerAsyncId = opts;
    } else {
      const optTrigger = (opts as { triggerAsyncId?: number }).triggerAsyncId;
      triggerAsyncId = optTrigger === undefined
        ? internalExecutionAsyncId()
        : optTrigger;
      requireManualDestroy =
        ((opts as { requireManualDestroy?: boolean }).requireManualDestroy) ??
          false;
    }

    if (!NumberIsSafeInteger(triggerAsyncId) || triggerAsyncId < -1) {
      throw new ERR_INVALID_ASYNC_ID("triggerAsyncId", triggerAsyncId);
    }

    this.type = type;
    this.#snapshot = getAsyncContext();
    this.#asyncId = newAsyncId();
    this.#triggerAsyncId = triggerAsyncId;
    // Fire the init hook so that async_hooks.createHook({ init }) callbacks
    // receive this resource, matching Node.js behaviour.
    emitInit(this.#asyncId, type, this.#triggerAsyncId, this);
    // Register with the FinalizationRegistry so emitDestroy is called when
    // this object is garbage collected (unless the caller opts out).
    if (!requireManualDestroy) {
      asyncResourceRegistry.register(this, this.#asyncId, this);
    }
  }

  asyncId() {
    return this.#asyncId;
  }

  triggerAsyncId() {
    return this.#triggerAsyncId;
  }

  runInAsyncScope(
    fn: (...args: unknown[]) => unknown,
    thisArg: unknown,
    ...args: unknown[]
  ) {
    const previousContext = getAsyncContext();
    // Pass `this` as the resource so emitBefore establishes it as the
    // synchronously-active executionAsyncResource() BEFORE any user before()
    // hook runs (Node: emitBefore(asyncId, triggerAsyncId, this) ->
    // pushAsyncContext). emitAfter (in the finally below) pops it only after the
    // user after() hook has run, so before/during/after all observe `this`.
    emitBefore(this.#asyncId, this.#triggerAsyncId, this);
    try {
      setAsyncContext(this.#snapshot);
      // Also enter this resource into the AsyncVariable so promise continuations
      // created inside the scope inherit `this` across await transitions. The
      // synchronous executionAsyncResource() value is already supplied by the
      // emitBefore resource-stack push above.
      const prevResource = enterAsyncResource(this);
      try {
        return ReflectApply(fn, thisArg, args);
      } finally {
        exitAsyncResource(prevResource);
      }
    } finally {
      setAsyncContext(previousContext);
      emitAfter(this.#asyncId);
    }
  }

  emitDestroy() {
    asyncResourceRegistry.unregister(this);
    emitDestroyHook(this.#asyncId);
    return this;
  }

  bind(fn: (...args: unknown[]) => unknown, thisArg) {
    validateFunction(fn, "fn");
    let bound;
    if (thisArg === undefined) {
      // deno-lint-ignore no-this-alias
      const resource = this;
      bound = function (...args) {
        ArrayPrototypeUnshift(args, fn, this);
        return ReflectApply(resource.runInAsyncScope, resource, args);
      };
    } else {
      bound = FunctionPrototypeBind(this.runInAsyncScope, this, fn, thisArg);
    }
    ObjectDefineProperties(bound, {
      "length": {
        __proto__: null,
        configurable: true,
        enumerable: false,
        value: fn.length,
        writable: false,
      },
    });
    return bound;
  }

  static bind(
    fn: (...args: unknown[]) => unknown,
    type?: string,
    thisArg?: AsyncResource,
  ) {
    type = type || fn.name || "bound-anonymous-fn";
    return (new AsyncResource(type)).bind(fn, thisArg);
  }
}

class AsyncLocalStorage {
  #variable = new AsyncVariable();
  // deno-lint-ignore no-explicit-any
  #defaultValue: any = undefined;
  #name = "";
  enabled = false;

  constructor(options: { defaultValue?: unknown; name?: string } = {}) {
    validateObject(options, "options");
    this.#defaultValue = options.defaultValue;
    if (options.name !== undefined) {
      this.#name = `${options.name}`;
    }
  }

  get name() {
    return this.#name;
  }

  // deno-lint-ignore no-explicit-any
  run(store: any, callback: any, ...args: any[]): any {
    this.enabled = true;
    // Save just this variable's previous slot value so that nested
    // enterWith()/run() calls on *other* AsyncLocalStorage instances during
    // the callback are not reverted when we return - only our slot is.
    const oldStore = this.#variable.get();
    this.#variable.enter(store);
    try {
      return ReflectApply(callback, null, args);
    } finally {
      this.#variable.enter(oldStore);
    }
  }

  // deno-lint-ignore no-explicit-any
  exit(callback: (...args: unknown[]) => any, ...args: any[]): any {
    if (!this.enabled) {
      return ReflectApply(callback, null, args);
    }
    // Node 24's AsyncContextFrame model implements exit() as run(undefined, fn)
    // (lib/internal/async_local_storage/async_context_frame.js:71-73). The fork
    // is backed by AsyncVariable (V8 ContinuationPreservedEmbedderData), the same
    // frame model, so entering an `undefined` store propagates across `await`
    // boundaries - unlike the previous flag toggle, whose `finally` restored
    // `enabled` at the first suspension and leaked the enclosing store
    // (test/async-hooks/test-async-local-storage-async-functions.js).
    return this.run(undefined, callback, ...args);
  }

  // deno-lint-ignore no-explicit-any
  getStore(): any {
    if (!this.enabled) {
      return this.#defaultValue;
    }
    const value = this.#variable.get();
    return value === undefined ? this.#defaultValue : value;
  }

  enterWith(store: unknown) {
    this.enabled = true;
    this.#variable.enter(store);
  }

  disable() {
    this.enabled = false;
  }

  static bind(fn: (...args: unknown[]) => unknown) {
    return AsyncResource.bind(fn);
  }

  static snapshot() {
    const resource = new AsyncResource("AsyncLocalStorage.snapshot");
    return function (cb: (...args: unknown[]) => unknown, ...args: unknown[]) {
      return resource.runInAsyncScope(cb, null, ...args);
    };
  }
}

// Re-export executionAsyncId from internal
const executionAsyncId = internalExecutionAsyncId;
const triggerAsyncId = internalTriggerAsyncId;

const executionAsyncResource = internalExecutionAsyncResource;

// Derived from the single source of truth in internal_binding/async_wrap.ts so
// that `asyncWrapProviders` and `internalBinding('async_wrap').Providers` can
// never drift apart (test/async-hooks/test-async-wrap-providers.js asserts they
// are deep-equal). Frozen to satisfy the same fixture's "cannot modify" check.
const asyncWrapProviders = ObjectFreeze({
  __proto__: null,
  ...asyncWrapBinding.Providers,
});

// Use the AsyncHook from the internal module
function createHook(callbacks: {
  init?: (
    asyncId: number,
    type: string,
    triggerAsyncId: number,
    resource: unknown,
  ) => void;
  before?: (asyncId: number) => void;
  after?: (asyncId: number) => void;
  destroy?: (asyncId: number) => void;
  promiseResolve?: (asyncId: number) => void;
}) {
  return new AsyncHook(callbacks);
}

return {
  default: {
    AsyncLocalStorage,
    createHook,
    executionAsyncId,
    triggerAsyncId,
    executionAsyncResource,
    asyncWrapProviders,
    AsyncResource,
  },
  AsyncLocalStorage,
  AsyncResource,
  createHook,
  executionAsyncId,
  triggerAsyncId,
  executionAsyncResource,
  asyncWrapProviders,
};
})();
