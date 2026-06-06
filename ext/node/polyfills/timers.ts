// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const {
  DateNow,
  FunctionPrototypeBind,
  FunctionPrototypeCall,
  ObjectCreate,
  ObjectDefineProperty,
  Promise,
  PromiseReject,
  PromiseWithResolvers,
  ReflectApply,
  SafeArrayIterator,
  SafePromisePrototypeFinally,
} = primordials;
const {
  getActiveTimer,
  getTimerDuration,
  Immediate,
  kDestroy,
  Timeout,
} = core.loadExtScript("ext:deno_node/internal/timers.mjs");
const {
  validateAbortSignal,
  validateBoolean,
  validateFunction,
  validateNumber,
  validateObject,
} = core.loadExtScript("ext:deno_node/internal/validators.mjs");
const { kEmptyObject, promisify } = core.loadExtScript(
  "ext:deno_node/internal/util.mjs",
);
const {
  AbortError,
  ERR_ILLEGAL_CONSTRUCTOR,
} = core.loadExtScript("ext:deno_node/internal/errors.ts");
const lazyEventTarget = core.createLazyLoader(
  "ext:deno_node/internal/event_target.mjs",
);
// `util.deprecate` lives in the heavy `node:util` subtree. timers.ts is loaded
// early (before util in 01_require.js), so it must NOT eager-load util.ts at
// module body or the whole util subtree gets pulled into the snapshot. Resolve
// `deprecate` on first *call* of a legacy timer method instead: by then util.ts
// has already been loaded by 01_require.js, so loadExtScript returns the cached
// module. (createLazyLoader does not work here -- util.ts is not registered as a
// lazy-loadable ESM.)
let cachedDeprecate;
function makeDeprecated(fn, msg, code) {
  let wrapped;
  function deprecatedTimerFn(...args) {
    if (wrapped === undefined) {
      cachedDeprecate ??=
        core.loadExtScript("ext:deno_node/util.ts").deprecate;
      // modifyPrototype:false - these wrap plain functions with no meaningful
      // prototype chain, and we never construct them.
      wrapped = cachedDeprecate(fn, msg, code, {
        __proto__: null,
        modifyPrototype: false,
      });
    }
    return ReflectApply(wrapped, this, args);
  }
  return deprecatedTimerFn;
}

interface TimerOptions {
  signal?: AbortSignal | undefined;
  ref?: boolean | undefined;
}

function setTimeout(
  callback: (...args: unknown[]) => void,
  timeout?: number,
  ...args: unknown[]
) {
  validateFunction(callback, "callback");
  return new Timeout(callback, timeout, args, false, true);
}

function cancelListenerHandler(
  clear: typeof clearTimeout,
  reject: typeof PromiseReject,
  signal: AbortSignal | undefined,
) {
  if (!this._destroyed) {
    clear(this);
    reject(new AbortError(undefined, { cause: signal?.reason }));
  }
}

function setTimeoutPromise<T = void>(
  after: number | undefined,
  value: T,
  options: TimerOptions = kEmptyObject,
): Promise<T> {
  try {
    if (typeof after !== "undefined") {
      validateNumber(after, "delay");
    }

    validateObject(options, "options");

    if (typeof options?.signal !== "undefined") {
      validateAbortSignal(options.signal, "options.signal");
    }

    if (typeof options?.ref !== "undefined") {
      validateBoolean(options.ref, "options.ref");
    }
  } catch (err) {
    return PromiseReject(err);
  }

  const { signal, ref = true } = options;

  if (signal?.aborted) {
    return PromiseReject(new AbortError(undefined, { cause: signal.reason }));
  }

  let oncancel: EventListenerOrEventListenerObject | undefined;
  const { promise, resolve, reject } = PromiseWithResolvers();
  const timeout = new Timeout(resolve, after, [value], false, ref);
  if (signal) {
    oncancel = FunctionPrototypeBind(
      cancelListenerHandler,
      timeout,
      clearTimeout,
      reject,
      signal,
    );

    signal.addEventListener("abort", oncancel, {
      __proto__: null,
      [lazyEventTarget().kResistStopPropagation]: true,
    });
  }

  return oncancel !== undefined
    ? SafePromisePrototypeFinally(
      promise,
      () => signal!.removeEventListener("abort", oncancel),
    )
    : promise;
}

ObjectDefineProperty(setTimeoutPromise, "name", {
  __proto__: null,
  value: "setTimeout",
});

ObjectDefineProperty(setTimeout, promisify.custom, {
  __proto__: null,
  enumerable: true,
  get() {
    return setTimeoutPromise;
  },
});

function clearTimeout(timeout?: Timeout | number) {
  if (timeout == null) {
    return;
  }
  const id = +timeout;
  getActiveTimer(id)?.[kDestroy]();
}
function setInterval(
  callback: (...args: unknown[]) => void,
  timeout?: number,
  ...args: unknown[]
) {
  validateFunction(callback, "callback");
  return new Timeout(callback, timeout, args, true, true);
}
function clearInterval(timeout?: Timeout | number | string) {
  if (timeout == null) {
    return;
  }
  const id = +timeout;
  getActiveTimer(id)?.[kDestroy]();
}
function setImmediate(
  cb: (...args: unknown[]) => void,
  ...args: unknown[]
): Timeout {
  validateFunction(cb, "callback");
  return new Immediate(cb, ...new SafeArrayIterator(args));
}

function setImmediatePromise<T = void>(
  value?: T,
  options: TimerOptions = kEmptyObject,
): Promise<T> {
  try {
    validateObject(options, "options");

    if (typeof options?.signal !== "undefined") {
      validateAbortSignal(options.signal, "options.signal");
    }

    if (typeof options?.ref !== "undefined") {
      validateBoolean(options.ref, "options.ref");
    }
  } catch (err) {
    return PromiseReject(err);
  }

  const { signal, ref = true } = options;

  if (signal?.aborted) {
    return PromiseReject(new AbortError(undefined, { cause: signal.reason }));
  }

  let oncancel: EventListenerOrEventListenerObject | undefined;
  const { promise, resolve, reject } = PromiseWithResolvers();
  const immediate = new Immediate(() => resolve(value));
  if (!ref) {
    immediate.unref();
  }
  if (signal) {
    oncancel = FunctionPrototypeBind(
      cancelListenerHandler,
      immediate,
      clearImmediate,
      reject,
      signal,
    );

    signal.addEventListener("abort", oncancel, {
      __proto__: null,
      [lazyEventTarget().kResistStopPropagation]: true,
    });
  }

  return oncancel !== undefined
    ? SafePromisePrototypeFinally(
      promise,
      () => signal!.removeEventListener("abort", oncancel),
    )
    : promise;
}

ObjectDefineProperty(setImmediatePromise, "name", {
  __proto__: null,
  value: "setImmediate",
});

ObjectDefineProperty(setImmediate, promisify.custom, {
  __proto__: null,
  enumerable: true,
  get() {
    return setImmediatePromise;
  },
});

function clearImmediate(immediate: Immediate) {
  if (!immediate?._onImmediate || immediate._destroyed) {
    return;
  }
  core.clearImmediate(immediate);
}

async function* setIntervalAsync(
  after: number,
  value: number,
  options: { signal?: AbortSignal; ref?: boolean } = { __proto__: null },
) {
  validateObject(options, "options");

  if (typeof options?.signal !== "undefined") {
    validateAbortSignal(options.signal, "options.signal");
  }

  if (typeof options?.ref !== "undefined") {
    validateBoolean(options.ref, "options.ref");
  }

  const { signal, ref = true } = options;

  if (signal?.aborted) {
    throw new AbortError(undefined, { cause: signal?.reason });
  }

  let onCancel: (() => void) | undefined = undefined;
  let interval: Timeout | undefined = undefined;
  try {
    let notYielded = 0;
    let callback: ((value?: object) => void) | undefined = undefined;
    let rejectCallback: ((message?: string) => void) | undefined = undefined;
    interval = new Timeout(
      () => {
        notYielded++;
        if (callback) {
          callback();
          callback = undefined;
          rejectCallback = undefined;
        }
      },
      after,
      [],
      true,
      ref,
    );
    if (signal) {
      onCancel = () => {
        clearInterval(interval);
        if (rejectCallback) {
          rejectCallback(signal.reason);
          callback = undefined;
          rejectCallback = undefined;
        }
      };
      signal.addEventListener("abort", onCancel, { once: true });
    }
    while (!signal?.aborted) {
      if (notYielded === 0) {
        await new Promise((resolve: () => void, reject: () => void) => {
          callback = resolve;
          rejectCallback = reject;
        });
      }
      for (; notYielded > 0; notYielded--) {
        yield value;
      }
    }
    throw new AbortError(undefined, { cause: signal?.reason });
  } catch (error) {
    if (signal?.aborted) {
      throw new AbortError(undefined, { cause: signal?.reason });
    }
    throw error;
  } finally {
    if (interval) {
      clearInterval(interval);
    }
    if (onCancel) {
      signal?.removeEventListener("abort", onCancel);
    }
  }
}

// --- Legacy enroll()/unenroll()/active()/_unrefActive() (DEP0095/96/126/127) ---
//
// Node's legacy timer API lets a plain object act as a timer by carrying an
// `_onTimeout` method (lib/timers.js + lib/internal/timers.js). Upstream backs
// it with the global timerListMap linked-list machinery; this fork has no such
// machinery, so we faithfully reproduce the *observable* contract on top of the
// Timeout class: enroll() records the (validated) duration without starting,
// active()/_unrefActive() start a refed/unrefed Timeout whose callback invokes
// item._onTimeout(), and unenroll() cancels it. The hidden Timeout is stashed on
// the enrolled object under `kEnrollTimer`. All four are runtime-deprecated.
const kEnrollTimer = Symbol("kEnrollTimer");

// Cancel a timer. Resets the relevant private fields so a later active() can
// re-insert it, mirroring lib/timers.js#unenroll's `item._idleTimeout = -1`.
function unenrollImpl(item) {
  const timer = item[kEnrollTimer];
  if (timer !== undefined && timer !== null) {
    timer[kDestroy]();
    item[kEnrollTimer] = undefined;
  }
  item._idleNext = null;
  item._idlePrev = null;
  item._idleTimeout = -1;
}

// Make a regular object able to act as a timer. Does not start the timer; see
// active(). Mirrors lib/timers.js#enroll (validate -> unenroll-if-listed ->
// L.init -> set _idleTimeout).
function enrollImpl(item, msecs) {
  msecs = getTimerDuration(msecs, "msecs");

  // If this item was already enrolled, unenroll it from the previous schedule.
  if (item._idleNext) {
    unenrollImpl(item);
  }

  // L.init(item): the item is its own (single-element) list head.
  item._idleNext = item;
  item._idlePrev = item;
  item._idleTimeout = msecs;
}

// Schedule or re-schedule a previously enroll()'d item. `refed` controls whether
// it keeps the event loop alive (active=refed, _unrefActive=unrefed). Mirrors
// lib/internal/timers.js#insertGuarded.
function insertGuardedImpl(item, refed) {
  const msecs = item._idleTimeout;
  if (msecs < 0 || msecs === undefined) {
    return;
  }

  // active() may be called repeatedly to refresh; drop any prior schedule first.
  const prev = item[kEnrollTimer];
  if (prev !== undefined && prev !== null) {
    prev[kDestroy]();
  }

  // Mirror lib/internal/timers.js#insert: stamp the idle start and link the item
  // into a (single-element) list so the legacy private fields are populated, as
  // test-timers-active asserts (_idleStart integer, _idleNext/_idlePrev truthy).
  item._idleStart = DateNow();
  item._idleNext = item;
  item._idlePrev = item;

  const timer = new Timeout(
    function () {
      // One-shot: the underlying Timeout destroys itself after firing, so clear
      // our back-reference before invoking user code (which may re-enroll).
      item[kEnrollTimer] = undefined;
      const cb = item._onTimeout;
      if (typeof cb === "function") {
        FunctionPrototypeCall(cb, item);
      }
    },
    msecs,
    [],
    false,
    refed,
  );
  item[kEnrollTimer] = timer;
}

function activeImpl(item) {
  insertGuardedImpl(item, true);
}

function unrefActiveImpl(item) {
  insertGuardedImpl(item, false);
}

const enroll = makeDeprecated(
  enrollImpl,
  "timers.enroll() is deprecated. Please use setTimeout instead.",
  "DEP0095",
);
const unenroll = makeDeprecated(
  unenrollImpl,
  "timers.unenroll() is deprecated. Please use clearTimeout instead.",
  "DEP0096",
);
const active = makeDeprecated(
  activeImpl,
  "timers.active() is deprecated. Please use timeout.refresh() instead.",
  "DEP0126",
);
const _unrefActive = makeDeprecated(
  unrefActiveImpl,
  "timers._unrefActive() is deprecated. Please use timeout.refresh() instead.",
  "DEP0127",
);

const promises = {
  setTimeout: setTimeoutPromise,
  setImmediate: setImmediatePromise,
  setInterval: setIntervalAsync,
};

class Scheduler {
  constructor() {
    throw new ERR_ILLEGAL_CONSTRUCTOR();
  }
  async wait(
    delay: number,
    options?: { signal?: AbortSignal },
  ): Promise<void> {
    return await setTimeoutPromise(delay, undefined, options);
  }
  yield() {
    return promises.setImmediate();
  }
}

const scheduler = ObjectCreate(Scheduler.prototype);
promises.scheduler = scheduler;

return {
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  setImmediate,
  clearImmediate,
  enroll,
  unenroll,
  active,
  _unrefActive,
  promises,
};
})();
