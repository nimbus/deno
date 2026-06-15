// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

// deno-lint-ignore-file ban-untagged-todo

(function () {
const { core, primordials } = __bootstrap;
const { ERR_INVALID_ARG_TYPE } = core.loadExtScript(
  "ext:deno_node/internal/errors.ts",
);
const { nextTick } = core.loadExtScript("ext:deno_node/_next_tick.ts");
const { validateFunction } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);

const {
  ArrayPrototypeAt,
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypePushApply,
  ArrayPrototypeSlice,
  ArrayPrototypeSplice,
  ObjectDefineProperty,
  ObjectGetPrototypeOf,
  ObjectSetPrototypeOf,
  PromisePrototypeThen,
  PromiseReject,
  ReflectApply,
  SafeArrayIterator,
  SafeFinalizationRegistry,
  SafeMap,
  SafeMapIterator,
  SymbolDispose,
  SymbolHasInstance,
} = primordials;
const { WeakReference } = core.loadExtScript(
  "ext:deno_node/internal/util.mjs",
);

// Can't delete when weakref count reaches 0 as it could increment again.
// Only GC can be used as a valid time to clean up the channels map.
class WeakRefMap extends SafeMap {
  #finalizers = new SafeFinalizationRegistry((key) => {
    // Finalization can run after a new Channel for the same key has already
    // replaced the previous WeakRef (test-diagnostics-channel-gc-race-
    // condition exercises this race). Only drop the entry if the live
    // WeakRef is empty; otherwise the new Channel would be orphaned and
    // `channel(name)` would hand out a fresh one, breaking identity.
    if (!this.has(key)) this.delete(key);
  });

  set(key, value) {
    this.#finalizers.register(value, key);
    return super.set(key, new WeakReference(value));
  }

  get(key) {
    return super.get(key)?.get();
  }

  has(key) {
    return !!this.get(key);
  }

  incRef(key) {
    return super.get(key)?.incRef();
  }

  decRef(key) {
    return super.get(key)?.decRef();
  }
}

function markActive(channel) {
  ObjectSetPrototypeOf(channel, ActiveChannel.prototype);
  channel._subscribers = [];
  channel._stores = new SafeMap();
}

function maybeMarkInactive(channel) {
  // When there are no more active subscribers or bound, restore to fast prototype.
  if (!channel._subscribers.length && !channel._stores.size) {
    ObjectSetPrototypeOf(channel, Channel.prototype);
    channel._subscribers = undefined;
    channel._stores = undefined;
  }
}

function triggerUncaughtException(err) {
  nextTick(() => {
    if (globalThis.process?._fatalException?.(err, false)) {
      return;
    }
    throw err;
  });
}

class RunStoresScope {
  #scopes = [];
  #disposed = false;

  constructor(activeChannel, data) {
    if (activeChannel._stores) {
      for (const entry of new SafeMapIterator(activeChannel._stores)) {
        const store = entry[0];
        const transform = entry[1];

        let context = data;
        if (transform) {
          try {
            context = transform(data);
          } catch (err) {
            triggerUncaughtException(err);
            continue;
          }
        }

        ArrayPrototypePush(this.#scopes, store.withScope(context));
      }
    }

    activeChannel.publish(data);
  }

  [SymbolDispose]() {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    for (let i = this.#scopes.length - 1; i >= 0; i--) {
      this.#scopes[i][SymbolDispose]();
    }
  }
}

class ActiveChannel {
  subscribe(subscription) {
    validateFunction(subscription, "subscription");
    // Replace the subscriber array with a copy so any in-flight publish that
    // captured the previous reference keeps iterating over the snapshot
    // it started with.
    this._subscribers = ArrayPrototypeSlice(this._subscribers);
    ArrayPrototypePush(this._subscribers, subscription);
    channels.incRef(this.name);
  }

  unsubscribe(subscription) {
    const index = ArrayPrototypeIndexOf(this._subscribers, subscription);
    if (index === -1) return false;

    // Build a new array via slice + pushApply so a concurrent publish keeps
    // iterating over its original snapshot - matches Node and lets
    // unsubscribe-during-publish still deliver to the remaining subscribers
    // in that publish call.
    const before = ArrayPrototypeSlice(this._subscribers, 0, index);
    const after = ArrayPrototypeSlice(this._subscribers, index + 1);
    this._subscribers = before;
    ArrayPrototypePushApply(this._subscribers, after);

    channels.decRef(this.name);
    maybeMarkInactive(this);

    return true;
  }

  bindStore(store, transform) {
    const replacing = this._stores.has(store);
    if (!replacing) channels.incRef(this.name);
    this._stores.set(store, transform);
  }

  unbindStore(store) {
    if (!this._stores.has(store)) {
      return false;
    }

    this._stores.delete(store);

    channels.decRef(this.name);
    maybeMarkInactive(this);

    return true;
  }

  get hasSubscribers() {
    return true;
  }

  publish(data) {
    // Capture the subscriber array up front so that subscribe/unsubscribe
    // calls from inside a handler (which replace `this._subscribers` with a
    // new array) don't shift or shrink the array we're walking.
    const subscribers = this._subscribers;
    for (let i = 0; i < (subscribers?.length || 0); i++) {
      try {
        const onMessage = subscribers[i];
        onMessage(data, this.name);
      } catch (err) {
        triggerUncaughtException(err);
      }
    }
  }

  withStoreScope(data) {
    return new RunStoresScope(this, data);
  }

  runStores(data, fn, thisArg, ...args) {
    const scope = this.withStoreScope(data);
    try {
      return ReflectApply(fn, thisArg, args);
    } finally {
      scope[SymbolDispose]();
    }
  }
}

class Channel {
  constructor(name) {
    this._subscribers = undefined;
    this._stores = undefined;
    this.name = name;

    channels.set(name, this);
  }

  static [SymbolHasInstance](instance) {
    const prototype = ObjectGetPrototypeOf(instance);
    return prototype === Channel.prototype ||
      prototype === ActiveChannel.prototype;
  }

  subscribe(subscription) {
    markActive(this);
    this.subscribe(subscription);
  }

  unsubscribe() {
    return false;
  }

  bindStore(store, transform) {
    markActive(this);
    this.bindStore(store, transform);
  }

  unbindStore() {
    return false;
  }

  get hasSubscribers() {
    return false;
  }

  publish() {}

  runStores(_data, fn, thisArg, ...args) {
    return ReflectApply(fn, thisArg, args);
  }

  withStoreScope() {
    return {
      [SymbolDispose]() {},
    };
  }
}

const channels = new WeakRefMap();

function channel(name) {
  const ch = channels.get(name);
  if (ch) return ch;

  if (typeof name !== "string" && typeof name !== "symbol") {
    throw new ERR_INVALID_ARG_TYPE("channel", ["string", "symbol"], name);
  }

  return new Channel(name);
}

function subscribe(name, subscription) {
  return channel(name).subscribe(subscription);
}

function unsubscribe(name, subscription) {
  return channel(name).unsubscribe(subscription);
}

function hasSubscribers(name) {
  const ch = channels.get(name);
  if (!ch) return false;

  return ch.hasSubscribers;
}

const boundedEvents = [
  "start",
  "end",
];

function assertChannel(value, name) {
  // Channel defines a custom [Symbol.hasInstance] (accepting both Channel and
  // ActiveChannel prototypes), so this instanceof must stay to preserve that
  // behavior; ObjectPrototypeIsPrototypeOf would bypass it.
  // deno-lint-ignore prefer-primordials
  if (!(value instanceof Channel)) {
    throw new ERR_INVALID_ARG_TYPE(name, ["Channel"], value);
  }
}

function emitNonThenableWarning(fn) {
  globalThis.process?.emitWarning?.(
    `tracePromise was called with the function '${fn.name || "<anonymous>"}', ` +
      "which returned a non-thenable.",
  );
}

function channelFromMap(nameOrChannels, name, className) {
  if (typeof nameOrChannels === "string") {
    return channel(`tracing:${nameOrChannels}:${name}`);
  }

  if (typeof nameOrChannels === "object" && nameOrChannels !== null) {
    const ch = nameOrChannels[name];
    assertChannel(ch, `nameOrChannels.${name}`);
    return ch;
  }

  throw new ERR_INVALID_ARG_TYPE("nameOrChannels", [
    "string",
    "object",
    className,
  ], nameOrChannels);
}

class BoundedChannelScope {
  #context;
  #end;
  #scope;

  constructor(boundedChannel, context) {
    if (!boundedChannel.hasSubscribers) {
      return;
    }

    const { start, end } = boundedChannel;
    this.#context = context;
    this.#end = end;
    this.#scope = new RunStoresScope(start, context);
  }

  [SymbolDispose]() {
    if (!this.#scope) {
      return;
    }

    this.#end.publish(this.#context);
    this.#scope[SymbolDispose]();
    this.#scope = undefined;
  }
}

class BoundedChannel {
  constructor(nameOrChannels) {
    for (const eventName of new SafeArrayIterator(boundedEvents)) {
      ObjectDefineProperty(this, eventName, {
        __proto__: null,
        value: channelFromMap(nameOrChannels, eventName, "BoundedChannel"),
      });
    }
  }

  get hasSubscribers() {
    return this.start?.hasSubscribers || this.end?.hasSubscribers;
  }

  subscribe(handlers) {
    for (const name of new SafeArrayIterator(boundedEvents)) {
      if (!handlers[name]) continue;

      this[name]?.subscribe(handlers[name]);
    }
  }

  unsubscribe(handlers) {
    let done = true;

    for (const name of new SafeArrayIterator(boundedEvents)) {
      if (!handlers[name]) continue;

      if (!this[name]?.unsubscribe(handlers[name])) {
        done = false;
      }
    }

    return done;
  }

  withScope(context = { __proto__: null }) {
    return new BoundedChannelScope(this, context);
  }

  run(context, fn, thisArg, ...args) {
    context ??= { __proto__: null };
    const scope = this.withScope(context);
    try {
      return ReflectApply(fn, thisArg, args);
    } finally {
      scope[SymbolDispose]();
    }
  }
}

function boundedChannel(nameOrChannels) {
  return new BoundedChannel(nameOrChannels);
}

class TracingChannel {
  #callWindow;
  #continuationWindow;

  constructor(nameOrChannels) {
    if (typeof nameOrChannels === "string") {
      this.#callWindow = new BoundedChannel(nameOrChannels);
      this.#continuationWindow = new BoundedChannel({
        start: channel(`tracing:${nameOrChannels}:asyncStart`),
        end: channel(`tracing:${nameOrChannels}:asyncEnd`),
      });
    } else if (typeof nameOrChannels === "object") {
      this.#callWindow = new BoundedChannel({
        start: nameOrChannels.start,
        end: nameOrChannels.end,
      });
      this.#continuationWindow = new BoundedChannel({
        start: nameOrChannels.asyncStart,
        end: nameOrChannels.asyncEnd,
      });
    }

    ObjectDefineProperty(this, "error", {
      __proto__: null,
      value: channelFromMap(nameOrChannels, "error", "TracingChannel"),
    });
  }

  get start() {
    return this.#callWindow.start;
  }

  get end() {
    return this.#callWindow.end;
  }

  get asyncStart() {
    return this.#continuationWindow.start;
  }

  get asyncEnd() {
    return this.#continuationWindow.end;
  }

  get hasSubscribers() {
    return this.#callWindow.hasSubscribers ||
      this.#continuationWindow.hasSubscribers ||
      this.error?.hasSubscribers;
  }

  subscribe(handlers) {
    if (handlers.start || handlers.end) {
      this.#callWindow.subscribe({
        start: handlers.start,
        end: handlers.end,
      });
    }

    if (handlers.asyncStart || handlers.asyncEnd) {
      this.#continuationWindow.subscribe({
        start: handlers.asyncStart,
        end: handlers.asyncEnd,
      });
    }

    if (handlers.error) {
      this.error.subscribe(handlers.error);
    }
  }

  unsubscribe(handlers) {
    let done = true;

    if (handlers.start || handlers.end) {
      if (!this.#callWindow.unsubscribe({
        start: handlers.start,
        end: handlers.end,
      })) {
        done = false;
      }
    }

    if (handlers.asyncStart || handlers.asyncEnd) {
      if (!this.#continuationWindow.unsubscribe({
        start: handlers.asyncStart,
        end: handlers.asyncEnd,
      })) {
        done = false;
      }
    }

    if (handlers.error && !this.error.unsubscribe(handlers.error)) {
      done = false;
    }

    return done;
  }

  traceSync(fn, context = { __proto__: null }, thisArg, ...args) {
    if (!this.hasSubscribers) {
      return ReflectApply(fn, thisArg, args);
    }

    const { error } = this;

    const scope = this.#callWindow.withScope(context);
    try {
      const result = ReflectApply(fn, thisArg, args);
      context.result = result;
      return result;
    } catch (err) {
      context.error = err;
      error.publish(context);
      throw err;
    } finally {
      scope[SymbolDispose]();
    }
  }

  tracePromise(fn, context = { __proto__: null }, thisArg, ...args) {
    if (!this.hasSubscribers) {
      const result = ReflectApply(fn, thisArg, args);
      if (typeof result?.then !== "function") {
        emitNonThenableWarning(fn);
      }
      return result;
    }

    const { error } = this;
    const continuationWindow = this.#continuationWindow;

    function reject(err) {
      context.error = err;
      error.publish(context);
      const scope = continuationWindow.withScope(context);
      try {
        return PromiseReject(err);
      } finally {
        scope[SymbolDispose]();
      }
    }

    function resolve(result) {
      context.result = result;
      const scope = continuationWindow.withScope(context);
      try {
        return result;
      } finally {
        scope[SymbolDispose]();
      }
    }

    const scope = this.#callWindow.withScope(context);
    try {
      const result = ReflectApply(fn, thisArg, args);
      if (typeof result?.then !== "function") {
        emitNonThenableWarning(fn);
        context.result = result;
        return result;
      }
      if (core.isPromise(result)) {
        return PromisePrototypeThen(result, resolve, reject);
      }
      return result.then(resolve, reject);
    } catch (err) {
      context.error = err;
      error.publish(context);
      throw err;
    } finally {
      scope[SymbolDispose]();
    }
  }

  traceCallback(
    fn,
    position = -1,
    context = { __proto__: null },
    thisArg,
    ...args
  ) {
    if (!this.hasSubscribers) {
      return ReflectApply(fn, thisArg, args);
    }

    const { error } = this;
    const continuationWindow = this.#continuationWindow;

    function wrappedCallback(err, res) {
      if (err) {
        context.error = err;
        error.publish(context);
      } else {
        context.result = res;
      }

      const scope = continuationWindow.withScope(context);
      try {
        return ReflectApply(callback, this, arguments);
      } finally {
        scope[SymbolDispose]();
      }
    }

    const callback = ArrayPrototypeAt(args, position);
    validateFunction(callback, "callback");
    ArrayPrototypeSplice(args, position, 1, wrappedCallback);

    const scope = this.#callWindow.withScope(context);
    try {
      return ReflectApply(fn, thisArg, args);
    } catch (err) {
      context.error = err;
      error.publish(context);
      throw err;
    } finally {
      scope[SymbolDispose]();
    }
  }
}

function tracingChannel(nameOrChannels) {
  return new TracingChannel(nameOrChannels);
}

return {
  default: {
    channel,
    hasSubscribers,
    subscribe,
    tracingChannel,
    unsubscribe,
    boundedChannel,
    Channel,
    BoundedChannel,
  },
  channel,
  hasSubscribers,
  subscribe,
  tracingChannel,
  unsubscribe,
  boundedChannel,
  Channel,
  BoundedChannel,
};
})();
