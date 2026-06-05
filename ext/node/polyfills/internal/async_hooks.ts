// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent and Node contributors. All rights reserved. MIT license.

(function () {
const { core, primordials } = __bootstrap;
// deno-lint-ignore camelcase
const async_wrap = core.loadExtScript(
  "ext:deno_node/internal_binding/async_wrap.ts",
);
const { ERR_ASYNC_CALLBACK, ERR_INVALID_ARG_TYPE, ERR_INVALID_ARG_VALUE } =
  core.loadExtScript("ext:deno_node/internal/errors.ts");
const { asyncIdSymbol, ownerSymbol } = core.loadExtScript(
  "ext:deno_node/internal_binding/symbols.ts",
);
const {
  ArrayPrototypeIncludes,
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypePop,
  ArrayPrototypeSlice,
  ArrayPrototypeSplice,
  FunctionPrototypeApply,
  ObjectKeys,
  SafeFinalizationRegistry,
  SafeSet,
  SafeWeakMap,
  SafeWeakSet,
  Symbol,
} = primordials;
const {
  isPromiseHooksSuppressed,
  queueImmediate,
  queueMicrotask: coreQueueMicrotask,
  kRefed: kRefedImmediateSymbol,
} = core;
const {
  AsyncVariable,
  getAsyncContext,
  kNoAsyncContextRestore,
  setAsyncContext,
} = core;

interface ActiveHooks {
  array: AsyncHook[];
  // deno-lint-ignore camelcase
  call_depth: number;
  // deno-lint-ignore camelcase
  tmp_array: AsyncHook[] | null;
  // deno-lint-ignore camelcase
  tmp_fields: number[] | null;
}

// Properties in active_hooks are used to keep track of the set of hooks being
// executed in case another hook is enabled/disabled. The new set of hooks is
// then restored once the active set of hooks is finished executing.
// deno-lint-ignore camelcase
const active_hooks: ActiveHooks = {
  // Array of all AsyncHooks that will be iterated whenever an async event
  // fires. Using var instead of (preferably const) in order to assign
  // active_hooks.tmp_array if a hook is enabled/disabled during hook
  // execution.
  array: [],
  // Use a counter to track nested calls of async hook callbacks and make sure
  // the active_hooks.array isn't altered mid execution.
  // deno-lint-ignore camelcase
  call_depth: 0,
  // Use to temporarily store and updated active_hooks.array if the user
  // enables or disables a hook while hooks are being processed. If a hook is
  // enabled() or disabled() during hook execution then the current set of
  // active hooks is duplicated and set equal to active_hooks.tmp_array. Any
  // subsequent changes are on the duplicated array. When all hooks have
  // completed executing active_hooks.tmp_array is assigned to
  // active_hooks.array.
  // deno-lint-ignore camelcase
  tmp_array: null,
  // Keep track of the field counts held in active_hooks.tmp_array. Because the
  // async_hook_fields can't be reassigned, store each uint32 in an array that
  // is written back to async_hook_fields when active_hooks.array is restored.
  // deno-lint-ignore camelcase
  tmp_fields: null,
};

const registerDestroyHook = async_wrap.registerDestroyHook;
const {
  async_hook_fields,
  // deno-lint-ignore camelcase
  asyncIdFields: async_id_fields,
  newAsyncId,
  constants,
} = async_wrap;

// In Node.js the top-level execution async ID is 1 (kRootAsyncId). The trigger
// async ID at top level is 0 (no parent). Several Node compat tests assert
// this; e.g. test-async-hooks-promise-triggerid.js expects the first promise
// init to receive triggerId === 1.
const kRootAsyncId = 1;

// Parallel stacks for executionAsyncId() and triggerAsyncId(). They are pushed
// together by emitBefore() and popped together by emitAfter(), keeping them
// in sync for the lifetime of a single async callback.
const executionAsyncIdStack: number[] = [kRootAsyncId];
const triggerAsyncIdStack: number[] = [0];

function executionAsyncId(): number {
  return executionAsyncIdStack[executionAsyncIdStack.length - 1] || 0;
}

function triggerAsyncId(): number {
  return triggerAsyncIdStack[triggerAsyncIdStack.length - 1] || 0;
}

// Per-async-context "current resource" tracked via the AsyncVariable
// machinery (V8 ContinuationPreservedEmbedderData). This propagates across
// promises and await transitions automatically. The top-level resource is a
// shared singleton used before any specific resource has been entered.
// deno-lint-ignore no-explicit-any
const topLevelResource: any = { __proto__: null };
// deno-lint-ignore no-explicit-any
const executionResourceVariable: any = new AsyncVariable();

// Synchronous "current resource" stack, the mirror of Node's
// execution_async_resources (lib/internal/async_hooks.js). pushAsyncContext()
// sets execution_async_resources[offset] = resource BEFORE the user before()
// hook runs, and popAsyncContext() clears it AFTER the user after() hook runs,
// so executionAsyncResource() observed inside a before/after hook (and inside
// AsyncResource.runInAsyncScope's callback) returns the resource that owns that
// callback. emitBefore()/emitAfter() below push/pop this stack in lockstep with
// executionAsyncIdStack. A sentinel `undefined` entry means "no synchronous
// resource is active for this frame"; executionAsyncResource() then falls back
// to the AsyncVariable (continuation-preserved) value so AsyncLocalStorage and
// post-await promise continuations keep their existing propagation behavior.
// deno-lint-ignore no-explicit-any
const executionAsyncResourceStack: any[] = [undefined];

// deno-lint-ignore no-explicit-any
function executionAsyncResource(): any {
  // Prefer the synchronously-active resource for the current frame (set by
  // emitBefore). When none is active, defer to the AsyncVariable so await /
  // AsyncLocalStorage continuation propagation is unchanged.
  const top =
    executionAsyncResourceStack[executionAsyncResourceStack.length - 1];
  if (top !== undefined) {
    return top;
  }
  const r = executionResourceVariable.get();
  return r === undefined ? topLevelResource : r;
}

// Enter a new "current resource" scope. The returned value is the previous
// async context snapshot that must be restored by exitAsyncResource.
// deno-lint-ignore no-explicit-any
function enterAsyncResource(resource: any): any {
  return executionResourceVariable.enter(resource);
}

// deno-lint-ignore no-explicit-any
function exitAsyncResource(previousContext: any): void {
  setAsyncContext(previousContext);
}

// deno-lint-ignore no-explicit-any
function enterAsyncResourceIfActive(resource: any): any {
  if (active_hooks.array.length > 0) {
    return executionResourceVariable.enter(resource);
  }
  return executionResourceVariable.enterIfActive(resource);
}

// deno-lint-ignore no-explicit-any
function exitAsyncResourceIfActive(previousContext: any): void {
  if (previousContext !== kNoAsyncContextRestore) {
    setAsyncContext(previousContext);
    return;
  }

  const currentContext = getAsyncContext();
  if (
    currentContext !== null &&
    currentContext !== undefined &&
    ObjectKeys(currentContext).length > 0
  ) {
    setAsyncContext(undefined);
  }
}

// Mirror of Node's internal/async_hooks.js fatalError / inspectExceptionValue
// (lib/internal/async_hooks.js:156-176): when a user hook callback throws a
// value that is not already a stack-bearing Error, Node reports it as
// `Error: <inspect(value)>`. deno_core's uncaught-error rendering already emits
// `Error: <message>` for a thrown Error, so we normalize non-Error throws into
// an Error whose message is inspect(value) and let the existing propagation path
// produce the Node-matching stderr first line. Real Errors (anything already
// carrying a string `.stack`) propagate unchanged.
// deno-lint-ignore no-explicit-any
let lazyInspect: ((v: any) => string) | undefined;
function normalizeHookThrow(e: unknown): unknown {
  // deno-lint-ignore no-explicit-any
  if (typeof (e as any)?.stack === "string") {
    return e;
  }
  if (lazyInspect === undefined) {
    lazyInspect = core.loadExtScript(
      "ext:deno_node/internal/util/inspect.mjs",
    ).inspect;
  }
  return new Error(lazyInspect!(e));
}

// True when `e` is V8's stack-overflow RangeError ("Maximum call stack size
// exceeded"). The promise hooks below add JS frames on top of user recursion;
// when user code recurses to the stack limit the overflow can land INSIDE a
// hook body. A throw raised inside our context promise-hook callback is caught
// by V8's Torque RunContextPromiseHook try/catch and routed through
// runtime::ReportMessageFromMicrotask, which reports-then-clears it; the empty
// `new Promise` executor then overflows too and PromiseConstructor's own
// try/catch turns THAT into an unhandled rejection -- which bypasses the user's
// synchronous try/catch around `new Promise` (test-async-hooks-stack-overflow-
// try-catch). Swallowing the SECONDARY overflow inside the hook lets the
// overflow instead surface at the user frame, where the user try/catch (or
// uncaughtException) handles it, matching Node. Matched by name+message so the
// guard fires ONLY on genuine stack exhaustion, never on a normal throw from a
// user init/before/after/resolve callback.
// deno-lint-ignore no-explicit-any
function isStackOverflow(e: any): boolean {
  return e instanceof RangeError &&
    e.message === "Maximum call stack size exceeded";
}

// Emit functions that work with the internal hook system
// deno-lint-ignore no-explicit-any
function emitBefore(
  asyncId: number,
  triggerAsyncId?: number,
  // deno-lint-ignore no-explicit-any
  resource?: any,
): void {
  // Skip the entire before/after/destroy lifecycle for resources whose init was
  // suppressed (harness drain TickObjects etc.). We must not push a suppressed id
  // onto executionAsyncIdStack: the paired emitAfter is also skipped, so a push
  // here would never be popped and would corrupt executionAsyncId().
  if (suppressedAsyncIds.has(asyncId)) {
    return;
  }
  ArrayPrototypePush(executionAsyncIdStack, asyncId);
  ArrayPrototypePush(
    triggerAsyncIdStack,
    triggerAsyncId === undefined ? 0 : triggerAsyncId,
  );
  // Mirror Node's pushAsyncContext(): make `resource` the synchronously-active
  // executionAsyncResource() for the duration of this before/after window,
  // BEFORE any user before() hook runs. Pushed in lockstep with the id stack so
  // emitAfter's paired pop stays balanced. `undefined` is a valid sentinel
  // (callers without a resource keep the AsyncVariable fallback).
  ArrayPrototypePush(executionAsyncResourceStack, resource);

  // Call hooks if they exist. Mirror Node's emitHook(): bump call_depth so an
  // enable()/disable() invoked from inside a before() callback is buffered into
  // active_hooks.tmp_array and only takes effect on the NEXT emit cycle, instead
  // of mutating the live array mid-dispatch (test-async-hooks-enable-disable).
  const hooks = active_hooks.array;
  active_hooks.call_depth += 1;
  try {
    for (let i = 0; i < hooks.length; i++) {
      const hook = hooks[i];
      if (hook[before_symbol]) {
        hook[before_symbol](asyncId);
      }
    }
  } catch (e) {
    // Clean up stack corruption on hook errors (Node.js pattern)
    if (executionAsyncIdStack.length > 1) {
      ArrayPrototypePop(executionAsyncIdStack);
      ArrayPrototypePop(triggerAsyncIdStack);
      ArrayPrototypePop(executionAsyncResourceStack);
    }
    throw normalizeHookThrow(e);
  } finally {
    active_hooks.call_depth -= 1;
  }
  // Restore the active hooks array if enable()/disable() ran during dispatch and
  // no outer emit frame is still iterating (call_depth back to 0).
  if (active_hooks.call_depth === 0 && active_hooks.tmp_array !== null) {
    restoreActiveHooks();
  }
}

function emitAfter(asyncId: number): void {
  // Paired with the emitBefore suppression above: a suppressed id was never
  // pushed onto the stack, so there is nothing to pop and no user hook should
  // observe its 'after'.
  if (suppressedAsyncIds.has(asyncId)) {
    return;
  }
  // Call hooks if they exist. Mirror Node's emitHook(): bump call_depth so an
  // enable()/disable() invoked from inside an after() callback is buffered into
  // active_hooks.tmp_array and only takes effect on the NEXT emit cycle
  // (test-async-hooks-enable-disable: hook3 disables itself inside its own
  // after()).
  const hooks = active_hooks.array;
  active_hooks.call_depth += 1;
  try {
    for (let i = 0; i < hooks.length; i++) {
      const hook = hooks[i];
      if (hook[after_symbol]) {
        hook[after_symbol](asyncId);
      }
    }
  } catch (e) {
    throw normalizeHookThrow(e);
  } finally {
    active_hooks.call_depth -= 1;
    // Defensive pop (Node's promiseAfterHook / popAsyncContext): only pop when
    // the stack top matches the asyncId we are closing. A mismatched top means
    // the paired emitBefore was skipped (e.g. fired while hooks were disabled),
    // so popping would corrupt executionAsyncId() for an unrelated frame. The
    // resource stack pops in lockstep so executionAsyncResource() stays valid
    // for the enclosing frame; the user after() hook above already ran while
    // this frame's resource was still on top.
    if (
      executionAsyncIdStack.length > 1 &&
      executionAsyncIdStack[executionAsyncIdStack.length - 1] === asyncId
    ) {
      ArrayPrototypePop(executionAsyncIdStack);
      ArrayPrototypePop(triggerAsyncIdStack);
      ArrayPrototypePop(executionAsyncResourceStack);
    }
  }
  // Restore the active hooks array if enable()/disable() ran during dispatch and
  // no outer emit frame is still iterating (call_depth back to 0).
  if (active_hooks.call_depth === 0 && active_hooks.tmp_array !== null) {
    restoreActiveHooks();
  }
}

function emitDestroy(asyncId: number): void {
  // Final lifecycle event for a suppressed id: drop it from the tracking set
  // (so it cannot grow unbounded) and never surface 'destroy' to user hooks.
  // Done eagerly (not deferred) because the suppressed-id bookkeeping must stay
  // synchronous with the core drain loop that owns these ids.
  if (suppressedAsyncIds.has(asyncId)) {
    suppressedAsyncIds.delete(asyncId);
    return;
  }
  // Fast path: with no destroy() hooks enabled there is nothing to defer.
  // Mirrors Node's emitDestroyScript guard (async_hook_fields[kDestroy] === 0)
  // and rejects invalid ids (asyncId > 0), matching src/async_wrap.cc.
  if (async_hook_fields[kDestroy] === 0 || !(asyncId > 0)) {
    return;
  }
  // Deferred destroy: append the id and (if the queue was empty) schedule the
  // unref'd drain immediate. User destroy() hooks fire later, in the check
  // phase, after nextTick + microtasks -- matching Node (AsyncWrap::EmitDestroy
  // -> destroy_async_id_list + unref'd DestroyAsyncIdsCallback) so a same-turn
  // nextTick/microtask/promise still observes the resource as alive
  // (test-destroy-not-blocked) and the destroy lands after the owning
  // immediate's after() (test-enable-disable).
  //
  // The 16384 microtask hatch (Node async_wrap.cc AsyncWrap::EmitDestroy): when
  // the deferred list reaches Node's exact threshold, schedule a MICROTASK drain
  // in addition to the check-phase immediate. Without it, a long await chain that
  // floods the list with GC'd-promise destroys (test-destroy-not-blocked's two
  // 5000-iteration loops, each followed by global.gc()) never yields to the check
  // phase, so the resource under test would stay alive past L90. The threshold is
  // checked BEFORE the push (Node tests size() == 16384 pre-push_back), and stays
  // at the Node-faithful 16384 so the earlier L84 assert -- which must still see
  // the resource ALIVE because fewer than 16384 ids have accumulated by then --
  // does not regress. coreQueueMicrotask routes to V8 EnqueueMicrotask, mirroring
  // Node's RequestInterrupt(EnqueueMicrotask) without the GC-context restriction.
  if (destroyAsyncIdList.length === 16384) {
    coreQueueMicrotask(drainDestroyAsyncIds);
  }
  ArrayPrototypePush(destroyAsyncIdList, asyncId);
  scheduleDestroyDrain();
}

function emitPromiseResolve(asyncId: number): void {
  // Mirror emitBefore/emitAfter/emitDestroy: a resource whose init was withheld
  // by the promise-hook suppression gate (its id is in suppressedAsyncIds) must
  // not deliver ANY lifecycle callback to user hooks, promiseResolve included.
  // Without this guard a suppressed promise (e.g. one created by the Nimbus
  // harness drain or during bootstrap) still fires promiseResolve, which the
  // fixture's init-hooks checker reports as "promiseResolve invoked but not its
  // init hook" and which inflates mustCall counts. emitDestroy is what finally
  // deletes the id from suppressedAsyncIds, so this read-only check is safe to
  // run before destroy.
  if (suppressedAsyncIds.has(asyncId)) {
    return;
  }
  const hooks = active_hooks.array;
  try {
    for (let i = 0; i < hooks.length; i++) {
      const hook = hooks[i];
      if (hook[promise_resolve_symbol]) {
        hook[promise_resolve_symbol](asyncId);
      }
    }
  } catch (e) {
    // emitPromiseResolve's only caller is the V8 context-level promise resolve
    // hook (Context::SetPromiseHooks). V8's Torque promise-hook macros catch any
    // throw from the hook and route it through runtime::ReportMessageFromMicrotask,
    // which REPORTS then CLEARS the exception -- it never reaches the JS frame and,
    // because deno_core installs no V8 message listener, becomes a silent soft
    // report. A bare `throw` here is therefore dead. Route the throw through
    // core.__reportException (-> reportExceptionCallback -> the global "error"
    // event), the SAME path a throwing timer callback uses, so a throwing
    // promiseResolve hook reaches the emulated child's uncaughtException handler
    // and terminates with code 1. core.reportUnhandledException only calls
    // op_dispatch_exception(e, false), which sets terminate_execution() -- the
    // spawn-op loop treats that as a benign exit 0, so the child's status stayed 0
    // and test-async-hooks-fatal-error's `promiseResolve` case asserted 0 !== 1.
    core.__reportException(normalizeHookThrow(e));
  }
}
const {
  kInit,
  kBefore,
  kAfter,
  kDestroy,
  kPromiseResolve,
  kTotals,
  kCheck,
  kDefaultTriggerAsyncId,
  kStackLength,
} = constants;

// deno-lint-ignore camelcase
const resource_symbol = Symbol("resource");
// Alias to the same symbol used by `internal_binding/symbols.ts` so that
// `socket[asyncIdSymbol]` (set in net.ts/dgram.ts) and
// `socket[require('internal/async_hooks').symbols.async_id_symbol]`
// (read by Node test fixtures) refer to the same slot on objects.
// deno-lint-ignore camelcase
const async_id_symbol = asyncIdSymbol;
// deno-lint-ignore camelcase
const trigger_async_id_symbol = Symbol("trigger_async_id");
// deno-lint-ignore camelcase
const init_symbol = Symbol("init");
// deno-lint-ignore camelcase
const before_symbol = Symbol("before");
// deno-lint-ignore camelcase
const after_symbol = Symbol("after");
// deno-lint-ignore camelcase
const destroy_symbol = Symbol("destroy");
// deno-lint-ignore camelcase
const promise_resolve_symbol = Symbol("promiseResolve");

const symbols = {
  // deno-lint-ignore camelcase
  async_id_symbol,
  // deno-lint-ignore camelcase
  trigger_async_id_symbol,
  // deno-lint-ignore camelcase
  init_symbol,
  // deno-lint-ignore camelcase
  before_symbol,
  // deno-lint-ignore camelcase
  after_symbol,
  // deno-lint-ignore camelcase
  destroy_symbol,
  // deno-lint-ignore camelcase
  promise_resolve_symbol,
};

// deno-lint-ignore no-explicit-any
function lookupPublicResource(resource: any) {
  if (typeof resource !== "object" || resource === null) return resource;
  // TODO(addaleax): Merge this with owner_symbol and use it across all
  // AsyncWrap instances.
  const publicResource = resource[resource_symbol];
  if (publicResource !== undefined) {
    return publicResource;
  }
  return resource;
}

// Used by C++ to call all init() callbacks. Because some state can be setup
// from C++ there's no need to perform all the same operations as in
// emitInitScript.
function emitInitNative(
  asyncId: number,
  // deno-lint-ignore no-explicit-any
  type: any,
  triggerAsyncId: number,
  // deno-lint-ignore no-explicit-any
  resource: any,
) {
  // Harness drain / deno_core infrastructure suppression. When
  // core.isPromiseHooksSuppressed() is raised (e.g. the Nimbus test harness is
  // flushing its post-execution nextTick/promise drain) we must not fan out
  // init() to user hooks for ANY resource type. Promises self-guard in
  // promiseInitHook, but TickObject and other native inits route here directly
  // (see _next_tick.ts), so centralizing the gate keeps drain-created resources
  // invisible to fixture async_hooks callbacks.
  if (isPromiseHooksSuppressed()) {
    // Remember this id so the before/after/destroy the core drain loop will
    // fire for it later (outside the suppression window) are skipped too.
    suppressedAsyncIds.add(asyncId);
    return;
  }
  active_hooks.call_depth += 1;
  resource = lookupPublicResource(resource);
  // Use a single try/catch for all hooks to avoid setting up one per iteration.
  try {
    for (let i = 0; i < active_hooks.array.length; i++) {
      if (typeof active_hooks.array[i][init_symbol] === "function") {
        active_hooks.array[i][init_symbol](
          asyncId,
          type,
          triggerAsyncId,
          resource,
        );
      }
    }
  } catch (e) {
    throw normalizeHookThrow(e);
  } finally {
    active_hooks.call_depth -= 1;
  }

  // Hooks can only be restored if there have been no recursive hook calls.
  // Also the active hooks do not need to be restored if enable()/disable()
  // weren't called during hook execution, in which case active_hooks.tmp_array
  // will be null.
  if (active_hooks.call_depth === 0 && active_hooks.tmp_array !== null) {
    restoreActiveHooks();
  }
}

function getHookArrays(): [AsyncHook[], number[] | Uint32Array] {
  if (active_hooks.call_depth === 0) {
    return [active_hooks.array, async_hook_fields];
  }
  // If this hook is being enabled while in the middle of processing the array
  // of currently active hooks then duplicate the current set of active hooks
  // and store this there. This shouldn't fire until the next time hooks are
  // processed.
  if (active_hooks.tmp_array === null) {
    storeActiveHooks();
  }
  return [active_hooks.tmp_array!, active_hooks.tmp_fields!];
}

function storeActiveHooks() {
  active_hooks.tmp_array = ArrayPrototypeSlice(active_hooks.array);
  // Don't want to make the assumption that kInit to kDestroy are indexes 0 to
  // 4. So do this the long way.
  active_hooks.tmp_fields = [];
  copyHooks(active_hooks.tmp_fields, async_hook_fields);
}

function copyHooks(
  destination: number[] | Uint32Array,
  source: number[] | Uint32Array,
) {
  destination[kInit] = source[kInit];
  destination[kBefore] = source[kBefore];
  destination[kAfter] = source[kAfter];
  destination[kDestroy] = source[kDestroy];
  destination[kPromiseResolve] = source[kPromiseResolve];
}

// Then restore the correct hooks array in case any hooks were added/removed
// during hook callback execution.
function restoreActiveHooks() {
  active_hooks.array = active_hooks.tmp_array!;
  copyHooks(async_hook_fields, active_hooks.tmp_fields!);

  active_hooks.tmp_array = null;
  active_hooks.tmp_fields = null;
}

// ---------------------------------------------------------------------------
// Promise hook integration
//
// V8 exposes four promise hooks (init, before, after, resolve). Once any
// AsyncHook with init/before/after/promiseResolve is enabled we install our
// own V8 promise hooks; from there we assign an async id to each promise on
// first observation, track the parent->child relationship for triggerAsyncId,
// and fan out to the user's createHook() callbacks.
// ---------------------------------------------------------------------------

// Map promise -> { asyncId, triggerAsyncId }
const promiseInfo = new SafeWeakMap();

// Promises created while `core.isPromiseHooksSuppressed()` was true. We track
// them so that subsequent before/after/resolve V8 hook callbacks know to
// skip them as well.
const suppressedPromises = new SafeWeakSet();

// Async ids of NON-promise native resources (e.g. TickObjects from the Nimbus
// harness post-exec drain) whose init() was suppressed because
// `core.isPromiseHooksSuppressed()` was true at creation time. The core drain
// loop fires before/after/destroy for these inline as the tick runs - which is
// AFTER the suppression window closes (see _next_tick.ts setAsyncHooksEmit) - so
// we must remember the id and skip its entire remaining lifecycle. Without this,
// a fixture hook would observe a before/after/destroy for a resource it never
// saw an init for. Cleared in emitDestroy so the set cannot grow unbounded.
const suppressedAsyncIds = new SafeSet();

// ---------------------------------------------------------------------------
// Deferred destroy queue (mirror of Node's destroy_async_id_list +
// DestroyAsyncIdsCallback, src/async_wrap.cc). emitDestroy() does NOT run user
// destroy() hooks synchronously; it appends the asyncId here and, if the queue
// was empty, schedules an UNREF'd immediate that drains the queue in the check
// phase -- AFTER nextTick and microtasks. This matches Node, where
// AsyncResource.emitDestroy() only enqueues (lib/internal/async_hooks.js
// emitDestroyScript -> async_wrap.queueDestroyAsyncId), so a nextTick/
// microtask/promise scheduled in the same turn still observes the resource as
// "alive" (test-destroy-not-blocked), and the immediate ordering keeps destroy
// after the owning immediate's own after() (test-enable-disable).
const destroyAsyncIdList: number[] = [];
// True once a drain immediate has been queued and not yet run. Mirrors Node's
// "schedule only when the list was empty" guard so we never queue more than one
// drain immediate at a time.
let destroyDrainQueued = false;

// Drain the deferred destroy queue, firing user destroy() hooks for each id in
// FIFO order. Mirrors emitDestroy's original synchronous loop discipline
// (call_depth keeper for buffered enable()/disable(), normalizeHookThrow on a
// throwing user hook, restoreActiveHooks() once call_depth returns to 0) and
// Node's DestroyAsyncIdsCallback "loop until the list is empty" so ids enqueued
// by a destroy() hook are handled in the same drain.
function drainDestroyAsyncIds(): void {
  destroyDrainQueued = false;
  while (destroyAsyncIdList.length > 0) {
    const batch = ArrayPrototypeSplice(destroyAsyncIdList, 0);
    for (let b = 0; b < batch.length; b++) {
      const asyncId = batch[b];
      // A suppressed id may have been enqueued before its init was suppressed;
      // drop it without surfacing destroy(), and keep the tracking set bounded.
      if (suppressedAsyncIds.has(asyncId)) {
        suppressedAsyncIds.delete(asyncId);
        continue;
      }
      const hooks = active_hooks.array;
      active_hooks.call_depth += 1;
      try {
        for (let i = 0; i < hooks.length; i++) {
          const hook = hooks[i];
          if (hook[destroy_symbol]) {
            hook[destroy_symbol](asyncId);
          }
        }
      } catch (e) {
        // Re-arm a drain for any ids not yet processed in this batch so a
        // throwing destroy() hook does not silently drop the remainder, then
        // surface the throw (Node routes it through the immediate's TryCatch).
        for (let j = b + 1; j < batch.length; j++) {
          ArrayPrototypePush(destroyAsyncIdList, batch[j]);
        }
        scheduleDestroyDrain();
        active_hooks.call_depth -= 1;
        if (active_hooks.call_depth === 0 && active_hooks.tmp_array !== null) {
          restoreActiveHooks();
        }
        throw normalizeHookThrow(e);
      } finally {
        active_hooks.call_depth -= 1;
      }
      if (active_hooks.call_depth === 0 && active_hooks.tmp_array !== null) {
        restoreActiveHooks();
      }
    }
  }
}

// Schedule the destroy drain as an UNREF'd immediate (kRefed: false). Its job is
// to WAKE a future runImmediates() pass; the authoritative drain happens at the
// TOP of runImmediates() (core calls drainDestroyAsyncIds before processing each
// snapshot -- see libs/core/01_core.js). That placement is what mirrors Node's
// DestroyAsyncIdsCallback running as a native immediate BETWEEN JS-immediate
// snapshots: a setImmediate queued by a callback in pass N runs in pass N+1, but
// the destroy enqueued in that same callback drains at the TOP of pass N+1, i.e.
// BEFORE that next immediate's before() (test-enable-disable: destroy.uid-5
// lands before before.uid-6 even though the uid-6 immediate was queued first).
// A FIFO-ordered drain immediate could not express that ordering. The immediate
// here is unref'd so it never keeps the loop alive on its own (Node's
// SetImmediate(..., kUnrefed)); it is a plain object (NOT a timers.mjs Immediate)
// so no emitInit fires for it; and its asyncId is pre-registered in
// suppressedAsyncIds so the emitBefore/emitAfter/emitDestroy that runImmediates
// fires for the drain immediate itself are short-circuited. Its _onImmediate is
// drainDestroyAsyncIds too, as an idempotent safety net for the trailing case.
function scheduleDestroyDrain(): void {
  if (destroyDrainQueued) {
    return;
  }
  destroyDrainQueued = true;
  const drainAsyncId = newAsyncId();
  suppressedAsyncIds.add(drainAsyncId);
  queueImmediate({
    _idleNext: null,
    _idlePrev: null,
    _onImmediate: drainDestroyAsyncIds,
    _argv: undefined,
    _destroyed: false,
    asyncId: drainAsyncId,
    triggerAsyncId: 0,
    [kRefedImmediateSymbol]: false,
  });
}

// FinalizationRegistry to fire destroy() when a promise is garbage collected.
const promiseDestroyRegistry = new SafeFinalizationRegistry(
  (asyncId: number) => emitDestroy(asyncId),
);

let promiseHooksInstalled = false;

// Mirrors Node's `wantPromiseHook` (lib/internal/async_hooks.js). deno_core's
// core.setPromiseHooks is append-only: once installed the V8 promise hooks keep
// firing even after every AsyncHook has been disable()d, whereas Node stops
// emitting the moment all hooks are disabled. We cannot uninstall, so we gate
// the before/after/resolve dispatch on this flag, recomputed SYNCHRONOUSLY in
// enableHooks()/disableHooks() (never on a microtask).
let wantPromiseHook = false;
function updateWantPromiseHook() {
  wantPromiseHook = enabledHooksExist();
}

function ensurePromiseHooks() {
  if (promiseHooksInstalled) return;
  promiseHooksInstalled = true;
  core.setPromiseHooks(
    promiseInitHook,
    promiseBeforeHook,
    promiseAfterHook,
    promiseResolveHook,
  );
  // Reflect the now-installed hooks for
  // `internalBinding('async_wrap').getPromiseHooks()` introspection. Until this
  // runs the binding reports all four as `undefined`, matching Node when no
  // promise hooks are tracked (test-track-promises-false-check.js).
  async_wrap.setPromiseHooksForReporting([
    promiseInitHook,
    promiseBeforeHook,
    promiseAfterHook,
    promiseResolveHook,
  ]);
}

// Assign a fresh async id pair to a promise, recording the parent->child
// relationship. Returns the assigned id.
function trackPromise(
  // deno-lint-ignore no-explicit-any
  promise: any,
  // deno-lint-ignore no-explicit-any
  parent: any,
): { asyncId: number; triggerAsyncId: number } {
  const asyncId = newAsyncId();
  let trigger;
  if (parent != null && promiseInfo.has(parent)) {
    trigger = promiseInfo.get(parent).asyncId;
  } else {
    trigger = executionAsyncId();
  }
  const info = { asyncId, triggerAsyncId: trigger };
  promiseInfo.set(promise, info);
  // NOTE: GC-destroy registration is intentionally NOT done here. A promise must
  // only fire destroy() if its init() was actually delivered to user hooks --
  // otherwise the async-hooks checker (init-hooks.js) throws "destroy hook
  // invoked but not its init hook". Node's V8 promise hook is epoch-scoped, so a
  // promise created before enable() (or while init count is 0) gets neither init
  // nor destroy. We mirror that by registering in promiseInfoRegistry only from
  // the `kInit > 0` branch of promiseInitHook, where init is genuinely emitted.
  return info;
}

// deno-lint-ignore no-explicit-any
function promiseInitHook(promise: any, parent: any): void {
  if (isPromiseHooksSuppressed()) {
    // This promise was created by deno_core infrastructure (async-op
    // wrapper, etc.); user code never observes it directly so we skip
    // tracking and firing any of the four async_hooks callbacks for it.
    suppressedPromises.add(promise);
    return;
  }
  try {
    // Always assign an async id pair (so before/after/resolve can resolve it)
    // but only fire user init() callbacks when an init hook is installed. The
    // async id pair alone -- recorded in promiseInfo by trackPromise -- is what
    // before/after/resolve key off of, mirroring Node's internal init hook
    // which always assigns an id even when no user init() callback is
    // registered.
    const info = trackPromise(promise, parent);
    // Record whether this promise was created while ANY AsyncHook was enabled.
    // Node's V8 promise hook is epoch-scoped: it fires before/after/resolve
    // only for promises created during an enabled epoch, and fires NONE of them
    // for a promise created before enable() (or while fully disabled). deno_core
    // installs setPromiseHooks once and cannot re-scope per epoch, so we record
    // the epoch state here and gate resolve on it (see promiseResolveHook).
    // wantPromiseHook === enabledHooksExist(): true even for a resolve-only
    // hook with no init() (test-async-hooks-fatal-error), so this is broader
    // than "init was emitted" -- it captures the true creation epoch.
    info.createdInEpoch = wantPromiseHook;

    if (async_hook_fields[kInit] > 0) {
      emitInitNative(info.asyncId, "PROMISE", info.triggerAsyncId, promise);
      // init() was delivered to user hooks for this promise, so a paired
      // destroy() is now expected when it is garbage collected. Register for
      // GC-destroy ONLY here -- never for promises whose init was withheld
      // (kInit === 0, or suppressed) -- so emitDestroy can never surface a
      // destroy the async-hooks checker has no matching init for. Symmetric
      // with the createdInEpoch resolve gate in promiseResolveHook.
      info.initEmitted = true;
      promiseDestroyRegistry.register(promise, info.asyncId, promise);
    }
  } catch (e) {
    // Under genuine stack exhaustion, let the overflow surface at the user
    // `new Promise` frame (caught by the user try/catch) instead of being
    // diverted into the executor-reject -> unhandled-rejection path. Any
    // non-overflow throw from a user init() callback re-throws unchanged
    // (Node: a throwing hook is fatal).
    if (isStackOverflow(e)) return;
    throw e;
  }
}

// deno-lint-ignore no-explicit-any
function promiseBeforeHook(promise: any): void {
  if (suppressedPromises.has(promise)) return;
  // Stop-on-disable: once every hook is disabled, do not push the async-id
  // stack or dispatch user before() callbacks. Checked AFTER the suppression
  // guard so suppressed/internal promises keep their existing behavior.
  if (!wantPromiseHook) return;
  try {
    let info = promiseInfo.get(promise);
    if (info === undefined) {
      // Promise was created before any async_hook was enabled. Backfill an
      // async id pair so before/after stay balanced. Do NOT fire init() for
      // this promise (matches Node's fast-path behavior). See
      // test-async-wrap-promise-after-enabled.js.
      info = trackPromise(promise, null);
    }
    // Pass the promise as the resource (Node: promiseBeforeHook ->
    // emitBeforeScript(asyncId, triggerId, promise)). This makes
    // executionAsyncResource() return the promise inside its before/after hook,
    // which test-async-exec-resource-match.js asserts for every promise
    // reaction.
    emitBefore(info.asyncId, info.triggerAsyncId, promise);
  } catch (e) {
    // See promiseInitHook: swallow a secondary stack-overflow raised inside the
    // hook so the overflow surfaces at the user frame instead of being diverted.
    if (isStackOverflow(e)) return;
    throw e;
  }
}

// deno-lint-ignore no-explicit-any
function promiseAfterHook(promise: any): void {
  if (suppressedPromises.has(promise)) return;
  if (!wantPromiseHook) return;
  try {
    const info = promiseInfo.get(promise);
    if (info !== undefined) {
      emitAfter(info.asyncId);
    }
  } catch (e) {
    // See promiseInitHook: swallow a secondary stack-overflow from the hook.
    if (isStackOverflow(e)) return;
    throw e;
  }
}

// deno-lint-ignore no-explicit-any
function promiseResolveHook(promise: any): void {
  if (suppressedPromises.has(promise)) return;
  if (!wantPromiseHook) return;
  try {
    const info = promiseInfo.get(promise);
    // Emit promiseResolve only for a promise CREATED during an enabled epoch
    // (info.createdInEpoch). deno_core's core.setPromiseHooks is installed once
    // and cannot be re-scoped per enable/disable epoch the way Node's V8
    // createHook is, so its resolve callback also fires for promises created
    // before any hook was enabled (or while fully disabled). Node's epoch-scoped
    // hook fires NO resolve for those; emitting one would surface a
    // promiseResolve with no matching init and the async-hooks checker rejects
    // it (init-hooks.js: "promiseResolve hook invoked but not its init hook").
    // A promise created in-epoch still resolves even when no init() callback was
    // registered -- e.g. createHook({ promiseResolve }) with no init -- because
    // its creation epoch (not init emission) is the discriminator, mirroring
    // Node's always-on internal init hook (test-async-hooks-fatal-error).
    if (info === undefined || info.createdInEpoch !== true) return;
    if (async_hook_fields[kPromiseResolve] > 0) {
      emitPromiseResolve(info.asyncId);
    }
  } catch (e) {
    // See promiseInitHook: swallow a secondary stack-overflow from the hook.
    if (isStackOverflow(e)) return;
    throw e;
  }
}

// Run `fn` (the process 'unhandledRejection' emit) inside the async scope of the
// rejected `promise`, so async_hooks.executionAsyncId()/triggerAsyncId() observed
// by an unhandledRejection handler resolve to the promise's ids instead of the
// empty top-level scope. Node emits the rejection from within the promise's own
// async resource (processPromiseRejections runs the reaction under its asyncId);
// our process-side emit happens outside any promise reaction, so we re-enter the
// promise's before/after window explicitly here. If the promise was never tracked
// (created before any hook, or suppressed) there is no id to enter, so we run the
// emit in the current scope. test-unhandled-rejection-context asserts the handler
// observes the rejected promise's executionAsyncId.
// deno-lint-ignore no-explicit-any
function runInPromiseRejectionScope(promise: any, fn: () => void): void {
  const info = promiseInfo.get(promise);
  if (info === undefined) {
    fn();
    return;
  }
  emitBefore(info.asyncId, info.triggerAsyncId, promise);
  try {
    fn();
  } finally {
    emitAfter(info.asyncId);
  }
}

function enableHooks() {
  async_hook_fields[kCheck] += 1;
  updateWantPromiseHook();
}

function disableHooks() {
  async_hook_fields[kCheck] -= 1;
  // Flip synchronously (Node sets wantPromiseHook in disableHooks); do NOT
  // defer to a microtask, or post-disable promise callbacks would still fire.
  updateWantPromiseHook();
}

// Return the triggerAsyncId meant for the constructor calling it. It's up to
// the user to safeguard this call and make sure it's zero'd out when the
// constructor is complete.
function getDefaultTriggerAsyncId() {
  const defaultTriggerAsyncId =
    async_id_fields[async_wrap.UidFields.kDefaultTriggerAsyncId];
  // If defaultTriggerAsyncId isn't set, use the executionAsyncId
  if (defaultTriggerAsyncId < 0) {
    return executionAsyncId();
  }
  return defaultTriggerAsyncId;
}

function defaultTriggerAsyncIdScope(
  triggerAsyncId: number | undefined,
  // deno-lint-ignore no-explicit-any
  block: (...arg: any[]) => void,
  ...args: unknown[]
) {
  if (triggerAsyncId === undefined) {
    return FunctionPrototypeApply(block, null, args);
  }
  // CHECK(NumberIsSafeInteger(triggerAsyncId))
  // CHECK(triggerAsyncId > 0)
  const oldDefaultTriggerAsyncId = async_id_fields[kDefaultTriggerAsyncId];
  async_id_fields[kDefaultTriggerAsyncId] = triggerAsyncId;

  try {
    return FunctionPrototypeApply(block, null, args);
  } finally {
    async_id_fields[kDefaultTriggerAsyncId] = oldDefaultTriggerAsyncId;
  }
}

function hasHooks(key: number) {
  return async_hook_fields[key] > 0;
}

function enabledHooksExist() {
  return active_hooks.array.length > 0;
}

function hasAsyncIdStack() {
  return hasHooks(kStackLength);
}

type Fn = (...args: unknown[]) => unknown;

// deno-lint-ignore camelcase
const no_promise_hook_symbol = Symbol("no_promise_hook");

class AsyncHook {
  [init_symbol]: Fn;
  [before_symbol]: Fn;
  [after_symbol]: Fn;
  [destroy_symbol]: Fn;
  [promise_resolve_symbol]: Fn;
  [no_promise_hook_symbol]: boolean;

  constructor({
    init,
    before,
    after,
    destroy,
    promiseResolve,
    trackPromises,
  }: {
    init: Fn;
    before: Fn;
    after: Fn;
    destroy: Fn;
    promiseResolve: Fn;
    trackPromises?: boolean;
  }) {
    if (init !== undefined && typeof init !== "function") {
      throw new ERR_ASYNC_CALLBACK("hook.init");
    }
    if (before !== undefined && typeof before !== "function") {
      throw new ERR_ASYNC_CALLBACK("hook.before");
    }
    if (after !== undefined && typeof after !== "function") {
      throw new ERR_ASYNC_CALLBACK("hook.after");
    }
    if (destroy !== undefined && typeof destroy !== "function") {
      throw new ERR_ASYNC_CALLBACK("hook.destroy");
    }
    if (promiseResolve !== undefined && typeof promiseResolve !== "function") {
      throw new ERR_ASYNC_CALLBACK("hook.promiseResolve");
    }
    if (trackPromises !== undefined && typeof trackPromises !== "boolean") {
      throw new ERR_INVALID_ARG_TYPE("trackPromises", "boolean", trackPromises);
    }
    if (trackPromises === false && promiseResolve !== undefined) {
      throw new ERR_INVALID_ARG_VALUE(
        "trackPromises",
        trackPromises,
        "must not be false when promiseResolve is enabled",
      );
    }

    this[init_symbol] = init;
    this[before_symbol] = before;
    this[after_symbol] = after;
    this[destroy_symbol] = destroy;
    this[promise_resolve_symbol] = promiseResolve;
    this[no_promise_hook_symbol] = trackPromises === false;
  }

  enable() {
    // The set of callbacks for a hook should be the same regardless of whether
    // enable()/disable() are run during their execution. The following
    // references are reassigned to the tmp arrays if a hook is currently being
    // processed.
    // deno-lint-ignore camelcase
    const { 0: hooks_array, 1: hook_fields } = getHookArrays();

    // Each hook is only allowed to be added once.
    if (ArrayPrototypeIncludes(hooks_array, this)) {
      return this;
    }

    // deno-lint-ignore camelcase
    const prev_kTotals = hook_fields[kTotals];

    // createHook() has already enforced that the callbacks are all functions,
    // so here simply increment the count of whether each callbacks exists or
    // not.
    hook_fields[kTotals] = hook_fields[kInit] += +!!this[init_symbol];
    hook_fields[kTotals] += hook_fields[kBefore] += +!!this[before_symbol];
    hook_fields[kTotals] += hook_fields[kAfter] += +!!this[after_symbol];
    hook_fields[kTotals] += hook_fields[kDestroy] += +!!this[destroy_symbol];
    hook_fields[kTotals] += hook_fields[kPromiseResolve] +=
      +!!this[promise_resolve_symbol];
    ArrayPrototypePush(hooks_array, this);

    if (prev_kTotals === 0 && hook_fields[kTotals] > 0) {
      enableHooks();
    }

    // Install V8 promise hooks lazily, the first time any promise-tracking hook
    // needs them. A hook created with `trackPromises: false` opts out, matching
    // Node's kNoPromiseHook (lib/async_hooks.js).
    if (!this[no_promise_hook_symbol]) {
      ensurePromiseHooks();
    }

    return this;
  }

  disable() {
    // deno-lint-ignore camelcase
    const { 0: hooks_array, 1: hook_fields } = getHookArrays();

    const index = ArrayPrototypeIndexOf(hooks_array, this);
    if (index === -1) {
      return this;
    }

    // deno-lint-ignore camelcase
    const prev_kTotals = hook_fields[kTotals];

    hook_fields[kTotals] = hook_fields[kInit] -= +!!this[init_symbol];
    hook_fields[kTotals] += hook_fields[kBefore] -= +!!this[before_symbol];
    hook_fields[kTotals] += hook_fields[kAfter] -= +!!this[after_symbol];
    hook_fields[kTotals] += hook_fields[kDestroy] -= +!!this[destroy_symbol];
    hook_fields[kTotals] += hook_fields[kPromiseResolve] -=
      +!!this[promise_resolve_symbol];
    ArrayPrototypeSplice(hooks_array, index, 1);

    if (prev_kTotals > 0 && hook_fields[kTotals] === 0) {
      disableHooks();
    }

    return this;
  }
}

return {
  asyncIdSymbol,
  ownerSymbol,
  newAsyncId,
  emitInit: emitInitNative,
  constants,
  executionAsyncId,
  triggerAsyncId,
  executionAsyncResource,
  enterAsyncResource,
  exitAsyncResource,
  enterAsyncResourceIfActive,
  exitAsyncResourceIfActive,
  emitBefore,
  emitAfter,
  emitDestroy,
  drainDestroyAsyncIds,
  emitPromiseResolve,
  runInPromiseRejectionScope,
  getDefaultTriggerAsyncId,
  defaultTriggerAsyncIdScope,
  enabledHooksExist,
  hasAsyncIdStack,
  AsyncHook,
  registerDestroyHook,
  async_id_symbol,
  trigger_async_id_symbol,
  init_symbol,
  before_symbol,
  after_symbol,
  destroy_symbol,
  promise_resolve_symbol,
  symbols,
};
})();
