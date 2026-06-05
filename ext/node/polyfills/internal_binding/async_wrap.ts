// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// This module ports:
// - https://github.com/nodejs/node/blob/master/src/async_wrap-inl.h
// - https://github.com/nodejs/node/blob/master/src/async_wrap.cc
// - https://github.com/nodejs/node/blob/master/src/async_wrap.h

// TODO(petamoriken): enable prefer-primordials for node polyfills
// deno-lint-ignore-file prefer-primordials
(function () {
const { core } = __bootstrap;
const { AsyncWrap, op_node_new_async_id } = core.ops;

function registerDestroyHook(
  // deno-lint-ignore no-explicit-any
  _target: any,
  _asyncId: number,
  _prop: { destroyed: boolean },
) {
  // TODO(kt3k): implement actual procedures
}

// Mirror of the four V8 promise hooks currently installed, exposed for Node's
// `internalBinding('async_wrap').getPromiseHooks()` introspection
// (see test/async-hooks/test-track-promises-false-check.js). deno_core's
// `core.setPromiseHooks` is append-only, so internal/async_hooks.ts pushes the
// active set here whenever it installs them; before that, all four are
// `undefined`, matching Node when no promise hooks are tracked.
// deno-lint-ignore no-explicit-any
const promiseHooksForReporting: (((...args: any[]) => void) | undefined)[] = [
  undefined,
  undefined,
  undefined,
  undefined,
];

function getPromiseHooks() {
  return [
    promiseHooksForReporting[0],
    promiseHooksForReporting[1],
    promiseHooksForReporting[2],
    promiseHooksForReporting[3],
  ];
}

function setPromiseHooksForReporting(
  // deno-lint-ignore no-explicit-any
  hooks: (((...args: any[]) => void) | undefined)[] | null,
) {
  for (let i = 0; i < 4; i++) {
    promiseHooksForReporting[i] = hooks === null ? undefined : hooks[i];
  }
}

enum constants {
  kInit,
  kBefore,
  kAfter,
  kDestroy,
  kPromiseResolve,
  kTotals,
  kCheck,
  kExecutionAsyncId,
  kTriggerAsyncId,
  kAsyncIdCounter,
  kDefaultTriggerAsyncId,
  kUsesExecutionAsyncResource,
  kStackLength,
}

const asyncHookFields = new Uint32Array(Object.keys(constants).length);

// Increment the internal id counter and return the value.
function newAsyncId() {
  return op_node_new_async_id();
}

enum UidFields {
  kExecutionAsyncId,
  kTriggerAsyncId,
  kDefaultTriggerAsyncId,
  kUidFieldsCount,
}

const asyncIdFields = new Float64Array(Object.keys(UidFields).length);

// `kDefaultTriggerAsyncId` should be `-1`, this indicates that there is no
// specified default value and it should fallback to the executionAsyncId.
// 0 is not used as the magic value, because that indicates a missing
// context which is different from a default context.
asyncIdFields[UidFields.kDefaultTriggerAsyncId] = -1;

enum providerType {
  NONE,
  DIRHANDLE,
  DNSCHANNEL,
  ELDHISTOGRAM,
  FILEHANDLE,
  FILEHANDLECLOSEREQ,
  FIXEDSIZEBLOBCOPY,
  FSEVENTWRAP,
  FSREQCALLBACK,
  FSREQPROMISE,
  GETADDRINFOREQWRAP,
  GETNAMEINFOREQWRAP,
  HEAPSNAPSHOT,
  HTTP2SESSION,
  HTTP2STREAM,
  HTTP2PING,
  HTTP2SETTINGS,
  HTTPINCOMINGMESSAGE,
  HTTPCLIENTREQUEST,
  JSSTREAM,
  JSUDPWRAP,
  MESSAGEPORT,
  PIPECONNECTWRAP,
  PIPESERVERWRAP,
  PIPEWRAP,
  PROCESSWRAP,
  PROMISE,
  QUERYWRAP,
  SHUTDOWNWRAP,
  SIGNALWRAP,
  STATWATCHER,
  STREAMPIPE,
  TCPCONNECTWRAP,
  TCPSERVERWRAP,
  TCPWRAP,
  TTYWRAP,
  UDPSENDWRAP,
  UDPWRAP,
  SIGINTWATCHDOG,
  WORKER,
  WORKERHEAPSNAPSHOT,
  WRITEWRAP,
  ZLIB,
}

// Canonical async-wrap provider map, mirroring Node's
// internalBinding('async_wrap').Providers. This is the single source of truth;
// the public async_hooks polyfill derives its frozen `asyncWrapProviders` from
// it (see test/async-hooks/test-async-wrap-providers.js, which asserts they are
// deep-equal). The numbering matches Node's AsyncWrap provider enum.
const Providers = {
  __proto__: null,
  NONE: 0,
  DIRHANDLE: 1,
  DNSCHANNEL: 2,
  ELDHISTOGRAM: 3,
  FILEHANDLE: 4,
  FILEHANDLECLOSEREQ: 5,
  BLOBREADER: 6,
  FSEVENTWRAP: 7,
  FSREQCALLBACK: 8,
  FSREQPROMISE: 9,
  GETADDRINFOREQWRAP: 10,
  GETNAMEINFOREQWRAP: 11,
  HEAPSNAPSHOT: 12,
  HTTP2SESSION: 13,
  HTTP2STREAM: 14,
  HTTP2PING: 15,
  HTTP2SETTINGS: 16,
  HTTPINCOMINGMESSAGE: 17,
  HTTPCLIENTREQUEST: 18,
  JSSTREAM: 19,
  JSUDPWRAP: 20,
  MESSAGEPORT: 21,
  PIPECONNECTWRAP: 22,
  PIPESERVERWRAP: 23,
  PIPEWRAP: 24,
  PROCESSWRAP: 25,
  PROMISE: 26,
  QUERYWRAP: 27,
  QUIC_ENDPOINT: 28,
  QUIC_LOGSTREAM: 29,
  QUIC_PACKET: 30,
  QUIC_SESSION: 31,
  QUIC_STREAM: 32,
  QUIC_UDP: 33,
  SHUTDOWNWRAP: 34,
  SIGNALWRAP: 35,
  STATWATCHER: 36,
  STREAMPIPE: 37,
  TCPCONNECTWRAP: 38,
  TCPSERVERWRAP: 39,
  TCPWRAP: 40,
  TTYWRAP: 41,
  UDPSENDWRAP: 42,
  UDPWRAP: 43,
  SIGINTWATCHDOG: 44,
  WORKER: 45,
  WORKERHEAPSNAPSHOT: 46,
  WRITEWRAP: 47,
  ZLIB: 48,
  CHECKPRIMEREQUEST: 49,
  PBKDF2REQUEST: 50,
  KEYPAIRGENREQUEST: 51,
  KEYGENREQUEST: 52,
  KEYEXPORTREQUEST: 53,
  CIPHERREQUEST: 54,
  DERIVEBITSREQUEST: 55,
  HASHREQUEST: 56,
  RANDOMBYTESREQUEST: 57,
  RANDOMPRIMEREQUEST: 58,
  SCRYPTREQUEST: 59,
  SIGNREQUEST: 60,
  TLSWRAP: 61,
  VERIFYREQUEST: 62,
};

return {
  async_hook_fields: asyncHookFields,
  asyncIdFields,
  AsyncWrap,
  registerDestroyHook,
  newAsyncId,
  constants,
  UidFields,
  providerType,
  Providers,
  getPromiseHooks,
  setPromiseHooksForReporting,
};
})();
