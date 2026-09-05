// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

// deno-lint-ignore-file no-explicit-any

(function () {
const { core, primordials } = __bootstrap;
const {
  Error,
  ErrorPrototype,
  ObjectDefineProperty,
  ObjectPrototypeIsPrototypeOf,
  PromisePrototypeThen,
  queueMicrotask,
  ReflectHas,
} = primordials;

const {
  op_node_create_private_key,
  op_node_create_public_key,
  op_node_kem_decapsulate,
  op_node_kem_decapsulate_async,
  op_node_kem_encapsulate,
  op_node_kem_encapsulate_async,
} = core.ops;

const { Buffer } = core.loadExtScript(
  "ext:deno_node/internal/buffer.mjs",
);
const {
  getArrayBufferOrView,
  kConsumePrivate,
  kConsumePublic,
  prepareAsymmetricKey,
} = core.loadExtScript("ext:deno_node/internal/crypto/keys.ts");
const { validateFunction } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);

function operationError(message: string): Error {
  const error = new Error(message);
  ObjectDefineProperty(error, "code", {
    __proto__: null,
    configurable: true,
    value: "ERR_CRYPTO_OPERATION_FAILED",
  });
  return error;
}

function unsupportedAlgorithm(error: unknown): Error {
  const result = ObjectPrototypeIsPrototypeOf(ErrorPrototype, error)
    ? error
    : new Error("KEM is not supported for this key type");
  ObjectDefineProperty(result, "code", {
    __proto__: null,
    configurable: true,
    value: "ERR_OSSL_EVP_UNSUPPORTED_ALGORITHM",
  });
  return result;
}

function dispatchAsyncCallback<T>(
  operation: () => Promise<T>,
  onFulfilled: (value: T) => void,
  onRejected: (error: unknown) => void,
) {
  let promise;
  try {
    promise = operation();
  } catch (error) {
    queueMicrotask(() => onRejected(error));
    return;
  }
  ObjectDefineProperty(promise, "constructor", {
    __proto__: null,
    value: undefined,
    configurable: true,
  });
  PromisePrototypeThen(
    promise,
    (value) => queueMicrotask(() => onFulfilled(value)),
    (error) => queueMicrotask(() => onRejected(error)),
  );
}

function publicHandle(key: any) {
  const prepared = prepareAsymmetricKey(key, kConsumePublic);
  return ReflectHas(prepared, "handle")
    ? prepared.handle
    : op_node_create_public_key(
      prepared.data,
      prepared.format,
      prepared.type ?? "",
      prepared.passphrase,
      prepared.namedCurve,
    );
}

function privateHandle(key: any) {
  const prepared = prepareAsymmetricKey(key, kConsumePrivate);
  return ReflectHas(prepared, "handle")
    ? prepared.handle
    : op_node_create_private_key(
      prepared.data,
      prepared.format,
      prepared.type ?? "",
      prepared.passphrase,
      prepared.namedCurve,
    );
}

function encapsulateSync(key: any) {
  const handle = publicHandle(key);
  try {
    const { sharedKey, ciphertext } = op_node_kem_encapsulate(handle);
    return {
      sharedKey: Buffer.from(sharedKey),
      ciphertext: Buffer.from(ciphertext),
    };
  } catch (error) {
    throw unsupportedAlgorithm(error);
  }
}

function decapsulateSync(key: any, ciphertext: any): Buffer {
  const handle = privateHandle(key);
  ciphertext = getArrayBufferOrView(ciphertext, "ciphertext");
  try {
    return Buffer.from(op_node_kem_decapsulate(handle, ciphertext));
  } catch {
    throw operationError("Decapsulation failed");
  }
}

function encapsulate(
  key: any,
  callback?: (error: Error | null, result?: any) => void,
) {
  if (callback !== undefined) {
    validateFunction(callback, "callback");
  }
  if (callback === undefined) {
    return encapsulateSync(key);
  }
  const handle = publicHandle(key);
  dispatchAsyncCallback(
    () => op_node_kem_encapsulate_async(handle),
    ({ sharedKey, ciphertext }) =>
      callback(null, {
        sharedKey: Buffer.from(sharedKey),
        ciphertext: Buffer.from(ciphertext),
      }),
    (error) => callback(unsupportedAlgorithm(error)),
  );
}

function decapsulate(
  key: any,
  ciphertext: any,
  callback?: (error: Error | null, sharedKey?: Buffer) => void,
) {
  if (callback !== undefined) {
    validateFunction(callback, "callback");
  }
  if (callback === undefined) {
    return decapsulateSync(key, ciphertext);
  }
  const handle = privateHandle(key);
  ciphertext = getArrayBufferOrView(ciphertext, "ciphertext");
  dispatchAsyncCallback(
    () => op_node_kem_decapsulate_async(handle, ciphertext),
    (sharedKey) => callback(null, Buffer.from(sharedKey)),
    () => callback(operationError("Decapsulation failed")),
  );
}

return {
  decapsulate,
  encapsulate,
  default: {
    decapsulate,
    encapsulate,
  },
};
})();
