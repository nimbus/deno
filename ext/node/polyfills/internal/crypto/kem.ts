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
  ReflectHas,
} = primordials;

const {
  op_node_create_private_key,
  op_node_create_public_key,
  op_node_kem_decapsulate,
  op_node_kem_encapsulate,
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

function encapsulateSync(key: any) {
  const prepared = prepareAsymmetricKey(key, kConsumePublic);
  const handle = ReflectHas(prepared, "handle")
    ? prepared.handle
    : op_node_create_public_key(
      prepared.data,
      prepared.format,
      prepared.type ?? "",
      prepared.passphrase,
      prepared.namedCurve,
    );
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
  const prepared = prepareAsymmetricKey(key, kConsumePrivate);
  const handle = ReflectHas(prepared, "handle")
    ? prepared.handle
    : op_node_create_private_key(
      prepared.data,
      prepared.format,
      prepared.type ?? "",
      prepared.passphrase,
      prepared.namedCurve,
    );
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
  try {
    const result = encapsulateSync(key);
    if (callback) {
      setTimeout(() => callback(null, result));
      return;
    }
    return result;
  } catch (error) {
    if (callback) {
      setTimeout(() => callback(error as Error));
      return;
    }
    throw error;
  }
}

function decapsulate(
  key: any,
  ciphertext: any,
  callback?: (error: Error | null, sharedKey?: Buffer) => void,
) {
  if (callback !== undefined) {
    validateFunction(callback, "callback");
  }
  try {
    const sharedKey = decapsulateSync(key, ciphertext);
    if (callback) {
      setTimeout(() => callback(null, sharedKey));
      return;
    }
    return sharedKey;
  } catch (error) {
    if (callback) {
      setTimeout(() => callback(error as Error));
      return;
    }
    throw error;
  }
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
