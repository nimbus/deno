// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

// deno-lint-ignore-file no-explicit-any

(function () {
const { core, primordials } = __bootstrap;

const {
  ArrayBufferIsView,
  ArrayBufferPrototype,
  ArrayBufferPrototypeGetByteLength,
  ArrayPrototypeIncludes,
  DataViewPrototypeGetBuffer,
  DataViewPrototypeGetByteLength,
  DataViewPrototypeGetByteOffset,
  Error,
  FunctionPrototypeApply,
  FunctionPrototypeCall,
  MathMin,
  ObjectDefineProperty,
  ObjectPrototypeIsPrototypeOf,
  ObjectSetPrototypeOf,
  PromisePrototypeThen,
  queueMicrotask,
  RangeError,
  ReflectHas,
  StringFromCharCode,
  StringPrototypeIncludes,
  StringPrototypeToLowerCase,
  SymbolSpecies,
  TypeError,
  TypedArrayPrototypeGetBuffer,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeGetByteOffset,
  Uint8Array,
  Uint8ArrayPrototype,
} = primordials;

const {
  op_node_create_private_key,
  op_node_create_public_key,
  op_node_derive_public_key_from_private_key,
  op_node_get_asymmetric_key_details,
  op_node_get_asymmetric_key_type,
  op_node_sign,
  op_node_sign_ed25519,
  op_node_sign_ed448,
  op_node_sign_ml_dsa,
  op_node_sign_ml_dsa_async,
  op_node_verify,
  op_node_verify_ed25519,
  op_node_verify_ed448,
  op_node_verify_ml_dsa,
  op_node_verify_ml_dsa_async,
} = core.ops;

const {
  validateFunction,
  validateString,
} = core.loadExtScript("ext:deno_node/internal/validators.mjs");
const { Buffer } = core.loadExtScript("ext:deno_node/internal/buffer.mjs");
const { isAnyArrayBuffer } = core.loadExtScript(
  "ext:deno_node/internal/util/types.ts",
);

const lazyWritable = core.createLazyLoader("node:_stream_writable");

const {
  kConsumePrivate,
  kConsumePublic,
  KeyObject,
  prepareAsymmetricKey,
  PrivateKeyObject,
  PublicKeyObject,
} = core.loadExtScript("ext:deno_node/internal/crypto/keys.ts");
const { createHash } = core.loadExtScript(
  "ext:deno_node/internal/crypto/hash.ts",
);
const {
  ERR_CRYPTO_SIGN_KEY_REQUIRED,
  ERR_INVALID_ARG_TYPE,
  ERR_INVALID_ARG_VALUE,
} = core.loadExtScript("ext:deno_node/internal/errors.ts");

const FastBuffer = Buffer[SymbolSpecies];

function isMlDsaKeyType(keyType: string): boolean {
  return ArrayPrototypeIncludes(
    ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"],
    keyType,
  );
}

function unsupportedMlDsaDigest(): Error {
  const error = new Error(
    "error:03000094:digital envelope routines::COMMAND_NOT_SUPPORTED",
  );
  ObjectDefineProperty(error, "code", {
    __proto__: null,
    value: "ERR_OSSL_EVP_COMMAND_NOT_SUPPORTED",
    configurable: true,
  });
  return error;
}

function getPadding(options) {
  return getIntOption("padding", options);
}

function getSaltLength(options) {
  return getIntOption("saltLength", options);
}

function getDSASignatureEncoding(options) {
  if (typeof options === "object") {
    const { dsaEncoding = "der" } = options;
    if (dsaEncoding === "der") {
      return 0;
    } else if (dsaEncoding === "ieee-p1363") {
      return 1;
    }
    throw new ERR_INVALID_ARG_VALUE("options.dsaEncoding", dsaEncoding);
  }

  return 0;
}

function getIntOption(name, options) {
  const value = options[name];
  if (value !== undefined) {
    if (value === value >> 0) {
      return value;
    }
    throw new ERR_INVALID_ARG_VALUE(`options.${name}`, value);
  }
  return undefined;
}

function getContext(options): Uint8Array | undefined {
  const context = options?.context;
  if (context === undefined) {
    return undefined;
  }
  if (!ArrayBufferIsView(context)) {
    throw new ERR_INVALID_ARG_TYPE(
      "options.context",
      ["Buffer", "TypedArray", "DataView"],
      context,
    );
  }
  let bytes;
  try {
    bytes = new Uint8Array(
      DataViewPrototypeGetBuffer(context),
      DataViewPrototypeGetByteOffset(context),
      DataViewPrototypeGetByteLength(context),
    );
  } catch {
    bytes = new Uint8Array(
      TypedArrayPrototypeGetBuffer(context),
      TypedArrayPrototypeGetByteOffset(context),
      TypedArrayPrototypeGetByteLength(context),
    );
  }
  if (TypedArrayPrototypeGetByteLength(bytes) > 255) {
    const error = new RangeError("context string must be at most 255 bytes");
    ObjectDefineProperty(error, "code", {
      __proto__: null,
      configurable: true,
      value: "ERR_OUT_OF_RANGE",
    });
    throw error;
  }
  return bytes;
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

function unsupportedContext(): Error {
  const error = new Error("Context parameter is unsupported");
  ObjectDefineProperty(error, "code", {
    __proto__: null,
    configurable: true,
    value: "ERR_CRYPTO_OPERATION_FAILED",
  });
  return error;
}

// Private key types that need to be converted to public keys for verification
const PRIVATE_KEY_TYPES = ["pkcs8", "sec1"];

function isPrivateKeyType(type: string | undefined): boolean {
  return type !== undefined &&
    ArrayPrototypeIncludes(PRIVATE_KEY_TYPES, type);
}

function isPrivateKeyPem(data: ArrayBuffer | ArrayBufferView): boolean {
  const bytes = ObjectPrototypeIsPrototypeOf(ArrayBufferPrototype, data)
    ? new Uint8Array(
      data as ArrayBuffer,
      0,
      MathMin(ArrayBufferPrototypeGetByteLength(data as ArrayBuffer), 100),
    )
    : new Uint8Array(
      TypedArrayPrototypeGetBuffer(data as ArrayBufferView),
      TypedArrayPrototypeGetByteOffset(data as ArrayBufferView),
      MathMin(TypedArrayPrototypeGetByteLength(data as ArrayBufferView), 100),
    );
  const prefix = FunctionPrototypeApply(StringFromCharCode, null, bytes);
  return StringPrototypeIncludes(prefix, "PRIVATE KEY");
}

let Writable;
function getWritable() {
  if (!Writable) Writable = lazyWritable().default;
  return Writable;
}

class SignImpl {
  hash: any;
  #digestType: string;

  constructor(algorithm: string, _options?: any) {
    validateString(algorithm, "algorithm");

    ensureSignProtoSetup();
    const W = getWritable();
    FunctionPrototypeCall(W, this, {
      write(chunk, enc, callback) {
        this.update(chunk, enc);
        callback();
      },
    });

    algorithm = StringPrototypeToLowerCase(algorithm);

    this.#digestType = algorithm;
    try {
      this.hash = createHash(this.#digestType);
    } catch {
      throw new Error(`Invalid digest: ${algorithm}`);
    }
  }

  sign(
    privateKey: any,
    encoding?: any,
  ): Buffer | string {
    if (!privateKey) {
      throw new ERR_CRYPTO_SIGN_KEY_REQUIRED();
    }

    const res = prepareAsymmetricKey(privateKey, kConsumePrivate);

    // Options specific to RSA
    const rsaPadding = getPadding(privateKey);

    // Options specific to RSA-PSS
    const pssSaltLength = getSaltLength(privateKey);

    // Options specific to (EC)DSA
    const dsaSigEnc = getDSASignatureEncoding(privateKey);

    let handle;
    if (ReflectHas(res, "handle")) {
      handle = res.handle;
    } else {
      try {
        handle = op_node_create_private_key(
          res.data,
          res.format,
          res.type ?? "",
          res.passphrase,
          res.namedCurve,
        );
      } catch (err) {
        // Trigger any prototype setter for `library` (Node.js compatibility)
        (err as Record<string, unknown>).library = "PEM routines";
        throw err;
      }
    }
    let ret;
    try {
      ret = Buffer.from(op_node_sign(
        handle,
        this.hash.digest(),
        this.#digestType,
        pssSaltLength,
        rsaPadding,
        dsaSigEnc,
      ));
    } catch (err) {
      // Decorate RSA sign errors with OpenSSL-compatible properties.
      if (
        err && typeof err === "object" &&
        ReflectHas(err, "message") && typeof err.message === "string" &&
        StringPrototypeIncludes(err.message, "rsa routines") &&
        !ReflectHas(err, "library")
      ) {
        (err as Record<string, unknown>).library = "rsa routines";
      }
      throw err;
    }
    // deno-lint-ignore deno-internal/prefer-primordials -- Buffer.prototype.toString(encoding) is not a primordial
    return encoding && encoding !== "buffer" ? ret.toString(encoding) : ret;
  }

  update(
    data: any,
    encoding?: any,
  ): this {
    this.hash.update(data, encoding);
    return this;
  }
}

function Sign(algorithm: string, options?: any) {
  return new SignImpl(algorithm, options);
}

// Defer prototype setup
let _signProtoSetup = false;
function ensureSignProtoSetup() {
  if (_signProtoSetup) return;
  _signProtoSetup = true;
  const W = getWritable();
  ObjectSetPrototypeOf(SignImpl.prototype, W.prototype);
  ObjectSetPrototypeOf(SignImpl, W);
  ObjectSetPrototypeOf(VerifyImpl.prototype, W.prototype);
  ObjectSetPrototypeOf(VerifyImpl, W);
}

Sign.prototype = SignImpl.prototype;

class VerifyImpl {
  hash: any;
  #digestType: string;

  constructor(algorithm: string, _options?: any) {
    validateString(algorithm, "algorithm");

    ensureSignProtoSetup();
    const W = getWritable();
    FunctionPrototypeCall(W, this, {
      write(chunk, enc, callback) {
        this.update(chunk, enc);
        callback();
      },
    });

    algorithm = StringPrototypeToLowerCase(algorithm);

    this.#digestType = algorithm;
    try {
      this.hash = createHash(this.#digestType);
    } catch {
      throw new Error(`Invalid digest: ${algorithm}`);
    }
  }

  update(data: any, encoding?: string): this {
    this.hash.update(data, encoding);
    return this;
  }

  verify(
    publicKey: any,
    signature: any,
    encoding?: any,
  ): boolean {
    if (
      typeof signature !== "string" &&
      !ArrayBufferIsView(signature) &&
      !isAnyArrayBuffer(signature)
    ) {
      throw new ERR_INVALID_ARG_TYPE(
        "signature",
        ["string", "ArrayBuffer", "Buffer", "TypedArray", "DataView"],
        signature,
      );
    }
    const res = prepareAsymmetricKey(publicKey, kConsumePublic);

    // Options specific to RSA
    const rsaPadding = getPadding(publicKey);

    // Options specific to RSA-PSS
    const pssSaltLength = getSaltLength(publicKey);

    // Options specific to (EC)DSA
    const dsaSigEnc = getDSASignatureEncoding(publicKey);

    let handle;
    if (ReflectHas(res, "handle")) {
      handle = res.handle;
    } else if (
      isPrivateKeyType(res.type) ||
      (res.type === undefined && isPrivateKeyPem(res.data))
    ) {
      const privateHandle = op_node_create_private_key(
        res.data,
        res.format,
        res.type ?? "",
        res.passphrase,
        res.namedCurve,
      );
      handle = op_node_derive_public_key_from_private_key(privateHandle);
    } else {
      handle = op_node_create_public_key(
        res.data,
        res.format,
        res.type ?? "",
        res.passphrase,
        res.namedCurve,
      );
    }
    return op_node_verify(
      handle,
      this.hash.digest(),
      this.#digestType,
      Buffer.from(signature, encoding),
      pssSaltLength,
      rsaPadding,
      dsaSigEnc,
    );
  }
}

function Verify(algorithm: string, options?: any) {
  return new VerifyImpl(algorithm, options);
}

Verify.prototype = VerifyImpl.prototype;

function signOneShot(
  algorithm: string | null | undefined,
  data: ArrayBufferView,
  key: any,
  callback?: (error: Error | null, data: Buffer) => void,
): Buffer | void {
  if (algorithm != null) {
    validateString(algorithm, "algorithm");
  }

  if (callback !== undefined) {
    validateFunction(callback, "callback");
  }

  if (!ArrayBufferIsView(data) && typeof data !== "string") {
    throw new ERR_INVALID_ARG_TYPE(
      "data",
      ["Buffer", "TypedArray", "DataView"],
      data,
    );
  }

  if (!key) {
    throw new ERR_CRYPTO_SIGN_KEY_REQUIRED();
  }

  // Validate dsaEncoding early so it takes precedence over key errors
  if (
    typeof key === "object" && key !== null &&
    !(ObjectPrototypeIsPrototypeOf(KeyObject.prototype, key))
  ) {
    getDSASignatureEncoding(key);
  }

  // Normalize ArrayBufferView data to Uint8Array for Rust ops
  const dataBytes = ArrayBufferIsView(data) &&
      !(ObjectPrototypeIsPrototypeOf(Uint8ArrayPrototype, data))
    ? new Uint8Array(
      TypedArrayPrototypeGetBuffer(data as ArrayBufferView),
      TypedArrayPrototypeGetByteOffset(data as ArrayBufferView),
      TypedArrayPrototypeGetByteLength(data as ArrayBufferView),
    )
    : data as ArrayBufferView | string;
  const context = getContext(key);
  const contextBytes = context ?? new Uint8Array();

  try {
    const res = prepareAsymmetricKey(key, kConsumePrivate);
    let handle;
    if (ReflectHas(res, "handle")) {
      handle = res.handle;
    } else {
      handle = op_node_create_private_key(
        res.data,
        res.format,
        res.type ?? "",
        res.passphrase,
        res.namedCurve,
      );
    }

    let result: Buffer;
    const keyType = op_node_get_asymmetric_key_type(handle);
    if (
      !isMlDsaKeyType(keyType) && keyType !== "ed448" &&
      TypedArrayPrototypeGetByteLength(contextBytes) > 0
    ) {
      throw unsupportedContext();
    }
    if (isMlDsaKeyType(keyType)) {
      if (algorithm != null) {
        throw unsupportedMlDsaDigest();
      }
      if (callback) {
        const asyncData = typeof dataBytes === "string"
          ? Buffer.from(dataBytes)
          : dataBytes;
        dispatchAsyncCallback(
          () => op_node_sign_ml_dsa_async(handle, asyncData, contextBytes),
          (signature) => callback(null, Buffer.from(signature)),
          (error) => callback(error),
        );
        return;
      }
      result = Buffer.from(
        op_node_sign_ml_dsa(handle, dataBytes, contextBytes),
      );
    } else if (keyType === "ed25519") {
      if (algorithm != null && algorithm !== "sha512") {
        throw new TypeError("Only 'sha512' is supported for Ed25519 keys");
      }
      result = new FastBuffer(64);
      op_node_sign_ed25519(handle, dataBytes, result);
    } else if (keyType === "ed448") {
      result = new FastBuffer(114);
      op_node_sign_ed448(handle, dataBytes, contextBytes, result);
    } else {
      let digest = algorithm;
      if (digest == null) {
        if (keyType === "rsa-pss") {
          const details = op_node_get_asymmetric_key_details(handle);
          if (details.hashAlgorithm) {
            digest = details.hashAlgorithm;
          }
        }
        if (digest == null) {
          throw new TypeError(
            "Algorithm must be specified when using non-Ed25519 keys",
          );
        }
      }
      // Preserve padding/saltLength options from the original key
      const privateKeyObject = new PrivateKeyObject(handle);
      const signKey = typeof key === "object" &&
          !(ObjectPrototypeIsPrototypeOf(KeyObject.prototype, key))
        ? { ...key, key: privateKeyObject }
        : privateKeyObject;
      result = Sign(digest).update(dataBytes)
        .sign(signKey);
    }

    if (callback) {
      setTimeout(() => callback(null, result));
    } else {
      return result;
    }
  } catch (err) {
    if (callback) {
      setTimeout(() => callback(err));
    } else {
      throw err;
    }
  }
}

function verifyOneShot(
  algorithm: string | null | undefined,
  data: any,
  key: any,
  signature: any,
  callback?: (error: Error | null, result: boolean) => void,
): boolean | void {
  if (algorithm != null) {
    validateString(algorithm, "algorithm");
  }

  if (callback !== undefined) {
    validateFunction(callback, "callback");
  }

  if (!ArrayBufferIsView(data) && typeof data !== "string") {
    throw new ERR_INVALID_ARG_TYPE(
      "data",
      ["Buffer", "TypedArray", "DataView"],
      data,
    );
  }

  if (
    !ArrayBufferIsView(signature) && !isAnyArrayBuffer(signature) &&
    typeof signature !== "string"
  ) {
    throw new ERR_INVALID_ARG_TYPE(
      "signature",
      ["string", "ArrayBuffer", "Buffer", "TypedArray", "DataView"],
      signature,
    );
  }

  if (!key) {
    throw new ERR_CRYPTO_SIGN_KEY_REQUIRED();
  }

  // Normalize ArrayBufferView data to Uint8Array for Rust ops
  const dataBytes = ArrayBufferIsView(data) &&
      !(ObjectPrototypeIsPrototypeOf(Uint8ArrayPrototype, data))
    ? new Uint8Array(
      TypedArrayPrototypeGetBuffer(data as ArrayBufferView),
      TypedArrayPrototypeGetByteOffset(data as ArrayBufferView),
      TypedArrayPrototypeGetByteLength(data as ArrayBufferView),
    )
    : data as ArrayBufferView | string;
  const context = getContext(key);
  const contextBytes = context ?? new Uint8Array();

  try {
    const res = prepareAsymmetricKey(key, kConsumePublic);
    let handle;
    if (ReflectHas(res, "handle")) {
      handle = res.handle;
    } else if (
      isPrivateKeyType(res.type) ||
      (res.type === undefined && isPrivateKeyPem(res.data))
    ) {
      const privateHandle = op_node_create_private_key(
        res.data,
        res.format,
        res.type ?? "",
        res.passphrase,
        res.namedCurve,
      );
      handle = op_node_derive_public_key_from_private_key(privateHandle);
    } else {
      handle = op_node_create_public_key(
        res.data,
        res.format,
        res.type ?? "",
        res.passphrase,
        res.namedCurve,
      );
    }

    let result: boolean;
    const keyType = op_node_get_asymmetric_key_type(handle);
    if (
      !isMlDsaKeyType(keyType) && keyType !== "ed448" &&
      TypedArrayPrototypeGetByteLength(contextBytes) > 0
    ) {
      throw unsupportedContext();
    }
    if (isMlDsaKeyType(keyType)) {
      if (algorithm != null) {
        throw unsupportedMlDsaDigest();
      }
      if (callback) {
        const asyncData = typeof dataBytes === "string"
          ? Buffer.from(dataBytes)
          : dataBytes;
        const asyncSignature = typeof signature === "string"
          ? Buffer.from(signature)
          : signature;
        dispatchAsyncCallback(
          () =>
            op_node_verify_ml_dsa_async(
              handle,
              asyncData,
              asyncSignature,
              contextBytes,
            ),
          (verified) => callback(null, verified),
          (error) => callback(error, false),
        );
        return;
      }
      result = op_node_verify_ml_dsa(
        handle,
        dataBytes,
        signature,
        contextBytes,
      );
    } else if (keyType === "ed25519") {
      if (algorithm != null && algorithm !== "sha512") {
        throw new TypeError("Only 'sha512' is supported for Ed25519 keys");
      }
      result = op_node_verify_ed25519(handle, dataBytes, signature);
    } else if (keyType === "ed448") {
      result = op_node_verify_ed448(
        handle,
        dataBytes,
        contextBytes,
        signature,
      );
    } else if (
      keyType === "x25519" || keyType === "x448" || keyType === "dh"
    ) {
      throw new TypeError(
        "operation not supported for this keytype",
      );
    } else {
      let digest = algorithm;
      if (digest == null) {
        if (keyType === "rsa-pss") {
          const details = op_node_get_asymmetric_key_details(handle);
          if (details.hashAlgorithm) {
            digest = details.hashAlgorithm;
          }
        }
        if (digest == null) {
          throw new TypeError("no default digest");
        }
      }
      // Preserve padding/saltLength options from the original key
      const publicKeyObject = new PublicKeyObject(handle);
      const verifyKey = typeof key === "object" &&
          !(ObjectPrototypeIsPrototypeOf(KeyObject.prototype, key))
        ? { ...key, key: publicKeyObject }
        : publicKeyObject;
      result = Verify(digest).update(dataBytes)
        .verify(verifyKey, signature);
    }

    if (callback) {
      setTimeout(() => callback(null, result));
    } else {
      return result;
    }
  } catch (err) {
    if (callback) {
      setTimeout(() => callback(err));
    } else {
      throw err;
    }
  }
}

return {
  signOneShot,
  verifyOneShot,
  Sign,
  Verify,
  SignImpl,
  VerifyImpl,
  default: {
    signOneShot,
    verifyOneShot,
    Sign,
    Verify,
  },
};
})();
