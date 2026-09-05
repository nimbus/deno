// Copyright 2018-2026 the Deno authors. MIT license.

// This module is intentionally thin: every WebCrypto algorithm body
// (`SubtleCrypto.{digest,encrypt,decrypt,sign,verify,deriveBits,deriveKey,
// importKey,exportKey,wrapKey,unwrapKey,generateKey,getPublicKey,
// encapsulateKey,encapsulateBits,decapsulateKey,decapsulateBits,supports}`,
// and the `Crypto.{getRandomValues,randomUUID,subtle}` members) is
// implemented natively on the cppgc-wrapped Rust classes in
// `ext/crypto/{crypto,subtle_crypto,crypto_key}.rs` and the per-algorithm
// modules they delegate to. What remains in JS is bookkeeping the v8 layer
// requires us to do outside cppgc: the privateCustomInspect decoration on
// the three prototypes, the lazy minting of the `Crypto` / `SubtleCrypto`
// singletons (cppgc allocations can't run at snapshot-build time), the
// structured-clone resurrection callback, and the small `deriveBits`
// forwarder that gives the spec-mandated `Function.length === 2`.

(function () {
const { core, primordials } = __bootstrap;
const {
  op_crypto_error_policy,
  op_crypto_is_seeded,
  op_crypto_random_uuid_batch,
  Crypto,
  CryptoKey,
  SubtleCrypto,
} = core.ops;
const {
  ArrayBufferIsView,
  ArrayBufferPrototypeGetByteLength,
  ArrayIsArray,
  ArrayPrototypeIncludes,
  DataViewPrototypeGetByteLength,
  Error,
  FunctionPrototypeCall,
  MathCeil,
  NumberIsFinite,
  NumberIsInteger,
  ObjectAssign,
  ObjectCreate,
  ObjectDefineProperty,
  ObjectGetOwnPropertyDescriptor,
  ObjectHasOwn,
  ObjectPrototypeIsPrototypeOf,
  Promise,
  PromisePrototype,
  PromisePrototypeThen,
  SafeArrayIterator,
  StringPrototypeIncludes,
  StringPrototypeSlice,
  StringPrototypeToUpperCase,
  SymbolFor,
  TypedArrayPrototypeGetSymbolToStringTag,
  TypedArrayPrototypeGetByteLength,
  TypeError,
} = primordials;
const { isAnyArrayBuffer, isTypedArray } = core;

const webidl = core.loadExtScript("ext:deno_webidl/00_webidl.js");
const { createFilteredInspectProxy } = core.loadExtScript(
  "ext:deno_web/01_console.js",
);
const { DOMException } = core.loadExtScript(
  "ext:deno_web/01_dom_exception.js",
);
// op2-generated interface constructors expose the macro's internal
// new-target signal (`_: bool`) as a formal parameter, giving the
// constructor's `.length` a value of 1. Per Web IDL, the interface
// object's `.length` is the minimum-overload required-argument count -- 0
// for all three classes (`Crypto`, `CryptoKey`, `SubtleCrypto` have no
// constructor exposed). Also pin the `prototype` slot to non-writable:
// V8's FunctionTemplate-derived constructors default to a writable
// prototype, but Web IDL requires
// `{ writable: false, enumerable: false, configurable: false }`. The
// `configurable: false` slot is already set, and ECMAScript permits
// downgrading `writable: true -> false` on a non-configurable property.
function applyWebIdlInterfaceShape(interface_) {
  ObjectDefineProperty(interface_, "length", {
    __proto__: null,
    value: 0,
    writable: false,
    enumerable: false,
    configurable: true,
  });
  ObjectDefineProperty(interface_, "prototype", {
    __proto__: null,
    writable: false,
  });
}

// `CryptoKey` is the cppgc-wrapped Rust class imported above; the `type`,
// `extractable`, `usages` and `algorithm` getters and the underlying state
// all live in Rust (`ext/crypto/crypto_key.rs`). The JS shim only attaches
// the `Deno.privateCustomInspect` symbol to the prototype.
const CryptoKeyPrototype = CryptoKey.prototype;
ObjectDefineProperty(
  CryptoKeyPrototype,
  SymbolFor("Deno.privateCustomInspect"),
  {
    __proto__: null,
    value: function (inspect, inspectOptions) {
      if (!CryptoKey.isKey(this)) {
        return inspect(
          createFilteredInspectProxy({
            object: this,
            evaluate: false,
            keys: [
              "type",
              "extractable",
              "algorithm",
              "usages",
            ],
          }),
          inspectOptions,
        );
      }
      const snapshot = CryptoKey.inspectSnapshot(this);
      const view = ObjectCreate(CryptoKeyPrototype);
      ObjectDefineProperty(view, "type", {
        __proto__: null,
        value: snapshot.type,
        enumerable: true,
        configurable: true,
      });
      ObjectDefineProperty(view, "extractable", {
        __proto__: null,
        value: snapshot.extractable,
        enumerable: true,
        configurable: true,
      });
      ObjectDefineProperty(view, "algorithm", {
        __proto__: null,
        value: snapshot.algorithm,
        enumerable: true,
        configurable: true,
      });
      ObjectDefineProperty(view, "usages", {
        __proto__: null,
        value: snapshot.usages,
        enumerable: true,
        configurable: true,
      });
      return inspect(
        createFilteredInspectProxy({
          object: view,
          evaluate: ObjectPrototypeIsPrototypeOf(CryptoKeyPrototype, this),
          keys: [
            "type",
            "extractable",
            "algorithm",
            "usages",
          ],
        }),
        inspectOptions,
      );
    },
    enumerable: false,
    configurable: true,
    writable: true,
  },
);
webidl.configureInterface(CryptoKey);
applyWebIdlInterfaceShape(CryptoKey);

// Structured-clone resurrection. The inherited host-object hook installed by
// `make_crypto_key` (`ext/crypto/make_key.rs`) returns a
// snapshot with shape `{ type: "CryptoKey", keyType, extractable, usages,
// algorithm, keyData }`; the static method `CryptoKey.fromCloneData(data)`
// (`ext/crypto/node_interop.rs::from_clone_data`) parses the snapshot back
// into a freshly-minted cppgc instance.
core.registerCloneableResource(
  "CryptoKey",
  (data) => CryptoKey.fromCloneData(data),
);

// `SubtleCrypto.prototype.deriveBits` is a cppgc method declared with three
// formal params (`algorithm`, `baseKey`, `length`). The op2 macro has no
// way to declare an *optional* param while keeping the macro-level
// minimum-arg check, so we cannot use `#[required(2)]` (it would also cap
// the `Function.length` slot to 2 and route through `async_op_2`, which
// silently drops the third user argument before it reaches Rust -- see
// `setUpAsyncStub` in `libs/core/00_infra.js`). The spec (and WebIDL idl
// harness) requires `Function.length === 2` for
// `deriveBits(AlgorithmIdentifier, CryptoKey, optional unsigned long?)`,
// so wrap the cppgc method in a small forwarder whose declared params
// give it `length === 2` (the `length` default doesn't count) and
// explicitly pass all three args through.
const SubtleCryptoPrototype = SubtleCrypto.prototype;
const cppgcDeriveBits = SubtleCryptoPrototype.deriveBits;

const WEB_CRYPTO_ERROR_POLICY_WEB_STANDARD = 0;
const WEB_CRYPTO_ERROR_POLICY_NODE22 = 1;
const WEB_CRYPTO_ERROR_POLICY_NODE24 = 2;

function tagNodeErrorCode(error, code) {
  if (
    (typeof error === "object" && error !== null) ||
    typeof error === "function"
  ) {
    try {
      ObjectDefineProperty(error, "code", {
        __proto__: null,
        value: code,
        configurable: true,
        writable: true,
      });
    } catch {
      // A thrown value can be frozen or non-extensible. Error decoration
      // must not replace the original exception with this secondary failure.
    }
  }
  return error;
}

function rawAlgorithmName(algorithm) {
  if (typeof algorithm === "string") {
    return StringPrototypeToUpperCase(algorithm);
  }
  if (
    algorithm !== null &&
    typeof algorithm === "object" &&
    typeof algorithm.name === "string"
  ) {
    return StringPrototypeToUpperCase(algorithm.name);
  }
  return undefined;
}

function hasRequiredOption(algorithm, name) {
  return ObjectHasOwn(algorithm, name) && algorithm[name] !== undefined;
}

function isSupportedKeyFormat(format) {
  return typeof format === "string" && ArrayPrototypeIncludes(
    [
      "jwk",
      "pkcs8",
      "raw",
      "raw-private",
      "raw-public",
      "raw-secret",
      "raw-seed",
      "spki",
    ],
    format,
  );
}

function isSecretKeyAlgorithm(algorithm) {
  return ArrayPrototypeIncludes(
    [
      "AES-CBC",
      "AES-CTR",
      "AES-GCM",
      "AES-KW",
      "AES-OCB",
      "CHACHA20-POLY1305",
      "HKDF",
      "HMAC",
      "KMAC128",
      "KMAC256",
      "PBKDF2",
    ],
    rawAlgorithmName(algorithm),
  );
}

function rsaPublicExponentValue(input) {
  let firstNonZero = 0;
  while (firstNonZero < input.length && input[firstNonZero] === 0) {
    firstNonZero++;
  }
  if (input.length - firstNonZero > 4) {
    return undefined;
  }
  let result = 0;
  for (let index = firstNonZero; index < input.length; index++) {
    result = result * 256 + input[index];
  }
  return result;
}

function isGenerateKeyMissingRequiredOption(algorithm) {
  if (algorithm === null || typeof algorithm !== "object") {
    return false;
  }
  switch (rawAlgorithmName(algorithm)) {
    case "RSASSA-PKCS1-V1_5":
    case "RSA-PSS":
    case "RSA-OAEP":
      return !hasRequiredOption(algorithm, "modulusLength") ||
        !hasRequiredOption(algorithm, "publicExponent") ||
        !hasRequiredOption(algorithm, "hash");
    case "ECDSA":
    case "ECDH":
      return !hasRequiredOption(algorithm, "namedCurve");
    case "AES-CTR":
    case "AES-CBC":
    case "AES-GCM":
    case "AES-OCB":
    case "AES-KW":
      return !hasRequiredOption(algorithm, "length");
    case "HMAC":
      return !hasRequiredOption(algorithm, "hash");
    default:
      return false;
  }
}

function isDeriveMissingRequiredOption(algorithm) {
  if (algorithm === null || typeof algorithm !== "object") {
    return false;
  }
  switch (rawAlgorithmName(algorithm)) {
    case "ECDH":
    case "X25519":
    case "X448":
      return !ObjectHasOwn(algorithm, "public");
    case "HKDF":
      return !ObjectHasOwn(algorithm, "hash") ||
        !ObjectHasOwn(algorithm, "salt") ||
        !ObjectHasOwn(algorithm, "info");
    default:
      return false;
  }
}

function isDeriveInvalidPublicOption(algorithm) {
  const name = rawAlgorithmName(algorithm);
  return algorithm !== null &&
    typeof algorithm === "object" &&
    (name === "ECDH" || name === "X25519" || name === "X448") &&
    ObjectHasOwn(algorithm, "public") &&
    !ObjectPrototypeIsPrototypeOf(CryptoKeyPrototype, algorithm.public);
}

function nodeOperationErrorMessage(methodName, args, policy) {
  if (
    methodName !== "encrypt" && methodName !== "decrypt" &&
    methodName !== "sign" && methodName !== "verify" &&
    methodName !== "wrapKey" && methodName !== "unwrapKey"
  ) {
    return undefined;
  }
  if (policy === WEB_CRYPTO_ERROR_POLICY_NODE22) {
    return methodName === "encrypt" || methodName === "decrypt"
      ? "The requested operation is not valid for the provided key"
      : `Unable to use this key to ${methodName}`;
  }

  const key = methodName === "wrapKey" || methodName === "unwrapKey"
    ? args[2]
    : args[1];
  if (ObjectPrototypeIsPrototypeOf(CryptoKeyPrototype, key)) {
    const requestedName = rawAlgorithmName(
      methodName === "wrapKey" || methodName === "unwrapKey"
        ? args[3]
        : args[0],
    );
    const keyName = rawAlgorithmName(CryptoKey.inspectSnapshot(key).algorithm);
    if (requestedName !== undefined && requestedName !== keyName) {
      return "Key algorithm mismatch";
    }
  }
  return `Unable to use this key to ${methodName}`;
}

function rsaPssHashLengthBytes(name) {
  switch (rawAlgorithmName(name)) {
    case "SHA-1":
      return 20;
    case "SHA-256":
    case "SHA3-256":
      return 32;
    case "SHA-384":
    case "SHA3-384":
      return 48;
    case "SHA-512":
    case "SHA3-512":
      return 64;
    default:
      return undefined;
  }
}

function normalizeNodeRsaPssArgs(methodName, args) {
  if (
    op_crypto_error_policy() !== WEB_CRYPTO_ERROR_POLICY_NODE24 ||
    (methodName !== "sign" && methodName !== "verify")
  ) {
    return args;
  }
  const algorithm = args[0];
  if (
    algorithm === null ||
    (typeof algorithm !== "object" && typeof algorithm !== "function")
  ) {
    return args;
  }
  const prefix = `Failed to execute '${methodName}' on 'SubtleCrypto'`;
  const name = webidl.converters.DOMString(
    algorithm.name,
    prefix,
    "Argument 1",
  );
  if (StringPrototypeToUpperCase(name) !== "RSA-PSS") {
    return args;
  }
  const saltLength = webidl.converters["unsigned long"](
    algorithm.saltLength,
    prefix,
    "'saltLength' of 'RsaPssParams'",
    { __proto__: null, enforceRange: true },
  );
  const normalized = ObjectCreate(null);
  ObjectDefineProperty(normalized, "name", {
    __proto__: null,
    value: name,
    enumerable: true,
  });
  ObjectDefineProperty(normalized, "saltLength", {
    __proto__: null,
    value: saltLength,
    enumerable: true,
  });
  return methodName === "sign"
    ? [normalized, args[1], args[2]]
    : [normalized, args[1], args[2], args[3]];
}

function nodeRsaPssSaltLengthError(methodName, args) {
  if (
    (methodName !== "sign" && methodName !== "verify") ||
    rawAlgorithmName(args[0]) !== "RSA-PSS" ||
    !CryptoKey.isKey(args[1])
  ) {
    return undefined;
  }
  const snapshot = CryptoKey.inspectSnapshot(args[1]);
  const modulusLength = snapshot.algorithm.modulusLength;
  const hashLength = rsaPssHashLengthBytes(snapshot.algorithm.hash);
  const saltLength = args[0]?.saltLength;
  if (
    typeof modulusLength !== "number" ||
    hashLength === undefined ||
    typeof saltLength !== "number"
  ) {
    return undefined;
  }
  const max = MathCeil((modulusLength - 1) / 8) - hashLength - 2;
  if (saltLength <= max) {
    return undefined;
  }
  const message =
    `The value of "algorithm.saltLength" is out of range. It must be >= 0 && <= ${max}. Received ${saltLength}`;
  const cause = new Error(message);
  tagNodeErrorCode(cause, "ERR_OUT_OF_RANGE");
  const operationError = new DOMException(message, "OperationError");
  ObjectDefineProperty(operationError, "cause", {
    __proto__: null,
    value: cause,
    configurable: true,
  });
  return operationError;
}

function decorateNodeWebCryptoError(methodName, args, error, argumentCount) {
  const policy = op_crypto_error_policy();
  if (policy === WEB_CRYPTO_ERROR_POLICY_WEB_STANDARD) {
    if (
      methodName === "importKey" &&
      error?.name === "DataError" &&
      error.message === "Invalid key type"
    ) {
      ObjectDefineProperty(error, "message", {
        __proto__: null,
        value: "unsupported algorithm",
        configurable: true,
      });
    } else if (
      methodName === "deriveBits" &&
      error?.name === "OperationError" &&
      error.message === "derived bit length is too small"
    ) {
      ObjectDefineProperty(error, "message", {
        __proto__: null,
        value: "Invalid length",
        configurable: true,
      });
    }
    return error;
  }
  if (error?.code === "ERR_INVALID_THIS") {
    return error;
  }

  const algorithm = args[0];
  const rsaPssSaltLengthError = nodeRsaPssSaltLengthError(methodName, args);
  if (rsaPssSaltLengthError !== undefined) {
    return rsaPssSaltLengthError;
  }
  if (methodName === "importKey" && args.length < 5) {
    return tagNodeErrorCode(error, "ERR_MISSING_ARGS");
  }
  if (
    methodName === "deriveBits" && error?.name === "TypeError" &&
    typeof args[2] === "number" &&
    (!NumberIsFinite(args[2]) || args[2] < 0 || args[2] > 0xffff_ffff)
  ) {
    return tagNodeErrorCode(error, "ERR_OUT_OF_RANGE");
  }
  if (methodName === "importKey" && !isSupportedKeyFormat(args[0])) {
    return tagNodeErrorCode(error, "ERR_INVALID_ARG_VALUE");
  }
  if (methodName === "deriveBits" && error?.name === "OperationError") {
    let message;
    if (args[2] === null || argumentCount < 3) {
      message = "length cannot be null";
    } else if (
      StringPrototypeIncludes(
        error.message,
        "length provided for HKDF is too large",
      )
    ) {
      message = "length exceeds the maximum derived bit length";
    } else if (
      typeof args[2] === "number" &&
      !NumberIsInteger(args[2] / 8)
    ) {
      message = "length must be a multiple of 8";
    }
    if (message !== undefined) {
      ObjectDefineProperty(error, "message", {
        __proto__: null,
        value: message,
        configurable: true,
      });
      return error;
    }
  }
  if (
    methodName === "importKey" && args[0] === "jwk" &&
    error?.name === "TypeError" &&
    (args[1] === null || typeof args[1] !== "object")
  ) {
    return new DOMException("Invalid keyData", "DataError");
  }
  if (
    methodName === "generateKey" && algorithm !== null &&
    typeof algorithm === "object" &&
    ArrayPrototypeIncludes(
      ["RSA-OAEP", "RSA-PSS", "RSASSA-PKCS1-V1_5"],
      rawAlgorithmName(algorithm),
    ) &&
    ((ObjectHasOwn(algorithm, "modulusLength") &&
      typeof algorithm.modulusLength !== "number") ||
      (ObjectHasOwn(algorithm, "publicExponent") &&
        TypedArrayPrototypeGetSymbolToStringTag(algorithm.publicExponent) !==
          "Uint8Array"))
  ) {
    return tagNodeErrorCode(error, "ERR_INVALID_ARG_TYPE");
  }
  if (methodName === "generateKey" && !ArrayIsArray(args[2])) {
    return tagNodeErrorCode(error, "ERR_INVALID_ARG_TYPE");
  }
  if (
    error?.name === "TypeError" &&
    (methodName === "importKey" ||
      (methodName === "generateKey" &&
        !isGenerateKeyMissingRequiredOption(algorithm)) ||
      (methodName === "digest" &&
        StringPrototypeIncludes(error.message, "BufferSource")))
  ) {
    return tagNodeErrorCode(error, "ERR_INVALID_ARG_TYPE");
  }
  if (
    methodName === "generateKey" &&
    isGenerateKeyMissingRequiredOption(algorithm)
  ) {
    return tagNodeErrorCode(error, "ERR_MISSING_OPTION");
  }
  if (
    methodName === "generateKey" && error?.name === "OperationError" &&
    algorithm !== null && typeof algorithm === "object" &&
    ArrayPrototypeIncludes(
      ["RSA-OAEP", "RSA-PSS", "RSASSA-PKCS1-V1_5"],
      rawAlgorithmName(algorithm),
    )
  ) {
    let message;
    if (
      typeof algorithm.modulusLength === "number" &&
      algorithm.modulusLength < 512
    ) {
      message = "algorithm.modulusLength must be at least 512";
    } else if (
      TypedArrayPrototypeGetSymbolToStringTag(algorithm.publicExponent) ===
        "Uint8Array"
    ) {
      const publicExponent = rsaPublicExponentValue(algorithm.publicExponent);
      if (publicExponent === undefined) {
        message =
          "algorithm.publicExponent must fit in an unsigned 32-bit integer";
      } else if (publicExponent < 3) {
        message = "algorithm.publicExponent must be at least 3";
      } else if (publicExponent % 2 === 0) {
        message = "algorithm.publicExponent must be odd";
      }
    }
    if (message !== undefined) {
      ObjectDefineProperty(error, "message", {
        __proto__: null,
        value: message,
        configurable: true,
      });
      return error;
    }
  }
  if (
    (methodName === "deriveBits" || methodName === "deriveKey") &&
    isDeriveMissingRequiredOption(algorithm)
  ) {
    return tagNodeErrorCode(error, "ERR_MISSING_OPTION");
  }
  if (
    (methodName === "deriveBits" || methodName === "deriveKey") &&
    isDeriveInvalidPublicOption(algorithm)
  ) {
    return tagNodeErrorCode(error, "ERR_INVALID_ARG_TYPE");
  }
  if (
    error?.name === "TypeError" &&
    StringPrototypeIncludes(error.message, "CryptoKey")
  ) {
    return tagNodeErrorCode(error, "ERR_INVALID_THIS");
  }
  if (
    (methodName === "deriveBits" || methodName === "deriveKey") &&
    error?.name === "InvalidAccessError" &&
    (error.message === "Algorithm mismatch" ||
      StringPrototypeIncludes(error.message, "Invalid algorithm name"))
  ) {
    ObjectDefineProperty(error, "message", {
      __proto__: null,
      value: StringPrototypeIncludes(error.message, "Invalid algorithm name")
        ? "Key algorithm mismatch"
        : policy === WEB_CRYPTO_ERROR_POLICY_NODE22
        ? "algorithm.public must be an ECDH key"
        : "key algorithm mismatch",
      configurable: true,
    });
    return error;
  }
  if (
    (methodName === "deriveBits" || methodName === "deriveKey") &&
    error?.name === "InvalidAccessError" &&
    StringPrototypeIncludes(error.message, "usages does not contain")
  ) {
    ObjectDefineProperty(error, "message", {
      __proto__: null,
      value: `baseKey does not have ${methodName} usage`,
      configurable: true,
    });
    return error;
  }
  if (
    (methodName === "sign" || methodName === "verify") &&
    error?.name === "NotSupportedError" &&
    StringPrototypeIncludes(error.message, "Unrecognized hash algorithm")
  ) {
    ObjectDefineProperty(error, "message", {
      __proto__: null,
      value: "Unrecognized algorithm name",
      configurable: true,
    });
    return error;
  }
  if (
    error?.name === "SyntaxError" &&
    (error.message === "Invalid key usage" ||
      error.message === "Key usage must be empty")
  ) {
    const importAlgorithmName = methodName === "importKey"
      ? rawAlgorithmName(args[2])
      : undefined;
    const message = methodName === "importKey" &&
        (args[0] === "pkcs8" || args[0] === "raw-private" ||
          args[0] === "raw-seed" ||
          (args[0] === "jwk" && args[1] !== null &&
            typeof args[1] === "object" &&
            (ObjectHasOwn(args[1], "d") || ObjectHasOwn(args[1], "priv")))) &&
        args[4]?.length === 0
      ? "Usages cannot be empty when importing a private key."
      : methodName === "importKey" && args[4]?.length === 0 &&
          (args[0] === "raw-secret" || isSecretKeyAlgorithm(args[2]))
      ? "Usages cannot be empty when importing a secret key."
      : importAlgorithmName === "HMAC"
      ? "Unsupported key usage for HMAC key"
      : importAlgorithmName === "HKDF"
      ? "Unsupported key usage for a HKDF key"
      : importAlgorithmName === "AES-CTR" ||
          importAlgorithmName === "AES-CBC" ||
          importAlgorithmName === "AES-GCM" ||
          importAlgorithmName === "AES-KW" ||
          importAlgorithmName === "AES-OCB"
      ? `Unsupported key usage for ${importAlgorithmName} key`
      : "Unsupported key usage";
    ObjectDefineProperty(error, "message", {
      __proto__: null,
      value: message,
      configurable: true,
    });
    return error;
  }
  if (
    methodName === "importKey" && rawAlgorithmName(args[2]) === "HMAC" &&
    args[2] !== null && typeof args[2] === "object" &&
    !ObjectHasOwn(args[2], "hash")
  ) {
    return tagNodeErrorCode(error, "ERR_MISSING_OPTION");
  }
  if (
    methodName === "importKey" && rawAlgorithmName(args[2]) === "HMAC" &&
    error?.name === "DataError" && error.message === "Key length is invalid"
  ) {
    ObjectDefineProperty(error, "message", {
      __proto__: null,
      value: args[2]?.length === 0
        ? "HmacImportParams.length cannot be 0"
        : "Invalid key length",
      configurable: true,
    });
    return error;
  }
  if (
    methodName === "importKey" && error?.name === "DataError" &&
    (error.message === "invalid key data" ||
      error.message === "Invalid key data")
  ) {
    ObjectDefineProperty(error, "message", {
      __proto__: null,
      value: "Invalid keyData",
      configurable: true,
    });
    return error;
  }
  if (
    methodName === "importKey" &&
    args[0] === "jwk"
  ) {
    const keyData = args[1];
    let message;
    if (StringPrototypeIncludes(error.message, "not a JsonWebKey")) {
      message = "Invalid keyData";
    } else if (
      StringPrototypeIncludes(
        error.message,
        "property of JsonWebKey is required",
      ) ||
      StringPrototypeIncludes(error.message, "'k' property") ||
      StringPrototypeIncludes(error.message, "'x' property") ||
      StringPrototypeIncludes(error.message, "'y' property")
    ) {
      message = "Invalid keyData";
    } else if (error.message === "Invalid algorithm") {
      message = keyData?.alg === undefined
        ? "Invalid keyData"
        : 'JWK "alg" Parameter and algorithm name mismatch';
    } else if (
      StringPrototypeIncludes(error.message, "'kty' property") ||
      error.message === "Invalid key type"
    ) {
      message = keyData !== null && typeof keyData === "object" &&
          ObjectHasOwn(keyData, "kty")
        ? 'Invalid JWK "kty" Parameter'
        : "Invalid keyData";
    } else if (
      StringPrototypeIncludes(error.message, "'use' property") ||
      error.message === "Invalid key use" ||
      error.message === "Invalid key usage"
    ) {
      message = 'Invalid JWK "use" Parameter';
    } else if (
      StringPrototypeIncludes(error.message, "'ext' property") ||
      error.message === "Invalid key extractability"
    ) {
      message = 'JWK "ext" Parameter and extractable mismatch';
    } else if (
      StringPrototypeIncludes(error.message, "'alg' property") ||
      StringPrototypeIncludes(error.message, "Invalid algorithm:") ||
      error.message === "Invalid JWK alg" ||
      error.message === "Mismatched curve algorithm" ||
      error.message === "Curve algorithm not supported"
    ) {
      message = 'JWK "alg" does not match the requested algorithm';
    } else if (error.message === "Invalid curve") {
      message = keyData?.crv === undefined
        ? "Invalid keyData"
        : rawAlgorithmName(args[2]) === "ECDSA" ||
            rawAlgorithmName(args[2]) === "ECDH"
        ? 'JWK "crv" does not match the requested algorithm'
        : 'JWK "crv" Parameter and algorithm name mismatch';
    } else if (StringPrototypeIncludes(error.message, "'key_ops'")) {
      message = "Key operations and usage mismatch";
    } else if (
      error.message === "Invalid public key data" ||
      error.message === "Invalid private key data" ||
      error.message === "Invalid key data"
    ) {
      message = "Invalid keyData";
    }
    if (message !== undefined) {
      ObjectDefineProperty(error, "message", {
        __proto__: null,
        value: message,
        configurable: true,
      });
      return error;
    }
  }
  if (
    methodName === "exportKey" &&
    error?.name === "InvalidAccessError" &&
    error.message === "Key is not extractable"
  ) {
    ObjectDefineProperty(error, "message", {
      __proto__: null,
      value: "key is not extractable",
      configurable: true,
    });
    return error;
  }
  if (
    (methodName === "exportKey" || methodName === "wrapKey") &&
    error?.name === "InvalidAccessError" &&
    (error.message === "Key is not a public key" ||
      error.message === "Key is not a private key") &&
    CryptoKey.isKey(args[1])
  ) {
    const snapshot = CryptoKey.inspectSnapshot(args[1]);
    return new DOMException(
      `Unable to export ${
        rawAlgorithmName(snapshot.algorithm)
      } ${snapshot.type} key using ${args[0]} format`,
      "NotSupportedError",
    );
  }
  if (
    (methodName === "encrypt" || methodName === "decrypt") &&
    error?.name === "OperationError"
  ) {
    let message;
    if (
      rawAlgorithmName(algorithm) === "CHACHA20-POLY1305" &&
      StringPrototypeIncludes(error.message, "tagLength")
    ) {
      message =
        `${algorithm.tagLength} is not a valid ChaCha20-Poly1305 tag length`;
    } else if (
      rawAlgorithmName(algorithm) === "AES-CBC" &&
      error.message === "Initialization vector must be 16 bytes"
    ) {
      message = "algorithm.iv must contain exactly 16 bytes";
    } else if (
      (rawAlgorithmName(algorithm) === "AES-GCM" ||
        rawAlgorithmName(algorithm) === "AES-OCB") &&
      (StringPrototypeIncludes(error.message, "tagLength") ||
        StringPrototypeIncludes(error.message, "tag length"))
    ) {
      message = `${algorithm.tagLength} is not a valid ${
        rawAlgorithmName(algorithm)
      } tag length`;
    }
    if (message !== undefined) {
      ObjectDefineProperty(error, "message", {
        __proto__: null,
        value: message,
        configurable: true,
      });
      return error;
    }
  }
  if (
    (methodName === "sign" || methodName === "verify") &&
    error?.name === "OperationError" &&
    error.message === "ContextParams.context must be at most 255 bytes"
  ) {
    const cause = new Error("context string must be at most 255 bytes");
    tagNodeErrorCode(cause, "ERR_OUT_OF_RANGE");
    ObjectDefineProperty(error, "cause", {
      __proto__: null,
      value: cause,
      configurable: true,
    });
    return error;
  }
  if (
    (methodName === "wrapKey" || methodName === "unwrapKey") &&
    error?.name === "InvalidAccessError" &&
    StringPrototypeIncludes(error.message, "algorithm does not match")
  ) {
    ObjectDefineProperty(error, "message", {
      __proto__: null,
      value: "Key algorithm mismatch",
      configurable: true,
    });
    return error;
  }
  if (error?.name === "InvalidAccessError") {
    const message = nodeOperationErrorMessage(methodName, args, policy);
    if (message !== undefined) {
      ObjectDefineProperty(error, "message", {
        __proto__: null,
        value: message,
        configurable: true,
      });
    }
  }
  return error;
}

function decorateNodeWebCryptoErrorSafely(
  methodName,
  args,
  error,
  argumentCount,
) {
  try {
    return decorateNodeWebCryptoError(
      methodName,
      args,
      error,
      argumentCount,
    );
  } catch {
    return error;
  }
}

function validateNodeWebCryptoCall(methodName, args) {
  if (op_crypto_error_policy() !== WEB_CRYPTO_ERROR_POLICY_NODE24) {
    return;
  }
  const rsaPssSaltLengthError = nodeRsaPssSaltLengthError(methodName, args);
  if (rsaPssSaltLengthError !== undefined) {
    throw rsaPssSaltLengthError;
  }
  if (methodName !== "deriveBits" && methodName !== "deriveKey") {
    return;
  }
  const algorithm = args[0];
  if (
    rawAlgorithmName(algorithm) !== "HKDF" ||
    algorithm === null || typeof algorithm !== "object"
  ) {
    return;
  }
  const info = algorithm?.info;
  let infoLength;
  if (isAnyArrayBuffer(info)) {
    infoLength = ArrayBufferPrototypeGetByteLength(info);
  } else if (isTypedArray(info)) {
    infoLength = TypedArrayPrototypeGetByteLength(info);
  } else if (ArrayBufferIsView(info)) {
    infoLength = DataViewPrototypeGetByteLength(info);
  }
  if (
    infoLength > 1024
  ) {
    throw new DOMException(
      "algorithm.info must be at most 1024 bytes",
      "OperationError",
    );
  }
}

function callSubtleAsPromise(
  receiver,
  cppgc,
  methodName,
  args,
  argumentCount = args.length,
  errorArgs = args,
) {
  return new Promise((resolve, reject) => {
    try {
      webidl.assertBranded(
        receiver,
        SubtleCryptoPrototype,
        "SubtleCrypto",
      );
    } catch (error) {
      reject(tagNodeErrorCode(error, "ERR_INVALID_THIS"));
      return;
    }
    let callArgs;
    try {
      callArgs = normalizeNodeRsaPssArgs(methodName, args);
    } catch (error) {
      reject(error);
      return;
    }
    const decoratedArgs = callArgs === args ? errorArgs : callArgs;
    try {
      validateNodeWebCryptoCall(methodName, decoratedArgs);
      const operation = FunctionPrototypeCall(
        cppgc,
        receiver,
        ...new SafeArrayIterator(callArgs),
      );
      if (ObjectPrototypeIsPrototypeOf(PromisePrototype, operation)) {
        // This promise is internal. Force intrinsic species construction
        // before a primordial reaction so user changes to Promise prototypes
        // cannot alter the WebCrypto return type or make this call throw
        // synchronously.
        ObjectDefineProperty(operation, "constructor", {
          __proto__: null,
          value: undefined,
          configurable: true,
        });
        PromisePrototypeThen(operation, resolve, (error) => {
          reject(decorateNodeWebCryptoErrorSafely(
            methodName,
            decoratedArgs,
            error,
            argumentCount,
          ));
        });
      } else {
        resolve(operation);
      }
    } catch (error) {
      reject(decorateNodeWebCryptoErrorSafely(
        methodName,
        decoratedArgs,
        error,
        argumentCount,
      ));
    }
  });
}

const deriveBitsForwarder = {
  deriveBits(algorithm, baseKey, length = undefined) {
    const argumentCount = arguments.length;
    const errorArgs = [algorithm, baseKey, length];
    const args = [algorithm, baseKey, length === null ? undefined : length];
    return callSubtleAsPromise(
      this,
      cppgcDeriveBits,
      "deriveBits",
      args,
      argumentCount,
      errorArgs,
    );
  },
}.deriveBits;
ObjectDefineProperty(SubtleCryptoPrototype, "deriveBits", {
  __proto__: null,
  value: deriveBitsForwarder,
  writable: true,
  enumerable: true,
  configurable: true,
});

// WebCrypto methods are ordinary functions that return Promises, not
// AsyncFunction instances. The cppgc implementations run their bodies
// synchronously, so the wrappers below put both return values and throws
// through an explicit Promise without changing the observable function kind.
function makeAsyncForwarder(name, methodName, arity) {
  const cppgc = SubtleCryptoPrototype[methodName];
  const wrapper = {
    [methodName](...args) {
      return callSubtleAsPromise(this, cppgc, methodName, args);
    },
  }[methodName];
  // `Function.length` of `(...args) => ...` is 0, but the WebIDL idl-harness
  // test (`SubtleCrypto interface: operation <name>(...)`) requires it to
  // match the operation's required-argument count per the spec.
  ObjectDefineProperty(wrapper, "length", {
    __proto__: null,
    value: arity,
    configurable: true,
  });
  ObjectDefineProperty(SubtleCryptoPrototype, name, {
    __proto__: null,
    value: wrapper,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

const cppgcSupports = SubtleCrypto.supports;
function supports(operation, algorithm, lengthOrHash = undefined) {
  if (this !== SubtleCrypto) {
    const error = new TypeError(
      'Value of "this" must be of type SubtleCrypto constructor',
    );
    tagNodeErrorCode(error, "ERR_INVALID_THIS");
    throw error;
  }
  if (arguments.length === 0) {
    return FunctionPrototypeCall(cppgcSupports, this);
  }
  if (arguments.length === 1) {
    return FunctionPrototypeCall(cppgcSupports, this, operation);
  }
  return FunctionPrototypeCall(
    cppgcSupports,
    this,
    operation,
    algorithm,
    lengthOrHash,
  );
}
ObjectDefineProperty(SubtleCrypto, "supports", {
  __proto__: null,
  value: supports,
  writable: true,
  enumerable: true,
  configurable: true,
});
// Per WebCrypto spec, every SubtleCrypto method returns a Promise. The
// op2-generated dispatchers invoke `WebIdlConverter`s synchronously before
// the async body runs, so a converter-level throw (`TypeError: Missing
// 'modulusLength'`, `Unrecognized algorithm`, etc.) reaches the call site
// as a synchronous exception. WPT's `promise_rejects_dom` wraps the call
// in `fn.call(undefined)`, which then surfaces the throw as
// `TypeError: Failed to execute 'call' on 'SubtleCrypto': ...` -- a wrong
// shape compared to the spec's "rejected promise". Forward every method
// through an explicit Promise so the throw becomes a Promise rejection.
// The third argument is the required-arg count from the WebCrypto IDL,
// applied to the wrapper's `Function.length` for idlharness compliance.
makeAsyncForwarder("digest", "digest", 2);
makeAsyncForwarder("encrypt", "encrypt", 3);
makeAsyncForwarder("decrypt", "decrypt", 3);
makeAsyncForwarder("sign", "sign", 3);
makeAsyncForwarder("verify", "verify", 4);
makeAsyncForwarder("deriveKey", "deriveKey", 5);
makeAsyncForwarder("importKey", "importKey", 5);
makeAsyncForwarder("exportKey", "exportKey", 2);
makeAsyncForwarder("generateKey", "generateKey", 3);
makeAsyncForwarder("getPublicKey", "getPublicKey", 2);
makeAsyncForwarder("wrapKey", "wrapKey", 4);
makeAsyncForwarder("unwrapKey", "unwrapKey", 7);
makeAsyncForwarder("encapsulateBits", "encapsulateBits", 2);
makeAsyncForwarder("encapsulateKey", "encapsulateKey", 5);
makeAsyncForwarder("decapsulateBits", "decapsulateBits", 3);
makeAsyncForwarder("decapsulateKey", "decapsulateKey", 6);

// `SubtleCrypto`'s prototype keeps a single privateCustomInspect helper so
// `Deno.inspect(crypto.subtle)` prints `SubtleCrypto {}` rather than the
// internal cppgc shape.
ObjectAssign(SubtleCryptoPrototype, {
  [SymbolFor("Deno.privateCustomInspect")](inspect, inspectOptions) {
    return `${this.constructor.name} ${inspect({}, inspectOptions)}`;
  },
});

webidl.configureInterface(SubtleCrypto);
applyWebIdlInterfaceShape(SubtleCrypto);

// The `SubtleCrypto` singleton (reachable as `globalThis.crypto.subtle`) is
// minted lazily: `SubtleCrypto.create()` (a static method on the cppgc
// class) allocates the cppgc-wrapped instance, because the cppgc heap
// isn't attached to the V8 isolate at snapshot-build time. The first
// runtime read of `crypto.subtle` calls `getSubtleSingleton`, which also
// stamps the `webidl.brand` symbol onto the instance so the
// `assertBranded` checks at the top of every method body pass. The same
// call hands the WebIDL brand and public CryptoKey prototype to Rust so native
// instances get the correct prototype chain without visible own properties.
let subtleSingleton;
function getSubtleSingleton() {
  if (subtleSingleton === undefined) {
    Crypto.registerSymbols(webidl.brand, CryptoKeyPrototype);
    subtleSingleton = SubtleCrypto.create();
    subtleSingleton[webidl.brand] = webidl.brand;
  }
  return subtleSingleton;
}

// `Crypto` is the cppgc-wrapped Rust class imported above. `getRandomValues`
// and the `subtle` getter are implemented natively in `crypto.rs`. The normal
// `randomUUID` path batches complete UUID strings so calls after a refill stay
// in JS; seeded runtimes use the native method to preserve exact RNG call order.
const CryptoPrototype = Crypto.prototype;
const cppgcRandomUUID = CryptoPrototype.randomUUID;
const cppgcGetRandomValues = CryptoPrototype.getRandomValues;
const cppgcSubtleGetter = ObjectGetOwnPropertyDescriptor(
  CryptoPrototype,
  "subtle",
).get;

const UUID_STRING_BYTES = 36;
const UUID_BATCH_SIZE = 128;
let uuidBatchData;
let uuidBatch = UUID_BATCH_SIZE;

function randomUUID() {
  if (this !== cryptoSingleton || usesSeededRng) {
    return FunctionPrototypeCall(cppgcRandomUUID, this);
  }
  if (uuidBatch === UUID_BATCH_SIZE) {
    uuidBatchData = op_crypto_random_uuid_batch();
    uuidBatch = 0;
  }
  const start = uuidBatch++ * UUID_STRING_BYTES;
  return StringPrototypeSlice(
    uuidBatchData,
    start,
    start + UUID_STRING_BYTES,
  );
}

function getRandomValues(typedArray) {
  webidl.assertBranded(this, CryptoPrototype, "Crypto");
  return FunctionPrototypeCall(cppgcGetRandomValues, this, typedArray);
}

function subtle() {
  webidl.assertBranded(this, CryptoPrototype, "Crypto");
  return FunctionPrototypeCall(cppgcSubtleGetter, this);
}

ObjectDefineProperty(CryptoPrototype, "randomUUID", {
  __proto__: null,
  value: randomUUID,
  writable: true,
  enumerable: true,
  configurable: true,
});
ObjectDefineProperty(CryptoPrototype, "getRandomValues", {
  __proto__: null,
  value: getRandomValues,
  writable: true,
  enumerable: true,
  configurable: true,
});
ObjectDefineProperty(CryptoPrototype, "subtle", {
  __proto__: null,
  get: subtle,
  enumerable: true,
  configurable: true,
});
ObjectDefineProperty(CryptoPrototype, SymbolFor("Deno.privateCustomInspect"), {
  __proto__: null,
  value: function (inspect, inspectOptions) {
    return inspect(
      createFilteredInspectProxy({
        object: this,
        evaluate: ObjectPrototypeIsPrototypeOf(CryptoPrototype, this),
        keys: ["subtle"],
      }),
      inspectOptions,
    );
  },
  enumerable: false,
  configurable: true,
  writable: true,
});
webidl.configureInterface(Crypto);
applyWebIdlInterfaceShape(Crypto);

let cryptoSingleton;
let usesSeededRng = false;
function getCryptoSingleton() {
  if (cryptoSingleton === undefined) {
    cryptoSingleton = Crypto.create(getSubtleSingleton());
    usesSeededRng = op_crypto_is_seeded();
    // Stamp the WebIDL brand so `Reflect.getPrototypeOf(crypto)` and
    // the IDL `Crypto interface: operation randomUUID()` invariants
    // resolve through the same brand-check path as `SubtleCrypto`.
    cryptoSingleton[webidl.brand] = webidl.brand;
  }
  return cryptoSingleton;
}

// Bridge functions for Node.js KeyObject interop -- thin trampolines onto
// the cppgc static methods declared on the `CryptoKey` class in
// `ext/crypto/crypto_key.rs` (which delegate to `node_interop.rs`).
function cryptoKeyExportNodeKeyMaterial(cryptoKey) {
  return CryptoKey.exportNodeMaterial(cryptoKey);
}

function importCryptoKeySync(format, keyData, algorithm, extractable, usages) {
  return CryptoKey.importSync(format, keyData, algorithm, extractable, usages);
}

return {
  Crypto,
  get crypto() {
    return getCryptoSingleton();
  },
  CryptoKey,
  cryptoKeyExportNodeKeyMaterial,
  importCryptoKeySync,
  SubtleCrypto,
};
})();
