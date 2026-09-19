// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

// deno-lint-ignore-file no-explicit-any

(function () {
const { core, primordials } = __bootstrap;
const {
  encode,
} = core;
const {
  ArrayBufferIsView,
  Boolean,
  DataViewPrototypeGetBuffer,
  DataViewPrototypeGetByteLength,
  DataViewPrototypeGetByteOffset,
  Error,
  FunctionPrototypeCall,
  MathFloor,
  ObjectPrototypeIsPrototypeOf,
  ObjectSetPrototypeOf,
  SafeRegExp,
  SafeSet,
  SetPrototypeHas,
  StringPrototypeReplace,
  StringPrototypeStartsWith,
  StringPrototypeToLowerCase,
  SymbolSpecies,
  TypedArrayPrototypeSubarray,
  TypeError,
  TypeErrorPrototype,
  TypedArrayPrototypeAt,
  TypedArrayPrototypeGetBuffer,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeGetByteOffset,
  Uint8Array,
} = primordials;
const {
  op_node_aead_mode_create,
  op_node_aead_mode_final,
  op_node_aead_mode_set_aad,
  op_node_aead_mode_set_auth_tag,
  op_node_aead_mode_update,
  op_node_aes_unwrap_key,
  op_node_aes_wrap_check_params,
  op_node_aes_wrap_key,
  op_node_cipher_auth_tag_requires_computed,
  op_node_cipheriv_encrypt,
  op_node_cipheriv_final,
  op_node_cipheriv_set_aad,
  op_node_cipheriv_take,
  op_node_create_cipheriv,
  op_node_create_decipheriv,
  op_node_create_private_key,
  op_node_decipheriv_auth_tag,
  op_node_decipheriv_decrypt,
  op_node_decipheriv_final,
  op_node_decipheriv_set_aad,
  op_node_des3_unwrap_key,
  op_node_des3_wrap_check_params,
  op_node_des3_wrap_key,
  op_node_export_private_key_pem,
  op_node_export_secret_key,
  op_node_gcm_implicit_short_tag_allowed,
  op_node_gcm_implicit_short_tag_warns_unconditionally,
  op_node_password_cipher_key_iv,
  op_node_private_decrypt,
  op_node_private_encrypt,
  op_node_public_decrypt,
  op_node_public_encrypt,
  op_node_validate_oaep_hash,
} = core.ops;

const { Buffer } = core.loadExtScript("ext:deno_node/internal/buffer.mjs");
const { getOptionValue } = core.loadExtScript(
  "ext:deno_node/internal/options.ts",
);

const lazyStream = core.createLazyLoader("node:stream");
const lazyProcess = core.createLazyLoader("node:process");

const {
  createPrivateKey,
  createPublicKey,
  getArrayBufferOrView,
} = core.loadExtScript("ext:deno_node/internal/crypto/keys.ts");
const { isKeyObject } = core.loadExtScript(
  "ext:deno_node/internal/crypto/_keys.ts",
);
const { kHandle } = core.loadExtScript(
  "ext:deno_node/internal/crypto/constants.ts",
);
const { getCipherInfo, getDefaultEncoding } = core.loadExtScript(
  "ext:deno_node/internal/crypto/util.ts",
);
const { validateString } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);
const {
  ERR_INVALID_ARG_TYPE,
  ERR_INVALID_ARG_VALUE,
  ERR_UNKNOWN_ENCODING,
  NodeError,
} = core.loadExtScript("ext:deno_node/internal/errors.ts");

const {
  isAnyArrayBuffer,
  isArrayBufferView,
  isTypedArray,
} = core.loadExtScript("ext:deno_node/internal/util/types.ts");
const { ERR_CRYPTO_INVALID_STATE, ERR_CRYPTO_UNKNOWN_CIPHER } = core
  .loadExtScript(
    "ext:deno_node/internal/errors.ts",
  );
const { StringDecoder } = core.loadExtScript(
  "ext:deno_node/string_decoder.ts",
);
const { default: assert } = core.loadExtScript("ext:deno_node/assert.ts");
const { normalizeEncoding } = core.loadExtScript(
  "ext:deno_node/internal/util.mjs",
);

let Transform;
function getTransform() {
  if (!Transform) Transform = lazyStream().Transform;
  return Transform;
}

const FastBuffer = Buffer[SymbolSpecies];

function getArrayBufferViewParts(
  view: ArrayBufferView,
): { buffer: ArrayBufferLike; byteOffset: number; byteLength: number } {
  if (isTypedArray(view)) {
    return {
      buffer: TypedArrayPrototypeGetBuffer(view as Uint8Array),
      byteOffset: TypedArrayPrototypeGetByteOffset(view as Uint8Array),
      byteLength: TypedArrayPrototypeGetByteLength(view as Uint8Array),
    };
  }
  return {
    buffer: DataViewPrototypeGetBuffer(view as DataView),
    byteOffset: DataViewPrototypeGetByteOffset(view as DataView),
    byteLength: DataViewPrototypeGetByteLength(view as DataView),
  };
}

function getArrayBufferViewByteLength(view: ArrayBufferView): number {
  const { byteLength } = getArrayBufferViewParts(view);
  return byteLength;
}

function toFastBufferView(view: ArrayBufferView): Buffer {
  const { buffer, byteOffset, byteLength } = getArrayBufferViewParts(view);
  return new FastBuffer(buffer, byteOffset, byteLength);
}

function opensslError(code: string, reason: string): NodeError {
  const err = new NodeError(code, reason);
  (err as any).reason = reason;
  return err;
}

function isAesWrap(cipher: string): boolean {
  return cipher === "aes128-wrap" || cipher === "aes192-wrap" ||
    cipher === "aes256-wrap" || cipher === "id-aes128-wrap-pad" ||
    cipher === "id-aes192-wrap-pad" || cipher === "id-aes256-wrap-pad";
}

// Triple-DES key wrap (RFC 3217). Node.js looks up cipher names without
// regard to case (`EVP_get_cipherbyname`).
function isDes3Wrap(cipher: string): boolean {
  const name = StringPrototypeToLowerCase(cipher);
  return name === "des3-wrap" || name === "id-smime-alg-cms3deswrap";
}

// Starts a key wrap cipher (AES or Triple-DES). A key wrap cipher wraps or
// unwraps the input of each `update` call on its own.
function initKeyWrap(self, cipher: string, key, iv) {
  self._keyWrapAlgorithm = cipher;
  self._keyWrapKey = toU8(key);
  self._keyWrapIv = toU8(iv);
  if (self._isDes3Wrap) {
    op_node_des3_wrap_check_params(self._keyWrapKey, self._keyWrapIv);
  } else {
    op_node_aes_wrap_check_params(cipher, self._keyWrapKey, self._keyWrapIv);
  }
  self._context = 1; // non-zero sentinel; not used for wrap ops
}

function keyWrapUpdate(self, data: Buffer, wrap: boolean): Buffer {
  try {
    if (self._isDes3Wrap) {
      return Buffer.from(
        wrap
          ? op_node_des3_wrap_key(self._keyWrapKey, data)
          : op_node_des3_unwrap_key(self._keyWrapKey, data),
      );
    }
    const op = wrap ? op_node_aes_wrap_key : op_node_aes_unwrap_key;
    return Buffer.from(
      op(self._keyWrapAlgorithm, self._keyWrapKey, self._keyWrapIv, data),
    );
  } catch {
    // OpenSSL rejects a bad input length or a failed integrity check in
    // EVP_CipherUpdate; Node.js reports both with this error.
    throw updateStateError();
  }
}

// The CCM and OCB ciphers. Node.js looks up cipher names without regard to
// case (`EVP_get_cipherbyname`).
const AEAD_MODE_CIPHERS = new SafeSet([
  "aes-128-ccm",
  "aes-192-ccm",
  "aes-256-ccm",
  "id-aes128-ccm",
  "id-aes192-ccm",
  "id-aes256-ccm",
  "aes-128-ocb",
  "aes-192-ocb",
  "aes-256-ocb",
]);

function isAeadMode(cipher: unknown): boolean {
  return typeof cipher === "string" &&
    SetPrototypeHas(AEAD_MODE_CIPHERS, StringPrototypeToLowerCase(cipher));
}

// `CipherBase::Final` throws this when the native context is already
// released. It has no operation name, unlike the JavaScript-layer errors.
function finalInvalidStateError(): NodeError {
  return new NodeError("ERR_CRYPTO_INVALID_STATE", "Invalid state");
}

// `CipherBase::Update` reports a released context with this message.
function updateStateError(): Error {
  return new Error("Trying to add data in unsupported state");
}

function isStringOrBuffer(
  val: unknown,
): val is string | Buffer | ArrayBuffer | ArrayBufferView {
  return typeof val === "string" ||
    isArrayBufferView(val) ||
    isAnyArrayBuffer(val) ||
    Buffer.isBuffer(val);
}

// Matches Node's `ArrayBuffer.isView(data)` check in
// `lib/internal/crypto/cipher.js`: accepts string, Buffer, TypedArray
// or DataView, but rejects raw ArrayBuffer / SharedArrayBuffer.
function validateCipherUpdateData(data: unknown): void {
  if (typeof data !== "string" && !ArrayBufferIsView(data)) {
    throw new ERR_INVALID_ARG_TYPE(
      "data",
      ["string", "Buffer", "TypedArray", "DataView"],
      data,
    );
  }
}

const NO_TAG = new Uint8Array();

function toU8(
  input: string | Uint8Array | KeyObject | null,
): Uint8Array {
  if (input == null) {
    return new Uint8Array(0);
  }
  if (isKeyObject(input)) {
    return op_node_export_secret_key(input[kHandle]);
  }
  return typeof input === "string" ? encode(input) : input;
}

function Cipheriv(
  cipher: string,
  key: any,
  iv: any,
  options?: any,
) {
  if (!ObjectPrototypeIsPrototypeOf(Cipheriv.prototype, this)) {
    return new Cipheriv(cipher, key, iv, options);
  }
  initCipher(this, cipher, key, iv, options);
}

// The shared body of the `Cipheriv` and password-based `Cipher` constructors.
function initCipher(
  self: any,
  cipher: string,
  key: any,
  iv: any,
  options?: any,
) {
  const authTagLength = getUIntOption(options, "authTagLength");

  FunctionPrototypeCall(getTransform(), self, {
    transform(chunk, encoding, cb) {
      // deno-lint-ignore deno-internal/prefer-primordials -- `this` is a Transform stream
      this.push(this.update(chunk, encoding));
      cb();
    },
    final(cb) {
      // deno-lint-ignore deno-internal/prefer-primordials -- `this` is a Transform stream
      this.push(this.final());
      cb();
    },
    ...options,
  });

  self._blockSize = getBlockSize(cipher);
  self._cache = new BlockModeCache(false, self._blockSize);
  self._isDes3Wrap = isDes3Wrap(cipher);
  self._isKeyWrap = self._isDes3Wrap || isAesWrap(cipher);
  self._aeadMode = isAeadMode(cipher);

  if (self._aeadMode) {
    self._context = op_node_aead_mode_create(
      cipher,
      toU8(key),
      toU8(iv),
      authTagLength,
      true,
    );
    self._authTagLength = authTagLength;
  } else if (self._isKeyWrap) {
    initKeyWrap(self, cipher, key, iv);
  } else {
    try {
      self._context = op_node_create_cipheriv(
        cipher,
        toU8(key),
        toU8(iv),
        authTagLength,
      );
    } catch (e) {
      // The op reports an unrecognized algorithm as a TypeError that includes
      // the cipher name; surface Node's ERR_CRYPTO_UNKNOWN_CIPHER instead.
      if (
        ObjectPrototypeIsPrototypeOf(TypeErrorPrototype, e) &&
        StringPrototypeStartsWith(e.message, "Unknown cipher")
      ) {
        throw new ERR_CRYPTO_UNKNOWN_CIPHER();
      }
      throw e;
    }
    if (self._context == 0) {
      throw new ERR_CRYPTO_UNKNOWN_CIPHER();
    }
  }

  self._needsBlockCache = !self._isKeyWrap && !self._aeadMode &&
    !isStreamCipher(cipher);
  self._authTag = undefined;
  self._autoPadding = true;
  self._finalized = false;
  self._decoder = undefined;
}

ObjectSetPrototypeOf(Cipheriv.prototype, getTransform().prototype);
ObjectSetPrototypeOf(Cipheriv, getTransform());

Cipheriv.prototype.final = function (
  encoding: string = getDefaultEncoding(),
): Buffer | string {
  if (this._finalized) {
    throw finalInvalidStateError();
  }
  // Node.js releases the native cipher context on every final() call, so the
  // cipher is finalized even when final() throws.
  this._finalized = true;

  if (this._aeadMode) {
    const tag = new FastBuffer(this._authTagLength);
    let output;
    try {
      output = op_node_aead_mode_final(this._context, tag);
    } catch (e) {
      // Node.js 20 and 22 keep a zero-filled tag after a failed final.
      // Node.js 24.2 and later keep no tag, so getAuthTag() throws.
      if (!op_node_cipher_auth_tag_requires_computed()) {
        this._authTag = tag;
      }
      throw e;
    }
    this._authTag = tag;
    return finalOutput(
      this,
      encoding,
      toFastBufferView(output),
      _lazyInitCipherDecoder,
    );
  }

  if (this._isKeyWrap) {
    return finalOutput(this, encoding, Buffer.from([]), _lazyInitCipherDecoder);
  }

  const bs = this._blockSize;
  const buf = new FastBuffer(bs);
  const hasNoBufferedData =
    TypedArrayPrototypeGetByteLength(this._cache.cache) === 0;
  const shouldPadEmptyBlock = this._needsBlockCache && this._autoPadding;

  if (hasNoBufferedData && !shouldPadEmptyBlock) {
    const maybeTag = op_node_cipheriv_take(this._context);
    if (maybeTag) this._authTag = Buffer.from(maybeTag);
    return finalOutput(this, encoding, Buffer.from([]), _lazyInitCipherDecoder);
  }

  if (
    !this._autoPadding &&
    TypedArrayPrototypeGetByteLength(this._cache.cache) != bs
  ) {
    throw opensslError(
      "ERR_OSSL_EVP_WRONG_FINAL_BLOCK_LENGTH",
      "wrong final block length",
    );
  }
  const maybeTag = op_node_cipheriv_final(
    this._context,
    this._autoPadding,
    this._cache.cache,
    buf,
  );
  if (maybeTag) {
    this._authTag = Buffer.from(maybeTag);
    return finalOutput(this, encoding, Buffer.from([]), _lazyInitCipherDecoder);
  }

  return finalOutput(this, encoding, buf, _lazyInitCipherDecoder);
};

Cipheriv.prototype.getAuthTag = function (): Buffer {
  if (!this._authTag) {
    throw new ERR_CRYPTO_INVALID_STATE("getAuthTag");
  }
  return this._authTag;
};

Cipheriv.prototype.setAAD = function (
  buffer: ArrayBufferView,
  options?: {
    plaintextLength?: number;
    encoding?: string;
  },
) {
  if (this._aeadMode) {
    return aeadModeSetAAD(this, buffer, options);
  }
  if (this._finalized) {
    throw new ERR_CRYPTO_INVALID_STATE("setAAD");
  }
  op_node_cipheriv_set_aad(this._context, buffer);
  return this;
};

Cipheriv.prototype.setAutoPadding = function (autoPadding?: boolean) {
  if (this._finalized) {
    throw new ERR_CRYPTO_INVALID_STATE("setAutoPadding");
  }
  this._autoPadding = !!autoPadding;
  return this;
};

Cipheriv.prototype.update = function (
  data: string | Buffer | ArrayBufferView,
  inputEncoding?: any,
  outputEncoding: any = getDefaultEncoding(),
): Buffer | string {
  validateCipherUpdateData(data);

  if (this._finalized) {
    throw updateStateError();
  }

  let buf = data;
  if (typeof data === "string") {
    buf = Buffer.from(data, inputEncoding);
  } else {
    buf = toFastBufferView(data);
  }
  const inputByteLength = getArrayBufferViewByteLength(buf);

  // Match Node.js/OpenSSL behavior: reject inputs >= INT_MAX bytes
  if (inputByteLength >= 2 ** 31 - 1) {
    throw new Error("Trying to add data in unsupported state");
  }

  _lazyInitCipherDecoder(this, outputEncoding);

  if (this._aeadMode) {
    return aeadModeUpdate(this, buf, outputEncoding);
  }

  if (this._isKeyWrap) {
    const output = keyWrapUpdate(this, buf, true);
    if (outputEncoding !== "buffer") {
      return this._decoder!.write(output);
    }
    return output;
  }

  let output: Buffer;
  if (!this._needsBlockCache) {
    output = new FastBuffer(inputByteLength);
    if (!op_node_cipheriv_encrypt(this._context, buf, output)) {
      throw new Error("Trying to add data in unsupported state");
    }

    if (outputEncoding !== "buffer") {
      return this._decoder!.write(output);
    }

    return output;
  }

  this._cache.add(buf);
  const input = this._cache.get();

  if (input === null) {
    output = Buffer.alloc(0);
  } else {
    output = new FastBuffer(input.length);
    if (!op_node_cipheriv_encrypt(this._context, input, output)) {
      throw new Error("Trying to add data in unsupported state");
    }
  }

  if (outputEncoding !== "buffer") {
    return this._decoder!.write(output);
  }

  return output;
};

// Node.js finalizes the native cipher before it selects the output decoder
// (lib/internal/crypto/cipher.js `final`), so a final-block or authentication
// error wins over an encoding change.
function finalOutput(
  self: any,
  encoding: string,
  output: Buffer,
  initDecoder: (self: any, encoding: string) => void,
): Buffer | string {
  if (encoding === "buffer") {
    return output;
  }
  initDecoder(self, encoding);
  return self._decoder!.end(output);
}

// CCM and OCB (`CipherBase` with an OpenSSL AEAD mode). The native
// resource holds the Node.js state machine; see ext/node_crypto/aead_mode.
function aeadModeUpdate(
  self: any,
  input: Buffer,
  outputEncoding: string,
): Buffer | string {
  const output = toFastBufferView(
    op_node_aead_mode_update(self._context, input),
  );
  if (outputEncoding !== "buffer") {
    return self._decoder!.write(output);
  }
  return output;
}

function aeadModeSetAAD(
  self: any,
  buffer: ArrayBufferView | string,
  options?: { plaintextLength?: number; encoding?: string },
) {
  const plaintextLength = getUIntOption(options, "plaintextLength");
  const aad = getArrayBufferOrView(buffer, "aadbuf", options?.encoding);
  if (
    self._finalized ||
    !op_node_aead_mode_set_aad(self._context, aad, plaintextLength)
  ) {
    throw new ERR_CRYPTO_INVALID_STATE("setAAD");
  }
  return self;
}

function _lazyInitCipherDecoder(self: any, encoding: string) {
  if (encoding === "buffer") {
    return;
  }

  const normalizedEncoding = normalizeEncoding(encoding);
  self._decoder ||= new StringDecoder(normalizedEncoding);

  if (self._decoder.encoding !== normalizedEncoding) {
    if (normalizedEncoding === undefined) {
      throw new ERR_UNKNOWN_ENCODING(encoding);
    }
    assert(false, "Cannot change encoding");
  }
}

/** Caches data and output the chunk of multiple of 16.
 * Used by CBC, ECB modes of block ciphers */
class BlockModeCache {
  cache: Uint8Array;
  blockSize: number;
  // The last chunk can be padded when decrypting.
  #lastChunkIsNonZero: boolean;

  constructor(lastChunkIsNotZero = false, blockSize = 16) {
    this.cache = new Uint8Array(0);
    this.blockSize = blockSize;
    this.#lastChunkIsNonZero = lastChunkIsNotZero;
  }

  add(data: ArrayBufferView) {
    const { buffer, byteOffset, byteLength } = getArrayBufferViewParts(data);
    const cache = this.cache;
    this.cache = new Uint8Array(cache.length + byteLength);
    this.cache.set(cache);
    this.cache.set(
      new Uint8Array(buffer, byteOffset, byteLength),
      cache.length,
    );
  }

  /** Gets the chunk of the length of largest multiple of blockSize.
   * Used for preparing data for encryption/decryption */
  get(): Uint8Array | null {
    const bs = this.blockSize;
    let len = this.cache.length;
    if (this.#lastChunkIsNonZero) {
      // Reduces the available chunk length by 1 to keep the last chunk
      len -= 1;
    }
    if (len < bs) {
      return null;
    }

    len = MathFloor(len / bs) * bs;
    const out = this.cache.subarray(0, len);
    this.cache = this.cache.subarray(len);
    return out;
  }

  set lastChunkIsNonZero(value: boolean) {
    this.#lastChunkIsNonZero = value;
  }
}

// Ciphers whose update output has the same length as its input.
function isStreamCipher(cipher: string): boolean {
  return cipher == "aes-128-gcm" || cipher == "aes-192-gcm" ||
    cipher == "aes-256-gcm" || cipher == "aes-128-ctr" ||
    cipher == "aes-192-ctr" || cipher == "aes-256-ctr" ||
    cipher == "chacha20" || cipher == "chacha20-poly1305";
}

function getBlockSize(cipher: string): number {
  if (StringPrototypeStartsWith(cipher, "des")) {
    return 8;
  }
  return 16;
}

function getUIntOption(options, key) {
  let value;
  if (options && (value = options[key]) != null) {
    if (value >>> 0 !== value) {
      throw new ERR_INVALID_ARG_VALUE(`options.${key}`, value);
    }
    return value;
  }
  return -1;
}

function Decipheriv(
  cipher: string,
  key: any,
  iv: any,
  options?: any,
) {
  if (!ObjectPrototypeIsPrototypeOf(Decipheriv.prototype, this)) {
    return new Decipheriv(cipher, key, iv, options);
  }
  initDecipher(this, cipher, key, iv, options);
}

// The shared body of the `Decipheriv` and password-based `Decipher`
// constructors.
function initDecipher(
  self: any,
  cipher: string,
  key: any,
  iv: any,
  options?: any,
) {
  const authTagLength = getUIntOption(options, "authTagLength");

  FunctionPrototypeCall(getTransform(), self, {
    transform(chunk, encoding, cb) {
      // deno-lint-ignore deno-internal/prefer-primordials -- `this` is a Transform stream
      this.push(this.update(chunk, encoding));
      cb();
    },
    final(cb) {
      // deno-lint-ignore deno-internal/prefer-primordials -- `this` is a Transform stream
      this.push(this.final());
      cb();
    },
    ...options,
  });

  self._autoPadding = true;
  self._blockSize = getBlockSize(cipher);
  self._cache = new BlockModeCache(self._autoPadding, self._blockSize);
  self._isDes3Wrap = isDes3Wrap(cipher);
  self._isKeyWrap = self._isDes3Wrap || isAesWrap(cipher);
  self._aeadMode = isAeadMode(cipher);

  if (self._aeadMode) {
    self._context = op_node_aead_mode_create(
      cipher,
      toU8(key),
      toU8(iv),
      authTagLength,
      false,
    );
  } else if (self._isKeyWrap) {
    initKeyWrap(self, cipher, key, iv);
  } else {
    try {
      self._context = op_node_create_decipheriv(
        cipher,
        toU8(key),
        toU8(iv),
        authTagLength,
      );
    } catch (e) {
      // The op reports an unrecognized algorithm as a TypeError that includes
      // the cipher name; surface Node's ERR_CRYPTO_UNKNOWN_CIPHER instead.
      if (
        ObjectPrototypeIsPrototypeOf(TypeErrorPrototype, e) &&
        StringPrototypeStartsWith(e.message, "Unknown cipher")
      ) {
        throw new ERR_CRYPTO_UNKNOWN_CIPHER();
      }
      throw e;
    }
    if (self._context == 0) {
      throw new ERR_CRYPTO_UNKNOWN_CIPHER();
    }
  }

  self._needsBlockCache = !self._isKeyWrap && !self._aeadMode &&
    !isStreamCipher(cipher);
  self._isGcmMode = cipher == "aes-128-gcm" || cipher == "aes-192-gcm" ||
    cipher == "aes-256-gcm";
  self._authTagLength = authTagLength;
  self._authTag = undefined;
  self._finalized = false;
  self._decoder = undefined;
}

ObjectSetPrototypeOf(Decipheriv.prototype, getTransform().prototype);
ObjectSetPrototypeOf(Decipheriv, getTransform());

Decipheriv.prototype.final = function (
  encoding: string = getDefaultEncoding(),
): Buffer | string {
  if (this._finalized) {
    throw finalInvalidStateError();
  }
  // Node.js releases the native cipher context on every final() call, so the
  // cipher is finalized even when final() throws.
  this._finalized = true;

  if (this._aeadMode) {
    return finalOutput(
      this,
      encoding,
      toFastBufferView(op_node_aead_mode_final(this._context, NO_TAG)),
      _lazyInitDecipherDecoder,
    );
  }

  if (this._isKeyWrap) {
    return finalOutput(
      this,
      encoding,
      Buffer.from([]),
      _lazyInitDecipherDecoder,
    );
  }

  const bs = this._blockSize;
  let buf = new FastBuffer(bs);
  op_node_decipheriv_final(
    this._context,
    this._autoPadding,
    this._cache.cache,
    buf,
    this._authTag || NO_TAG,
  );

  if (
    !this._needsBlockCache ||
    TypedArrayPrototypeGetByteLength(this._cache.cache) === 0
  ) {
    return finalOutput(
      this,
      encoding,
      Buffer.from([]),
      _lazyInitDecipherDecoder,
    );
  }
  if (TypedArrayPrototypeGetByteLength(this._cache.cache) != bs) {
    throw opensslError(
      "ERR_OSSL_EVP_WRONG_FINAL_BLOCK_LENGTH",
      "wrong final block length",
    );
  }

  if (this._autoPadding) {
    const padLen = TypedArrayPrototypeAt(buf, -1);
    if (padLen === 0 || padLen > bs) {
      throw opensslError(
        "ERR_OSSL_EVP_BAD_DECRYPT",
        "bad decrypt",
      );
    }
    buf = buf.subarray(0, bs - padLen); // Padded in Pkcs7 mode
  }
  return finalOutput(this, encoding, buf, _lazyInitDecipherDecoder);
};

Decipheriv.prototype.setAAD = function (
  buffer: ArrayBufferView,
  options?: {
    plaintextLength?: number;
    encoding?: string;
  },
) {
  if (this._aeadMode) {
    return aeadModeSetAAD(this, buffer, options);
  }
  if (this._finalized) {
    throw new ERR_CRYPTO_INVALID_STATE("setAAD");
  }
  op_node_decipheriv_set_aad(this._context, buffer);
  return this;
};

let gcmShortTagDeprecationEmitted = false;

Decipheriv.prototype.setAuthTag = function (
  buffer: any,
  encoding?: string,
) {
  if (this._aeadMode) {
    const tag = getArrayBufferOrView(buffer, "buffer", encoding);
    if (
      this._finalized || !op_node_aead_mode_set_auth_tag(this._context, tag)
    ) {
      throw new ERR_CRYPTO_INVALID_STATE("setAuthTag");
    }
    return this;
  }
  if (this._finalized || this._authTag) {
    throw new ERR_CRYPTO_INVALID_STATE("setAuthTag");
  }
  // deno-lint-ignore deno-internal/prefer-primordials -- `buffer` may be Buffer/TypedArray/DataView
  const tagByteLength = buffer.byteLength;
  let emitImplicitShortTagDeprecation = false;
  if (
    this._isGcmMode && this._authTagLength === -1 &&
    tagByteLength !== 16
  ) {
    if (!op_node_gcm_implicit_short_tag_allowed()) {
      throw new TypeError(
        `Invalid authentication tag length: ${tagByteLength}`,
      );
    }
    emitImplicitShortTagDeprecation =
      op_node_gcm_implicit_short_tag_warns_unconditionally() ||
      getOptionValue("--pending-deprecation") === true;
  }
  // deno-lint-ignore deno-internal/prefer-primordials -- `buffer` may be Buffer/TypedArray/DataView
  op_node_decipheriv_auth_tag(this._context, buffer.byteLength);
  if (emitImplicitShortTagDeprecation && !gcmShortTagDeprecationEmitted) {
    gcmShortTagDeprecationEmitted = true;
    lazyProcess().default.emitWarning(
      "Using AES-GCM authentication tags of less than 128 bits without " +
        "specifying the authTagLength option when initializing decryption " +
        "is deprecated.",
      "DeprecationWarning",
      "DEP0182",
    );
  }
  this._authTag = buffer;
  return this;
};

Decipheriv.prototype.setAutoPadding = function (autoPadding?: boolean) {
  if (this._finalized) {
    throw new ERR_CRYPTO_INVALID_STATE("setAutoPadding");
  }
  this._autoPadding = Boolean(autoPadding);
  this._cache.lastChunkIsNonZero = this._autoPadding;
  return this;
};

Decipheriv.prototype.update = function (
  data: string | Buffer | ArrayBufferView,
  inputEncoding?: any,
  outputEncoding: any = getDefaultEncoding(),
): Buffer | string {
  validateCipherUpdateData(data);

  if (this._finalized) {
    throw updateStateError();
  }

  let buf = data;
  if (typeof data === "string") {
    buf = Buffer.from(data, inputEncoding);
  } else {
    buf = toFastBufferView(data);
  }
  const inputByteLength = getArrayBufferViewByteLength(buf);

  // Match Node.js/OpenSSL behavior: reject inputs >= INT_MAX bytes
  if (inputByteLength >= 2 ** 31 - 1) {
    throw new Error("Trying to add data in unsupported state");
  }

  _lazyInitDecipherDecoder(this, outputEncoding);

  if (this._aeadMode) {
    return aeadModeUpdate(this, buf, outputEncoding);
  }

  if (this._isKeyWrap) {
    const output = keyWrapUpdate(this, buf, false);
    if (outputEncoding !== "buffer") {
      return this._decoder!.write(output);
    }
    return output;
  }

  let output;
  if (!this._needsBlockCache) {
    output = new FastBuffer(inputByteLength);
    if (!op_node_decipheriv_decrypt(this._context, buf, output)) {
      throw new Error("Trying to add data in unsupported state");
    }

    if (outputEncoding !== "buffer") {
      return this._decoder!.write(output);
    }

    return output;
  }

  this._cache.add(buf);
  const input = this._cache.get();
  if (input === null) {
    output = Buffer.alloc(0);
  } else {
    output = new FastBuffer(input.length);
    if (!op_node_decipheriv_decrypt(this._context, input, output)) {
      throw new Error("Trying to add data in unsupported state");
    }
  }

  if (outputEncoding !== "buffer") {
    return this._decoder!.write(output);
  }

  return output;
};

function _lazyInitDecipherDecoder(self: any, encoding: string) {
  if (encoding === "buffer") {
    return;
  }

  const normalizedEncoding = normalizeEncoding(encoding);
  self._decoder ||= new StringDecoder(normalizedEncoding);

  if (self._decoder.encoding !== normalizedEncoding) {
    if (normalizedEncoding === undefined) {
      throw new ERR_UNKNOWN_ENCODING(encoding);
    }
    assert(false, "Cannot change encoding");
  }
}

const ENCRYPT_UNSUPPORTED_KEY_TYPES = new SafeSet([
  "rsa-pss",
  "dsa",
  "ec",
  "ed25519",
  "ed448",
  "x25519",
  "x448",
]);

function checkUnsupportedKeyType(key) {
  const keyType = isKeyObject(key)
    ? key.asymmetricKeyType
    : key?.key?.asymmetricKeyType;
  if (keyType && SetPrototypeHas(ENCRYPT_UNSUPPORTED_KEY_TYPES, keyType)) {
    throw new Error("operation not supported for this keytype");
  }
}

const WEBCRYPTO_SHA_HYPHEN_RE = new SafeRegExp("^(sha)-(?!3-)");

function normalizeOaepHash(hash: unknown): string | undefined {
  if (hash === undefined) return undefined;
  if (typeof hash !== "string") {
    throw new ERR_INVALID_ARG_TYPE("oaepHash", "string", hash);
  }
  if (!hash) return undefined;
  // Normalize to lowercase and strip WebCrypto-style hyphens
  // (e.g. "SHA-256" -> "sha256") but keep sha3/sha512 sub-variants
  // (e.g. "sha3-256", "sha512-224") intact.
  const normalized = StringPrototypeReplace(
    StringPrototypeToLowerCase(hash),
    WEBCRYPTO_SHA_HYPHEN_RE,
    "$1",
  );
  // Validate before key parsing so unknown hash throws ERR_OSSL_EVP_INVALID_DIGEST
  // even when the key itself cannot be parsed as a private key.
  op_node_validate_oaep_hash(normalized);
  return normalized;
}

function bufferEncodingFrom(keyOptions: unknown): string | undefined {
  return (keyOptions as { encoding?: string } | null)?.encoding;
}

function validateOaepLabel(
  label: unknown,
): ArrayBufferView | ArrayBuffer | undefined {
  if (label === undefined) return undefined;
  if (!isArrayBufferView(label) && !isAnyArrayBuffer(label)) {
    throw new ERR_INVALID_ARG_TYPE(
      "oaepLabel",
      ["Buffer", "TypedArray", "DataView"],
      label,
    );
  }
  return label as ArrayBufferView | ArrayBuffer;
}

function privateEncrypt(
  privateKey: ArrayBufferView | string | KeyObject,
  buffer: ArrayBufferView,
): Buffer {
  checkUnsupportedKeyType(privateKey);
  const { data } = prepareKey(privateKey);
  const padding = privateKey.padding || 1;
  const oaepHash = normalizeOaepHash(privateKey.oaepHash);
  const oaepLabel = validateOaepLabel(privateKey.oaepLabel);

  buffer = getArrayBufferOrView(
    buffer,
    "buffer",
    bufferEncodingFrom(privateKey),
  );
  return Buffer.from(
    op_node_private_encrypt(data, buffer, padding, oaepHash, oaepLabel),
  );
}

function privateDecrypt(
  privateKey: ArrayBufferView | string | KeyObject,
  buffer: ArrayBufferView,
): Buffer {
  checkUnsupportedKeyType(privateKey);
  const { data } = prepareKey(privateKey);
  // Node.js defaults privateDecrypt to RSA_PKCS1_OAEP_PADDING (4)
  const padding = privateKey.padding || 4;
  const oaepHash = normalizeOaepHash(privateKey.oaepHash);
  const oaepLabel = validateOaepLabel(privateKey.oaepLabel);

  buffer = getArrayBufferOrView(
    buffer,
    "buffer",
    bufferEncodingFrom(privateKey),
  );
  return Buffer.from(
    op_node_private_decrypt(data, buffer, padding, oaepHash, oaepLabel),
  );
}

function publicEncrypt(
  publicKey: ArrayBufferView | string | KeyObject,
  buffer: ArrayBufferView,
): Buffer {
  checkUnsupportedKeyType(publicKey);
  const { data } = prepareKey(publicKey);
  // Node.js defaults publicEncrypt to RSA_PKCS1_OAEP_PADDING (4)
  const padding = publicKey.padding || 4;
  const oaepHash = normalizeOaepHash(publicKey.oaepHash);
  const oaepLabel = validateOaepLabel(publicKey.oaepLabel);

  buffer = getArrayBufferOrView(
    buffer,
    "buffer",
    bufferEncodingFrom(publicKey),
  );
  return Buffer.from(
    op_node_public_encrypt(data, buffer, padding, oaepHash, oaepLabel),
  );
}

function prepareKey(key) {
  // TODO(@littledivy): handle these cases
  // - web CryptoKey
  if (isStringOrBuffer(key)) {
    return { data: getArrayBufferOrView(key, "key") };
  } else if (isKeyObject(key) && key.type === "public") {
    const data = key.export({ type: "spki", format: "pem" });
    return { data: getArrayBufferOrView(data, "key") };
  } else if (isKeyObject(key) && key.type === "private") {
    const data = key.export({ type: "pkcs8", format: "pem" });
    return { data: getArrayBufferOrView(data, "key") };
  } else if (typeof key == "object") {
    const { key: data, encoding, passphrase, format, type } = key;
    if (isKeyObject(data)) {
      return prepareKey(data);
    }
    if (format === "jwk") {
      // Build a KeyObject from the JWK and export it as PEM so the
      // downstream op can consume it via the existing PEM parsing path.
      const isPrivate = typeof data === "object" && data !== null &&
        typeof (data as { d?: unknown }).d === "string";
      const keyObject = isPrivate
        ? createPrivateKey({ key: data, format: "jwk" })
        : createPublicKey({ key: data, format: "jwk" });
      return prepareKey(keyObject);
    }
    if (!isStringOrBuffer(data)) {
      throw new TypeError("Invalid key type");
    }

    // If a passphrase is supplied with raw key material, decrypt the key via
    // the native key handle and re-export as unencrypted PKCS#8 PEM so the
    // downstream RSA ops can parse it.
    if (passphrase != null) {
      const keyFormat = format ?? (typeof data === "string" ? "pem" : "der");
      const keyData = getArrayBufferOrView(data, "key", encoding);
      const passphraseData = getArrayBufferOrView(passphrase, "passphrase");
      const handle = op_node_create_private_key(
        keyData,
        keyFormat,
        type ?? "",
        passphraseData,
      );
      const pem = op_node_export_private_key_pem(
        handle,
        "pkcs8",
        null,
        null,
      );
      return { data: getArrayBufferOrView(pem, "key") };
    }

    return { data: getArrayBufferOrView(data, "key", encoding) };
  }

  throw new TypeError("Invalid key type");
}

function publicDecrypt(
  publicKey: ArrayBufferView | string | KeyObject,
  buffer: ArrayBufferView,
): Buffer {
  checkUnsupportedKeyType(publicKey);
  const { data } = prepareKey(publicKey);
  const padding = publicKey.padding || 1;

  buffer = getArrayBufferOrView(
    buffer,
    "buffer",
    bufferEncodingFrom(publicKey),
  );
  return Buffer.from(op_node_public_decrypt(data, buffer, padding));
}

// The password-based `Cipher` and `Decipher` of Node.js 20 (DEP0106). Node.js
// 22 removed them; `crypto.ts` exposes them only on lanes that keep the API.
//
// Node.js 20 `createCipher()` validates the cipher name, the password and the
// `authTagLength` option in that order. `CipherBase::Init` then derives the key
// and IV with `EVP_BytesToKey(cipher, EVP_md5(), nullptr, password, 1)`, and
// warns before `CommonInit` when a Cipher uses a counter mode.
function deriveLegacyKeyAndIv(
  cipher: unknown,
  password: unknown,
  options: unknown,
  isEncrypt: boolean,
): { key: Uint8Array; iv: Uint8Array } {
  validateString(cipher, "cipher");
  const passwordBytes = getArrayBufferOrView(password, "password");
  getUIntOption(options, "authTagLength");

  const info = getCipherInfo(cipher);
  if (info === undefined) {
    throw new ERR_CRYPTO_UNKNOWN_CIPHER();
  }
  const ivLength = info.ivLength ?? 0;
  const keyAndIv = op_node_password_cipher_key_iv(
    toFastBufferView(passwordBytes),
    info.keyLength,
    ivLength,
  );

  if (
    isEncrypt &&
    (info.mode === "ctr" || info.mode === "gcm" || info.mode === "ccm")
  ) {
    lazyProcess().default.emitWarning(
      `Use Cipheriv for counter mode of ${cipher}`,
    );
  }

  return {
    key: TypedArrayPrototypeSubarray(keyAndIv, 0, info.keyLength),
    iv: TypedArrayPrototypeSubarray(
      keyAndIv,
      info.keyLength,
      info.keyLength + ivLength,
    ),
  };
}

function Cipher(cipher: string, password: any, options?: any) {
  if (!ObjectPrototypeIsPrototypeOf(Cipher.prototype, this)) {
    return new Cipher(cipher, password, options);
  }
  const { key, iv } = deriveLegacyKeyAndIv(cipher, password, options, true);
  initCipher(this, cipher, key, iv, options);
}

ObjectSetPrototypeOf(Cipher.prototype, getTransform().prototype);
ObjectSetPrototypeOf(Cipher, getTransform());
Cipher.prototype.update = Cipheriv.prototype.update;
Cipher.prototype.final = Cipheriv.prototype.final;
Cipher.prototype.setAutoPadding = Cipheriv.prototype.setAutoPadding;
Cipher.prototype.getAuthTag = Cipheriv.prototype.getAuthTag;
Cipher.prototype.setAAD = Cipheriv.prototype.setAAD;

function Decipher(cipher: string, password: any, options?: any) {
  if (!ObjectPrototypeIsPrototypeOf(Decipher.prototype, this)) {
    return new Decipher(cipher, password, options);
  }
  const { key, iv } = deriveLegacyKeyAndIv(cipher, password, options, false);
  initDecipher(this, cipher, key, iv, options);
}

ObjectSetPrototypeOf(Decipher.prototype, getTransform().prototype);
ObjectSetPrototypeOf(Decipher, getTransform());
Decipher.prototype.update = Decipheriv.prototype.update;
Decipher.prototype.final = Decipheriv.prototype.final;
Decipher.prototype.setAutoPadding = Decipheriv.prototype.setAutoPadding;
Decipher.prototype.setAuthTag = Decipheriv.prototype.setAuthTag;
Decipher.prototype.setAAD = Decipheriv.prototype.setAAD;

return {
  isStringOrBuffer,
  Cipher,
  Cipheriv,
  Decipher,
  Decipheriv,
  privateEncrypt,
  privateDecrypt,
  publicEncrypt,
  publicDecrypt,
  prepareKey,
  default: {
    privateDecrypt,
    privateEncrypt,
    publicDecrypt,
    publicEncrypt,
    Cipheriv,
    Decipheriv,
    prepareKey,
  },
};
})();
