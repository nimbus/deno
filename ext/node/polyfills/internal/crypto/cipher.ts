// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and Node.js contributors. All rights reserved. MIT license.

// TODO(petamoriken): enable prefer-primordials for node polyfills
// deno-lint-ignore-file prefer-primordials no-explicit-any

import { core, primordials } from "ext:core/mod.js";
const {
  encode,
} = core;
const {
  SafeSet,
  SymbolSpecies,
} = primordials;
import {
  op_node_cipheriv_encrypt,
  op_node_cipheriv_final,
  op_node_cipheriv_final_key_wrap,
  op_node_cipheriv_set_aad,
  op_node_cipheriv_take,
  op_node_create_cipheriv,
  op_node_create_decipheriv,
  op_node_decipheriv_auth_tag,
  op_node_decipheriv_decrypt,
  op_node_decipheriv_final,
  op_node_decipheriv_final_key_wrap,
  op_node_decipheriv_set_aad,
  op_node_export_secret_key,
  op_node_private_decrypt,
  op_node_private_encrypt,
  op_node_public_decrypt,
  op_node_public_encrypt,
} from "ext:core/ops";

import { Buffer } from "node:buffer";
import process from "node:process";
import type { TransformOptions } from "ext:deno_node/_stream.d.ts";
import { Transform } from "node:stream";
import {
  getArrayBufferOrView,
  KeyObject,
} from "ext:deno_node/internal/crypto/keys.ts";
import { isKeyObject } from "ext:deno_node/internal/crypto/_keys.ts";
import { kHandle } from "ext:deno_node/internal/crypto/constants.ts";
import type { BufferEncoding } from "ext:deno_node/_global.d.ts";
import type {
  BinaryLike,
  Encoding,
} from "ext:deno_node/internal/crypto/types.ts";
import {
  getCipherInfo,
  getDefaultEncoding,
} from "ext:deno_node/internal/crypto/util.ts";
import {
  ERR_CRYPTO_UNKNOWN_CIPHER,
  ERR_INVALID_ARG_VALUE,
  ERR_UNKNOWN_ENCODING,
  NodeError,
  NodeTypeError,
} from "ext:deno_node/internal/errors.ts";
import { createHash } from "ext:deno_node/internal/crypto/hash.ts";

import {
  isAnyArrayBuffer,
  isArrayBufferView,
} from "ext:deno_node/internal/util/types.ts";
import { ERR_CRYPTO_INVALID_STATE } from "ext:deno_node/internal/errors.ts";
import { StringDecoder } from "node:string_decoder";
import assert from "node:assert";
import { normalizeEncoding } from "ext:deno_node/internal/util.mjs";
import { validateString } from "ext:deno_node/internal/validators.mjs";

const FastBuffer = Buffer[SymbolSpecies];

function opensslError(
  code: string,
  reason: string,
  message: string = reason,
): NodeError {
  const err = new NodeError(code, reason);
  err.message = message;
  (err as any).reason = reason;
  return err;
}

function invalidAuthTagLengthError(length: number): NodeTypeError {
  return new NodeTypeError(
    "ERR_CRYPTO_INVALID_AUTH_TAG",
    `Invalid authentication tag length: ${length}`,
  );
}

const KEY_WRAP_CIPHERS = new SafeSet([
  "aes128-wrap",
  "aes192-wrap",
  "aes256-wrap",
  "id-aes128-wrap",
  "id-aes192-wrap",
  "id-aes256-wrap",
  "id-aes128-wrap-pad",
  "id-aes192-wrap-pad",
  "id-aes256-wrap-pad",
  "aes128-wrap-pad",
  "aes192-wrap-pad",
  "aes256-wrap-pad",
  "des3-wrap",
]);

function isKeyWrapCipher(cipher: string): boolean {
  return KEY_WRAP_CIPHERS.has(cipher);
}

const BUFFERED_AEAD_CIPHERS = new SafeSet([
  "aes-128-ccm",
  "aes-192-ccm",
  "aes-256-ccm",
  "aes-128-ocb",
  "aes-192-ocb",
  "aes-256-ocb",
]);

function isBufferedAeadCipher(cipher: string): boolean {
  return BUFFERED_AEAD_CIPHERS.has(cipher);
}

function isCcmCipher(cipher: string): boolean {
  return cipher === "aes-128-ccm" || cipher === "aes-192-ccm" ||
    cipher === "aes-256-ccm";
}

function isOcbCipher(cipher: string): boolean {
  return cipher === "aes-128-ocb" || cipher === "aes-192-ocb" ||
    cipher === "aes-256-ocb";
}

function getCcmMaxMessageSize(ivLength: number): number {
  const exponent = 8 * (15 - ivLength);
  if (exponent >= 53) {
    return Number.MAX_SAFE_INTEGER;
  }
  return (2 ** exponent) - 1;
}

export function isStringOrBuffer(
  val: unknown,
): val is string | Buffer | ArrayBuffer | ArrayBufferView {
  return typeof val === "string" ||
    isArrayBufferView(val) ||
    isAnyArrayBuffer(val) ||
    Buffer.isBuffer(val);
}

const NO_TAG = new Uint8Array();

export type CipherCCMTypes =
  | "aes-128-ccm"
  | "aes-192-ccm"
  | "aes-256-ccm"
  | "chacha20-poly1305";
export type CipherGCMTypes = "aes-128-gcm" | "aes-192-gcm" | "aes-256-gcm";
export type CipherOCBTypes = "aes-128-ocb" | "aes-192-ocb" | "aes-256-ocb";

export type CipherKey = BinaryLike | KeyObject;

export interface CipherCCMOptions extends TransformOptions {
  authTagLength: number;
}

export interface CipherGCMOptions extends TransformOptions {
  authTagLength?: number | undefined;
}

export interface CipherOCBOptions extends TransformOptions {
  authTagLength: number;
}

export interface Cipher extends ReturnType<typeof Transform> {
  update(
    data: string,
    inputEncoding?: Encoding,
    outputEncoding?: Encoding,
  ): string;

  final(outputEncoding?: BufferEncoding): string;

  setAutoPadding(autoPadding?: boolean): this;
}

export type Decipher = Cipher;

export interface CipherCCM extends Cipher {
  setAAD(
    buffer: ArrayBufferView,
    options: {
      plaintextLength: number;
    },
  ): this;
  getAuthTag(): Buffer;
}

export interface CipherGCM extends Cipher {
  setAAD(
    buffer: ArrayBufferView,
    options?: {
      plaintextLength: number;
    },
  ): this;
  getAuthTag(): Buffer;
}

export interface CipherOCB extends Cipher {
  setAAD(
    buffer: ArrayBufferView,
    options?: {
      plaintextLength: number;
    },
  ): this;
  getAuthTag(): Buffer;
}

export interface DecipherCCM extends Decipher {
  setAuthTag(buffer: ArrayBufferView): this;
  setAAD(
    buffer: ArrayBufferView,
    options: {
      plaintextLength: number;
    },
  ): this;
}

export interface DecipherGCM extends Decipher {
  setAuthTag(buffer: ArrayBufferView): this;
  setAAD(
    buffer: ArrayBufferView,
    options?: {
      plaintextLength: number;
    },
  ): this;
}

export interface DecipherOCB extends Decipher {
  setAuthTag(buffer: ArrayBufferView): this;
  setAAD(
    buffer: ArrayBufferView,
    options?: {
      plaintextLength: number;
    },
  ): this;
}

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

function deriveLegacyCipherKeyAndIv(
  cipher: string,
  password: BinaryLike,
): { key: Buffer; iv: Buffer | null } {
  validateString(cipher, "cipher");
  const cipherInfo = getCipherInfo(cipher);
  if (cipherInfo == null) {
    throw new TypeError("Unknown cipher");
  }

  const passwordBytes = Buffer.from(getArrayBufferOrView(password, "password"));
  const requiredLength = cipherInfo.keyLength + cipherInfo.ivLength;
  const digests: Buffer[] = [];
  let generatedLength = 0;
  let previous = Buffer.alloc(0);

  while (generatedLength < requiredLength) {
    const hash = createHash("md5");
    if (previous.length > 0) {
      hash.update(previous);
    }
    hash.update(passwordBytes);
    previous = hash.digest();
    digests.push(previous);
    generatedLength += previous.length;
  }

  const material = Buffer.concat(digests, generatedLength);
  return {
    key: material.subarray(0, cipherInfo.keyLength),
    iv: cipherInfo.ivLength === 0
      ? null
      : material.subarray(cipherInfo.keyLength, requiredLength),
  };
}

export function LegacyCipher(
  cipher: string,
  password: BinaryLike,
  options?: TransformOptions,
) {
  if (!(this instanceof LegacyCipher)) {
    return new LegacyCipher(cipher, password, options);
  }

  const { key, iv } = deriveLegacyCipherKeyAndIv(cipher, password);
  const instance = Cipheriv(cipher, key, iv, options);
  Object.setPrototypeOf(instance, LegacyCipher.prototype);
  return instance;
}

Object.setPrototypeOf(LegacyCipher.prototype, Cipheriv.prototype);
Object.setPrototypeOf(LegacyCipher, Cipheriv);

export function Cipheriv(
  cipher: string,
  key: CipherKey,
  iv: BinaryLike | null,
  options?: TransformOptions,
) {
  if (!(this instanceof Cipheriv)) {
    return new Cipheriv(cipher, key, iv, options);
  }

  if (getCipherInfo(cipher) == null) {
    throw new ERR_CRYPTO_UNKNOWN_CIPHER();
  }

  const cipherInfo = getCipherInfo(cipher)!;
  const ivBytes = toU8(iv);
  const authTagLength = getUIntOption(options, "authTagLength");
  if (cipherInfo.mode === "ccm" && (ivBytes.length < 7 || ivBytes.length > 13)) {
    throw new TypeError("Invalid initialization vector");
  }
  if (cipherInfo.mode === "ocb" && (ivBytes.length < 1 || ivBytes.length > 15)) {
    throw new TypeError("Invalid initialization vector");
  }
  if (
    cipher === "chacha20-poly1305" &&
    authTagLength !== -1 &&
    (authTagLength < 1 || authTagLength > 16)
  ) {
    throw invalidAuthTagLengthError(authTagLength);
  }
  if ((isCcmCipher(cipher) || isOcbCipher(cipher)) && authTagLength === -1) {
    throw new TypeError(`authTagLength required for ${cipher}`);
  }

  Transform.call(this, {
    transform(chunk, encoding, cb) {
      this.push(this.update(chunk, encoding));
      cb();
    },
    final(cb) {
      this.push(this.final());
      cb();
    },
    ...options,
  });

  this._blockSize = getBlockSize(cipher);
  this._cache = new BlockModeCache(false, this._blockSize);
  this._context = op_node_create_cipheriv(
    cipher,
    toU8(key),
    ivBytes,
    authTagLength,
  );
  this._isKeyWrapMode = isKeyWrapCipher(cipher);
  this._keyWrapDone = false;
  this._isBufferedAeadMode = isBufferedAeadCipher(cipher);
  this._isCcmMode = cipherInfo.mode === "ccm";
  this._isOcbMode = cipherInfo.mode === "ocb";
  this._ccmPlaintextLength = undefined;
  this._ccmBytesSeen = 0;
  this._ivLength = ivBytes.length;
  this._needsBlockCache =
    !(cipher == "aes-128-gcm" || cipher == "aes-256-gcm" ||
      cipher == "aes-128-ctr" || cipher == "aes-192-ctr" ||
      cipher == "aes-256-ctr" || cipher == "chacha20-poly1305");
  this._authTag = undefined;
  this._autoPadding = true;
  this._finalized = false;
  this._decoder = undefined;

  if (this._context == 0) {
    throw new ERR_CRYPTO_UNKNOWN_CIPHER();
  }
}

Object.setPrototypeOf(Cipheriv.prototype, Transform.prototype);
Object.setPrototypeOf(Cipheriv, Transform);

Cipheriv.prototype.final = function (
  encoding: string = getDefaultEncoding(),
): Buffer | string {
  if (this._finalized) {
    throw new ERR_CRYPTO_INVALID_STATE("final");
  }

  if (this._isKeyWrapMode) {
    if (this._keyWrapDone) {
      this._finalized = true;
      return encoding === "buffer" ? Buffer.alloc(0) : "";
    }
    const output = op_node_cipheriv_final_key_wrap(
      this._context,
      this._cache.cache,
    );
    this._finalized = true;
    if (encoding !== "buffer") {
      _lazyInitCipherDecoder(this, encoding);
      return this._decoder!.end(output);
    }
    return Buffer.from(output);
  }

  if (this._isBufferedAeadMode) {
    if (
      this._isCcmMode &&
      this._ccmPlaintextLength === undefined &&
      this._ccmBytesSeen === 0
    ) {
      throw opensslError(
        "ERR_OSSL_TAG_NOT_SET",
        "tag not set",
        "error:1C80007A:Provider routines::tag not set",
      );
    }
    const output = Buffer.allocUnsafe(this._cache.cache.byteLength);
    const maybeTag = op_node_cipheriv_final(
      this._context,
      false,
      this._cache.cache,
      output,
    );
    if (maybeTag) {
      this._authTag = Buffer.from(maybeTag);
    }
    this._finalized = true;
    if (encoding !== "buffer") {
      _lazyInitCipherDecoder(this, encoding);
      return this._decoder!.end(output);
    }
    return Buffer.from(output);
  }

  const bs = this._blockSize;
  const buf = new FastBuffer(bs);
  const hasNoBufferedData = this._cache.cache.byteLength === 0;
  const shouldPadEmptyBlock = this._needsBlockCache && this._autoPadding;

  if (hasNoBufferedData && !shouldPadEmptyBlock) {
    const maybeTag = op_node_cipheriv_take(this._context);
    if (maybeTag) this._authTag = Buffer.from(maybeTag);
    this._finalized = true;
    return encoding === "buffer" ? Buffer.from([]) : "";
  }

  if (!this._autoPadding && this._cache.cache.byteLength != bs) {
    throw opensslError(
      "ERR_OSSL_WRONG_FINAL_BLOCK_LENGTH",
      "wrong final block length",
      "error:1C80006B:Provider routines::wrong final block length",
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
    this._finalized = true;
    return encoding === "buffer" ? Buffer.from([]) : "";
  }

  this._finalized = true;
  if (encoding !== "buffer") {
    _lazyInitCipherDecoder(this, encoding);
    return this._decoder!.end(buf);
  }

  return buf;
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
    plaintextLength: number;
  },
) {
  if (this._finalized) {
    throw new ERR_CRYPTO_INVALID_STATE("setAAD");
  }
  let plaintextLength = -1;
  if (this._isCcmMode) {
    plaintextLength = getUIntOption(options, "plaintextLength");
    if (plaintextLength === -1) {
      throw new TypeError("options.plaintextLength required for CCM mode with AAD");
    }
    if (plaintextLength > getCcmMaxMessageSize(this._ivLength)) {
      throw new TypeError("Invalid message length");
    }
    this._ccmPlaintextLength = plaintextLength;
  }
  op_node_cipheriv_set_aad(this._context, buffer, plaintextLength);
  return this;
};

Cipheriv.prototype.setAutoPadding = function (autoPadding?: boolean) {
  this._autoPadding = !!autoPadding;
  return this;
};

Cipheriv.prototype.update = function (
  data: string | Buffer | ArrayBufferView,
  inputEncoding?: Encoding,
  outputEncoding: Encoding = getDefaultEncoding(),
): Buffer | string {
  if (this._finalized) {
    throw new ERR_CRYPTO_INVALID_STATE("update");
  }

  // TODO(kt3k): throw ERR_INVALID_ARG_TYPE if data is not string, Buffer, or ArrayBufferView
  let buf = data;
  if (typeof data === "string") {
    buf = Buffer.from(data, inputEncoding);
  }

  // Match Node.js/OpenSSL behavior: reject inputs >= INT_MAX bytes
  if (buf.length >= 2 ** 31 - 1) {
    throw new Error("Trying to add data in unsupported state");
  }

  if (this._isKeyWrapMode) {
    if (this._keyWrapDone) {
      throw new ERR_CRYPTO_INVALID_STATE("update");
    }
    _lazyInitCipherDecoder(this, outputEncoding);
    const output = Buffer.from(op_node_cipheriv_final_key_wrap(
      this._context,
      buf,
    ));
    this._keyWrapDone = true;
    if (outputEncoding !== "buffer") {
      return this._decoder!.write(output);
    }
    return output;
  }

  if (this._isBufferedAeadMode) {
    if (this._isCcmMode) {
      const nextLength = this._ccmBytesSeen + buf.length;
      if (
        nextLength > getCcmMaxMessageSize(this._ivLength) ||
        (this._ccmPlaintextLength !== undefined &&
          nextLength > this._ccmPlaintextLength)
      ) {
        throw new TypeError("Invalid message length");
      }
      this._ccmBytesSeen = nextLength;
    }
    this._cache.add(buf);
    const output = Buffer.alloc(0);
    if (outputEncoding !== "buffer") {
      return "";
    }
    return output;
  }

  _lazyInitCipherDecoder(this, outputEncoding);

  let output: Buffer;
  if (!this._needsBlockCache) {
    output = Buffer.allocUnsafe(buf.length);
    op_node_cipheriv_encrypt(this._context, buf, output);

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
    output = Buffer.allocUnsafe(input.length);
    op_node_cipheriv_encrypt(this._context, input, output);
  }

  if (outputEncoding !== "buffer") {
    return this._decoder!.write(output);
  }

  return output;
};

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

  add(data: Uint8Array) {
    const cache = this.cache;
    this.cache = new Uint8Array(cache.length + data.length);
    this.cache.set(cache);
    this.cache.set(data, cache.length);
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

    len = Math.floor(len / bs) * bs;
    const out = this.cache.subarray(0, len);
    this.cache = this.cache.subarray(len);
    return out;
  }

  set lastChunkIsNonZero(value: boolean) {
    this.#lastChunkIsNonZero = value;
  }
}

function getBlockSize(cipher: string): number {
  if (cipher.startsWith("des")) {
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

export function Decipheriv(
  cipher: string,
  key: CipherKey,
  iv: BinaryLike | null,
  options?: TransformOptions,
) {
  if (!(this instanceof Decipheriv)) {
    return new Decipheriv(cipher, key, iv, options);
  }

  if (getCipherInfo(cipher) == null) {
    throw new ERR_CRYPTO_UNKNOWN_CIPHER();
  }

  const cipherInfo = getCipherInfo(cipher)!;
  const ivBytes = toU8(iv);
  const authTagLength = getUIntOption(options, "authTagLength");
  if (cipherInfo.mode === "ccm" && (ivBytes.length < 7 || ivBytes.length > 13)) {
    throw new TypeError("Invalid initialization vector");
  }
  if (cipherInfo.mode === "ocb" && (ivBytes.length < 1 || ivBytes.length > 15)) {
    throw new TypeError("Invalid initialization vector");
  }
  if (
    cipher === "chacha20-poly1305" &&
    authTagLength !== -1 &&
    (authTagLength < 1 || authTagLength > 16)
  ) {
    throw invalidAuthTagLengthError(authTagLength);
  }
  if ((isCcmCipher(cipher) || isOcbCipher(cipher)) && authTagLength === -1) {
    throw new TypeError(`authTagLength required for ${cipher}`);
  }

  Transform.call(this, {
    transform(chunk, encoding, cb) {
      this.push(this.update(chunk, encoding));
      cb();
    },
    final(cb) {
      this.push(this.final());
      cb();
    },
    ...options,
  });

  this._autoPadding = true;
  this._blockSize = getBlockSize(cipher);
  this._cache = new BlockModeCache(this._autoPadding, this._blockSize);
  this._context = op_node_create_decipheriv(
    cipher,
    toU8(key),
    ivBytes,
    authTagLength,
  );
  this._isKeyWrapMode = isKeyWrapCipher(cipher);
  this._keyWrapDone = false;
  this._isBufferedAeadMode = isBufferedAeadCipher(cipher);
  this._isCcmMode = cipherInfo.mode === "ccm";
  this._isOcbMode = cipherInfo.mode === "ocb";
  this._ccmPlaintextLength = undefined;
  this._ccmBytesSeen = 0;
  this._ivLength = ivBytes.length;
  this._needsBlockCache =
    !(cipher == "aes-128-gcm" || cipher == "aes-256-gcm" ||
      cipher == "aes-128-ctr" || cipher == "aes-192-ctr" ||
      cipher == "aes-256-ctr" || cipher == "chacha20-poly1305");
  this._isGcmMode = cipher == "aes-128-gcm" || cipher == "aes-192-gcm" ||
    cipher == "aes-256-gcm";
  this._authTagLength = authTagLength;
  this._authTag = undefined;
  this._finalized = false;
  this._decoder = undefined;

  if (this._context == 0) {
    throw new ERR_CRYPTO_UNKNOWN_CIPHER();
  }
}

Object.setPrototypeOf(Decipheriv.prototype, Transform.prototype);
Object.setPrototypeOf(Decipheriv, Transform);

export function LegacyDecipher(
  cipher: string,
  password: BinaryLike,
  options?: TransformOptions,
) {
  if (!(this instanceof LegacyDecipher)) {
    return new LegacyDecipher(cipher, password, options);
  }

  const { key, iv } = deriveLegacyCipherKeyAndIv(cipher, password);
  const instance = Decipheriv(cipher, key, iv, options);
  Object.setPrototypeOf(instance, LegacyDecipher.prototype);
  return instance;
}

Object.setPrototypeOf(LegacyDecipher.prototype, Decipheriv.prototype);
Object.setPrototypeOf(LegacyDecipher, Decipheriv);

Decipheriv.prototype.final = function (
  encoding: string = getDefaultEncoding(),
): Buffer | string {
  if (this._finalized) {
    throw new ERR_CRYPTO_INVALID_STATE("final");
  }

  if (this._isKeyWrapMode) {
    if (this._keyWrapDone) {
      this._finalized = true;
      return encoding === "buffer" ? Buffer.alloc(0) : "";
    }
    const output = op_node_decipheriv_final_key_wrap(
      this._context,
      this._cache.cache,
    );
    this._finalized = true;
    if (encoding !== "buffer") {
      _lazyInitDecipherDecoder(this, encoding);
      return this._decoder!.end(output);
    }
    return Buffer.from(output);
  }

  if (this._isBufferedAeadMode) {
    if (!this._authTag) {
      throw new ERR_CRYPTO_INVALID_STATE("final");
    }
    const output = Buffer.allocUnsafe(this._cache.cache.byteLength);
    op_node_decipheriv_final(
      this._context,
      false,
      this._cache.cache,
      output,
      this._authTag,
    );
    this._finalized = true;
    if (encoding !== "buffer") {
      _lazyInitDecipherDecoder(this, encoding);
      return this._decoder!.end(output);
    }
    return Buffer.from(output);
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

  if (!this._needsBlockCache || this._cache.cache.byteLength === 0) {
    this._finalized = true;
    return encoding === "buffer" ? Buffer.from([]) : "";
  }
  if (this._cache.cache.byteLength != bs) {
    throw opensslError(
      "ERR_OSSL_WRONG_FINAL_BLOCK_LENGTH",
      "wrong final block length",
      "error:1C80006B:Provider routines::wrong final block length",
    );
  }

  if (this._autoPadding) {
    const padLen = buf.at(-1);
    if (padLen === 0 || padLen > bs) {
      throw opensslError(
        "ERR_OSSL_BAD_DECRYPT",
        "bad decrypt",
        "error:1C800064:Provider routines::bad decrypt",
      );
    }
    buf = buf.subarray(0, bs - padLen); // Padded in Pkcs7 mode
  }
  this._finalized = true;
  if (encoding !== "buffer") {
    _lazyInitDecipherDecoder(this, encoding);
    return this._decoder!.end(buf);
  }

  return buf;
};

Decipheriv.prototype.setAAD = function (
  buffer: ArrayBufferView,
  options?: {
    plaintextLength: number;
  },
) {
  if (this._finalized) {
    throw new ERR_CRYPTO_INVALID_STATE("setAAD");
  }
  let plaintextLength = -1;
  if (this._isCcmMode) {
    plaintextLength = getUIntOption(options, "plaintextLength");
    if (plaintextLength === -1) {
      throw new TypeError("options.plaintextLength required for CCM mode with AAD");
    }
    if (plaintextLength > getCcmMaxMessageSize(this._ivLength)) {
      throw new TypeError("Invalid message length");
    }
    this._ccmPlaintextLength = plaintextLength;
  }
  op_node_decipheriv_set_aad(this._context, buffer, plaintextLength);
  return this;
};

let gcmShortTagDeprecationEmitted = false;
const gcmShortTagDeprecationSupported =
  Number.parseInt(process.versions.node.split(".")[0], 10) >= 22;

Decipheriv.prototype.setAuthTag = function (
  buffer: BinaryLike,
  _encoding?: string,
) {
  if (this._authTag) {
    throw new ERR_CRYPTO_INVALID_STATE("setAuthTag");
  }
  // DEP0182: warn once per process when using a short GCM auth tag without
  // an explicit `authTagLength` option at decipher creation time.
  if (
    gcmShortTagDeprecationSupported &&
    this._isGcmMode && this._authTagLength === -1 &&
    buffer.byteLength !== 16 && !gcmShortTagDeprecationEmitted
  ) {
    gcmShortTagDeprecationEmitted = true;
    process.emitWarning(
      "Using AES-GCM authentication tags of less than 128 bits without " +
        "specifying the authTagLength option when initializing decryption " +
        "is deprecated.",
      "DeprecationWarning",
      "DEP0182",
    );
  }
  op_node_decipheriv_auth_tag(this._context, buffer.byteLength);
  this._authTag = buffer;
  return this;
};

Decipheriv.prototype.setAutoPadding = function (autoPadding?: boolean) {
  this._autoPadding = Boolean(autoPadding);
  this._cache.lastChunkIsNonZero = this._autoPadding;
  return this;
};

Decipheriv.prototype.update = function (
  data: string | Buffer | ArrayBufferView,
  inputEncoding?: Encoding,
  outputEncoding: Encoding = getDefaultEncoding(),
): Buffer | string {
  if (this._finalized) {
    throw new ERR_CRYPTO_INVALID_STATE("update");
  }

  // TODO(kt3k): throw ERR_INVALID_ARG_TYPE if data is not string, Buffer, or ArrayBufferView
  let buf = data;
  if (typeof data === "string") {
    buf = Buffer.from(data, inputEncoding);
  }

  // Match Node.js/OpenSSL behavior: reject inputs >= INT_MAX bytes
  if (buf.length >= 2 ** 31 - 1) {
    throw new Error("Trying to add data in unsupported state");
  }

  if (this._isKeyWrapMode) {
    if (this._keyWrapDone) {
      throw new ERR_CRYPTO_INVALID_STATE("update");
    }
    _lazyInitDecipherDecoder(this, outputEncoding);
    const output = Buffer.from(op_node_decipheriv_final_key_wrap(
      this._context,
      buf,
    ));
    this._keyWrapDone = true;

    if (outputEncoding !== "buffer") {
      return this._decoder!.write(output);
    }

    return output;
  }

  if (this._isBufferedAeadMode) {
    if (this._isCcmMode) {
      const nextLength = this._ccmBytesSeen + buf.length;
      if (
        nextLength > getCcmMaxMessageSize(this._ivLength) ||
        (this._ccmPlaintextLength !== undefined &&
          nextLength > this._ccmPlaintextLength)
      ) {
        throw new TypeError("Invalid message length");
      }
      this._ccmBytesSeen = nextLength;
    }
    this._cache.add(buf);
    const output = Buffer.alloc(0);
    if (outputEncoding !== "buffer") {
      return "";
    }
    return output;
  }

  _lazyInitDecipherDecoder(this, outputEncoding);

  let output;
  if (!this._needsBlockCache) {
    output = Buffer.allocUnsafe(buf.length);
    op_node_decipheriv_decrypt(this._context, buf, output);

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
    op_node_decipheriv_decrypt(this._context, input, output);
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

const ENCRYPT_UNSUPPORTED_KEY_TYPES = new Set([
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
  if (keyType && ENCRYPT_UNSUPPORTED_KEY_TYPES.has(keyType)) {
    throw new Error("operation not supported for this keytype");
  }
}

function normalizeOaepHash(hash: string | undefined): string | undefined {
  if (!hash) return undefined;
  // Normalize to lowercase and strip WebCrypto-style hyphens
  // (e.g. "SHA-256" -> "sha256") but keep sha3/sha512 sub-variants
  // (e.g. "sha3-256", "sha512-224") intact.
  return hash.toLowerCase().replace(/^(sha)-(?!3-)/, "$1");
}

export function privateEncrypt(
  privateKey: ArrayBufferView | string | KeyObject,
  buffer: ArrayBufferView,
): Buffer {
  checkUnsupportedKeyType(privateKey);
  const { data } = prepareKey(privateKey);
  const padding = privateKey.padding || 1;
  const oaepHash = normalizeOaepHash(privateKey.oaepHash);
  const oaepLabel = privateKey.oaepLabel || undefined;

  buffer = getArrayBufferOrView(buffer, "buffer");
  return Buffer.from(
    op_node_private_encrypt(data, buffer, padding, oaepHash, oaepLabel),
  );
}

export function privateDecrypt(
  privateKey: ArrayBufferView | string | KeyObject,
  buffer: ArrayBufferView,
): Buffer {
  checkUnsupportedKeyType(privateKey);
  const { data } = prepareKey(privateKey);
  const padding = privateKey.padding || 1;
  const oaepHash = normalizeOaepHash(privateKey.oaepHash);
  const oaepLabel = privateKey.oaepLabel || undefined;

  buffer = getArrayBufferOrView(buffer, "buffer");
  return Buffer.from(
    op_node_private_decrypt(data, buffer, padding, oaepHash, oaepLabel),
  );
}

export function publicEncrypt(
  publicKey: ArrayBufferView | string | KeyObject,
  buffer: ArrayBufferView,
): Buffer {
  checkUnsupportedKeyType(publicKey);
  const { data } = prepareKey(publicKey);
  const padding = publicKey.padding || 1;
  const oaepHash = normalizeOaepHash(publicKey.oaepHash);
  const oaepLabel = publicKey.oaepLabel || undefined;

  buffer = getArrayBufferOrView(buffer, "buffer");
  return Buffer.from(
    op_node_public_encrypt(data, buffer, padding, oaepHash, oaepLabel),
  );
}

export function prepareKey(key) {
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
    const { key: data, encoding } = key;
    if (isKeyObject(data)) {
      return prepareKey(data);
    }
    if (!isStringOrBuffer(data)) {
      throw new TypeError("Invalid key type");
    }

    return { data: getArrayBufferOrView(data, "key", encoding) };
  }

  throw new TypeError("Invalid key type");
}

export function publicDecrypt(
  publicKey: ArrayBufferView | string | KeyObject,
  buffer: ArrayBufferView,
): Buffer {
  checkUnsupportedKeyType(publicKey);
  const { data } = prepareKey(publicKey);
  const padding = publicKey.padding || 1;

  buffer = getArrayBufferOrView(buffer, "buffer");
  return Buffer.from(op_node_public_decrypt(data, buffer, padding));
}

export default {
  privateDecrypt,
  privateEncrypt,
  publicDecrypt,
  publicEncrypt,
  Cipheriv,
  Decipheriv,
  prepareKey,
};
