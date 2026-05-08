// Copyright 2018-2026 the Deno authors. MIT license.
/*
MIT License

Copyright (c) 2018 cryptocoinjs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// TODO(petamoriken): enable prefer-primordials for node polyfills
// deno-lint-ignore-file prefer-primordials

import { Buffer } from "node:buffer";
import { HASH_DATA } from "ext:deno_node/internal/crypto/types.ts";
import { op_node_scrypt_async, op_node_scrypt_sync } from "ext:core/ops";
import {
  validateFunction,
  validateInt32,
  validateInteger,
  validateUint32,
} from "ext:deno_node/internal/validators.mjs";
import { ERR_CRYPTO_SCRYPT_INVALID_PARAMETER } from "ext:deno_node/internal/errors.ts";
import { getArrayBufferOrView } from "ext:deno_node/internal/crypto/keys.ts";

type Opts = Partial<{
  N: number;
  cost: number;
  p: number;
  parallelization: number;
  r: number;
  blockSize: number;
  maxmem: number;
}>;

function invalidScryptParamsMemoryLimitError() {
  const error = new Error("Invalid scrypt params: memory limit exceeded");
  (error as Error & { code: string }).code = "ERR_CRYPTO_INVALID_SCRYPT_PARAMS";
  return error;
}

function exceedsScryptMemoryLimit(
  N: number,
  r: number,
  p: number,
  maxmem: number,
) {
  if (N >= 2 ** (r * 16)) {
    return true;
  }
  if (p > (2 ** 30 - 1) / r) {
    return true;
  }
  return (128 * N * r) + (128 * r * p) > maxmem;
}

export function scryptSync(
  password: HASH_DATA,
  salt: HASH_DATA,
  keylen: number,
  _opts?: Opts,
): Buffer {
  const options = check(password, salt, keylen, _opts);
  const { N, r, p, maxmem } = options;
  if (keylen === 0) {
    return Buffer.alloc(0);
  }
  if (exceedsScryptMemoryLimit(N, r, p, maxmem)) {
    throw invalidScryptParamsMemoryLimitError();
  }

  const buf = Buffer.alloc(keylen);
  try {
    op_node_scrypt_sync(
      password,
      salt,
      keylen,
      Math.log2(N),
      r,
      p,
      Math.min(maxmem, 0xffffffff),
      buf.buffer,
    );
  } catch {
    throw new ERR_CRYPTO_SCRYPT_INVALID_PARAMETER();
  }

  return buf;
}

type Callback = (err: unknown, result?: Buffer) => void;

export function scrypt(
  password: HASH_DATA,
  salt: HASH_DATA,
  keylen: number,
  _opts: Opts | null | Callback,
  cb?: Callback,
) {
  if (!cb) {
    cb = _opts as Callback;
    _opts = null;
  }
  const options = check(password, salt, keylen, _opts);
  const { N, r, p, maxmem } = options;

  validateFunction(cb, "callback");
  if (keylen === 0) {
    cb(null, Buffer.alloc(0));
    return;
  }

  if (exceedsScryptMemoryLimit(N, r, p, maxmem)) {
    throw invalidScryptParamsMemoryLimitError();
  }

  op_node_scrypt_async(
    password,
    salt,
    keylen,
    Math.log2(N),
    r,
    p,
    Math.min(maxmem, 0xffffffff),
  ).then(
    (buf: Uint8Array) => {
      cb(null, Buffer.from(buf.buffer));
    },
  ).catch(() => cb(new ERR_CRYPTO_SCRYPT_INVALID_PARAMETER()));
}

const defaults = {
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 32 << 20, // 32 MiB, matches SCRYPT_MAX_MEM.
};

function check(password, salt, keylen, options) {
  password = getArrayBufferOrView(password, "password");
  salt = getArrayBufferOrView(salt, "salt");
  validateInt32(keylen, "keylen", 0);

  let { N, r, p, maxmem } = defaults;
  if (options && options !== defaults) {
    const hasN = options.N !== undefined;
    if (hasN) {
      N = options.N;
      validateUint32(N, "N");
    }
    if (options.cost !== undefined) {
      if (hasN) throw new ERR_CRYPTO_SCRYPT_INVALID_PARAMETER();
      N = options.cost;
      validateUint32(N, "cost");
    }
    const hasR = options.r !== undefined;
    if (hasR) {
      r = options.r;
      validateUint32(r, "r");
    }
    if (options.blockSize !== undefined) {
      if (hasR) throw new ERR_CRYPTO_SCRYPT_INVALID_PARAMETER();
      r = options.blockSize;
      validateUint32(r, "blockSize");
    }
    const hasP = options.p !== undefined;
    if (hasP) {
      p = options.p;
      validateUint32(p, "p");
    }
    if (options.parallelization !== undefined) {
      if (hasP) throw new ERR_CRYPTO_SCRYPT_INVALID_PARAMETER();
      p = options.parallelization;
      validateUint32(p, "parallelization");
    }
    if (options.maxmem !== undefined) {
      maxmem = options.maxmem;
      validateInteger(maxmem, "maxmem", 0);
    }
    if (N === 0) N = defaults.N;
    if (r === 0) r = defaults.r;
    if (p === 0) p = defaults.p;
    if (maxmem === 0) maxmem = defaults.maxmem;
  }

  if (N < 2 || (N & (N - 1)) !== 0) {
    throw new ERR_CRYPTO_SCRYPT_INVALID_PARAMETER();
  }

  return { password, salt, keylen, N, r, p, maxmem };
}

export default {
  scrypt,
  scryptSync,
};
