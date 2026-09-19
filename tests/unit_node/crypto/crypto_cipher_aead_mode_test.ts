// Copyright 2018-2026 the Deno authors. MIT license.

// AES-CCM and AES-OCB. The expected values come from Node.js v20.20.2
// (OpenSSL 3.0).

import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import { assertEquals, assertStrictEquals } from "@std/assert";

const key16 = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
const key32 = Buffer.from(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "hex",
);
const ccmIv = Buffer.from("101112131415161718191a1b", "hex");
const ccmCiphertext = "4bd0d5cc2dd45add78c01b";
const ccmTag = "dba1924a430fde53bdc35dbeebd27f56";

// Returns the error that `fn` throws, in the shape that the Node.js
// reference probe recorded.
function thrown(fn: () => unknown) {
  try {
    fn();
  } catch (e) {
    const err = e as Error & { code?: string };
    return { name: err.name, code: err.code, message: err.message };
  }
  throw new Error("expected an error");
}

Deno.test("aes-128-ccm encrypts and decrypts with AAD", () => {
  const cipher = crypto.createCipheriv("aes-128-ccm", key16, ccmIv, {
    authTagLength: 16,
  });
  cipher.setAAD(Buffer.from("additional"), { plaintextLength: 11 });
  const ciphertext = Buffer.concat([
    cipher.update("hello world"),
    cipher.final(),
  ]);
  assertEquals(ciphertext.toString("hex"), ccmCiphertext);
  assertEquals(cipher.getAuthTag().toString("hex"), ccmTag);

  const decipher = crypto.createDecipheriv("aes-128-ccm", key16, ccmIv, {
    authTagLength: 16,
  });
  decipher.setAuthTag(Buffer.from(ccmTag, "hex"));
  decipher.setAAD(Buffer.from("additional"), { plaintextLength: 11 });
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ccmCiphertext, "hex")),
    decipher.final(),
  ]);
  assertEquals(plaintext.toString(), "hello world");
});

Deno.test("aes-128-ccm reports a bad tag at final", () => {
  const decipher = crypto.createDecipheriv("aes-128-ccm", key16, ccmIv, {
    authTagLength: 16,
  });
  const tag = Buffer.from(ccmTag, "hex");
  tag[0] ^= 1;
  decipher.setAuthTag(tag);
  decipher.setAAD(Buffer.from("additional"), { plaintextLength: 11 });
  assertEquals(decipher.update(Buffer.from(ccmCiphertext, "hex")).length, 0);
  assertEquals(thrown(() => decipher.final()), {
    name: "Error",
    code: undefined,
    message: "Unsupported state or unable to authenticate data",
  });
});

Deno.test("aes-256-ocb buffers partial blocks across updates", () => {
  const iv = Buffer.from("202122232425262728292a2b", "hex");
  const cipher = crypto.createCipheriv("aes-256-ocb", key32, iv, {
    authTagLength: 12,
  });
  cipher.setAAD(Buffer.from("header"));
  const parts = [
    cipher.update("a".repeat(5)),
    cipher.update("b".repeat(20)),
    cipher.update("c".repeat(15)),
    cipher.final(),
  ];
  assertEquals(parts.map((part) => part.length), [0, 16, 16, 8]);
  const ciphertext = Buffer.concat(parts);
  assertEquals(
    ciphertext.toString("hex"),
    "8e4c8e1bb8749d1cddb095a316e0878ee144f074d2ee9c4d2c7e30973802433788266e70a042e002",
  );
  assertEquals(cipher.getAuthTag().toString("hex"), "8a545d37610bcfc3a4880924");

  const decipher = crypto.createDecipheriv("aes-256-ocb", key32, iv, {
    authTagLength: 12,
  });
  decipher.setAAD(Buffer.from("header"));
  decipher.setAuthTag(cipher.getAuthTag());
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  assertEquals(
    plaintext.toString(),
    "a".repeat(5) + "b".repeat(20) + "c".repeat(15),
  );
});

Deno.test("CCM and OCB names match without regard to case", () => {
  const cipher = crypto.createCipheriv(
    "AES-128-OCB" as crypto.CipherOCBTypes,
    key16,
    Buffer.alloc(12),
    { authTagLength: 16 },
  );
  cipher.final();
  assertEquals(
    cipher.getAuthTag().toString("hex"),
    "a5a7ac886f721925ed1b023829a078f9",
  );
});

Deno.test("CCM and OCB init errors", () => {
  assertEquals(
    thrown(() => crypto.createCipheriv("aes-128-ccm", key16, Buffer.alloc(12))),
    {
      name: "TypeError",
      code: "ERR_CRYPTO_INVALID_AUTH_TAG",
      message: "authTagLength required for aes-128-ccm",
    },
  );
  assertEquals(
    thrown(() =>
      crypto.createCipheriv("aes-128-ccm", key16, Buffer.alloc(14), {
        authTagLength: 16,
      })
    ),
    {
      name: "TypeError",
      code: "ERR_CRYPTO_INVALID_IV",
      message: "Invalid initialization vector",
    },
  );
  assertEquals(
    thrown(() =>
      crypto.createCipheriv("aes-128-ccm", key16, Buffer.alloc(12), {
        authTagLength: 5,
      })
    ),
    {
      name: "TypeError",
      code: "ERR_CRYPTO_INVALID_AUTH_TAG",
      message: "Invalid authentication tag length: 5",
    },
  );
  assertEquals(
    thrown(() =>
      crypto.createCipheriv("aes-128-ocb", Buffer.alloc(15), Buffer.alloc(12), {
        authTagLength: 16,
      })
    ),
    {
      name: "RangeError",
      code: "ERR_CRYPTO_INVALID_KEYLEN",
      message: "Invalid key length",
    },
  );
});

Deno.test("CCM message and state errors", () => {
  const ccm = (ivLength = 12, authTagLength = 16) =>
    crypto.createCipheriv("aes-128-ccm", key16, Buffer.alloc(ivLength), {
      authTagLength,
    });

  // A cipher holds its native context until final(), so each case below
  // calls final() to release it. The result of final() is not checked here.
  const release = (cipher: crypto.CipherCCM) => {
    try {
      cipher.final();
    } catch {
      // Ignored.
    }
  };

  const noOptions = ccm();
  // @ts-expect-error: CCM requires the options argument, which is omitted here.
  assertEquals(thrown(() => noOptions.setAAD(Buffer.from("x"))), {
    name: "TypeError",
    code: "ERR_MISSING_ARGS",
    message: "options.plaintextLength required for CCM mode with AAD",
  });
  release(noOptions);

  const tooLong = ccm(13);
  assertEquals(thrown(() => tooLong.update(Buffer.alloc(65536))), {
    name: "RangeError",
    code: "ERR_CRYPTO_INVALID_MESSAGELEN",
    message: "Invalid message length",
  });
  release(tooLong);

  const twice = ccm();
  twice.update("a");
  assertEquals(thrown(() => twice.update("b")), {
    name: "Error",
    code: undefined,
    message: "Trying to add data in unsupported state",
  });
  release(twice);

  let tagNotSet: Record<string, unknown> | undefined;
  try {
    ccm().final();
  } catch (e) {
    tagNotSet = e as Record<string, unknown>;
  }
  assertEquals(tagNotSet?.code, "ERR_OSSL_TAG_NOT_SET");
  assertEquals(
    tagNotSet?.message,
    "error:1C800077:Provider routines::tag not set",
  );
  assertEquals(tagNotSet?.reason, "tag not set");
  assertEquals(tagNotSet?.library, "Provider routines");

  // The default lane follows Node.js 24.2 and later (nodejs/node#58547):
  // getAuthTag throws after a failed final. Node.js 20 and 22 return a
  // zero-filled tag, which `CipherAuthTagPolicy` selects.
  const failed = ccm(12, 8);
  try {
    failed.final();
  } catch {
    // Expected: the tag is not set.
  }
  assertEquals(thrown(() => failed.getAuthTag()), {
    name: "Error",
    code: "ERR_CRYPTO_INVALID_STATE",
    message: "Invalid state for operation getAuthTag",
  });
});

Deno.test("getCiphers and getCipherInfo list CCM and OCB", () => {
  const ciphers = crypto.getCiphers();
  for (
    const name of [
      "aes-128-ccm",
      "aes-192-ccm",
      "aes-256-ccm",
      "aes-128-ocb",
      "aes-192-ocb",
      "aes-256-ocb",
      "aes-192-gcm",
    ]
  ) {
    assertEquals(ciphers.includes(name), true, name);
  }
  assertEquals([...ciphers].sort(), ciphers);

  assertEquals(crypto.getCipherInfo("AES-128-CCM", { ivLength: 7 }), {
    mode: "ccm",
    name: "id-aes128-ccm",
    nid: 896,
    blockSize: 1,
    ivLength: 7,
    keyLength: 16,
  });
  assertEquals(crypto.getCipherInfo("aes-256-ocb"), {
    mode: "ocb",
    name: "aes-256-ocb",
    nid: 960,
    blockSize: 16,
    ivLength: 12,
    keyLength: 32,
  });
  assertEquals(crypto.getCipherInfo(959)?.name, "aes-192-ocb");
  assertStrictEquals(
    crypto.getCipherInfo("aes-128-ccm", { ivLength: 14 }),
    undefined,
  );
  assertStrictEquals(
    crypto.getCipherInfo("aes-128-ocb", { ivLength: 16 }),
    undefined,
  );
});

// Node.js v20, v22, v24 and v26 give the same errors for every cipher after
// final().
Deno.test("cipher state errors after final", () => {
  const cases: [string, number, number, crypto.CipherCCMOptions?][] = [
    ["aes-128-cbc", 16, 16],
    ["aes-128-gcm", 16, 12],
    ["aes-128-ccm", 16, 12, { authTagLength: 16 }],
    ["aes-128-ocb", 16, 12, { authTagLength: 16 }],
  ];
  for (const [name, keyLength, ivLength, options] of cases) {
    const key = Buffer.alloc(keyLength);
    const iv = Buffer.alloc(ivLength);
    // The CCM types cover the AEAD methods that this test calls.
    const cipher = crypto.createCipheriv(
      name as crypto.CipherCCMTypes,
      key,
      iv,
      options as crypto.CipherCCMOptions,
    );
    if (name.endsWith("ccm")) {
      cipher.setAAD(Buffer.alloc(0), { plaintextLength: 0 });
    }
    cipher.update("");
    cipher.final();

    assertEquals(thrown(() => cipher.update("a")), {
      name: "Error",
      code: undefined,
      message: "Trying to add data in unsupported state",
    }, name);
    assertEquals(thrown(() => cipher.final()), {
      name: "Error",
      code: "ERR_CRYPTO_INVALID_STATE",
      message: "Invalid state",
    }, name);
    assertEquals(
      thrown(() => cipher.setAAD(Buffer.alloc(1), { plaintextLength: 1 })),
      {
        name: "Error",
        code: "ERR_CRYPTO_INVALID_STATE",
        message: "Invalid state for operation setAAD",
      },
      name,
    );
    assertEquals(thrown(() => cipher.setAutoPadding(false)), {
      name: "Error",
      code: "ERR_CRYPTO_INVALID_STATE",
      message: "Invalid state for operation setAutoPadding",
    }, name);

    const decipher = crypto.createDecipheriv(
      name as crypto.CipherCCMTypes,
      key,
      iv,
      options as crypto.CipherCCMOptions,
    );
    try {
      decipher.final();
    } catch {
      // A missing tag or empty input fails here; the state is final anyway.
    }
    assertEquals(thrown(() => decipher.update(Buffer.from("a"))), {
      name: "Error",
      code: undefined,
      message: "Trying to add data in unsupported state",
    }, name);
    assertEquals(thrown(() => decipher.setAuthTag(Buffer.alloc(16))), {
      name: "Error",
      code: "ERR_CRYPTO_INVALID_STATE",
      message: "Invalid state for operation setAuthTag",
    }, name);
    assertEquals(thrown(() => decipher.final()), {
      name: "Error",
      code: "ERR_CRYPTO_INVALID_STATE",
      message: "Invalid state",
    }, name);
  }
});
