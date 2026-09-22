// Copyright 2018-2026 the Deno authors. MIT license.
import { createDiffieHellman } from "node:crypto";
import { Buffer } from "node:buffer";
import { assert, assertEquals } from "../../unit/test_util.ts";

// Node stores a Diffie-Hellman key as an OpenSSL BIGNUM: a getter renders a
// fresh buffer out of it, and a setter reads the raw bytes of its argument
// into it. These tests pin both halves of that contract.

function newDh() {
  const dh = createDiffieHellman(1024);
  dh.generateKeys();
  return dh;
}

Deno.test("[node/crypto.DiffieHellman] a getter returns a fresh buffer", () => {
  const dh = newDh();

  assert(dh.getPublicKey() !== dh.getPublicKey());
  assert(dh.getPrivateKey() !== dh.getPrivateKey());
  assert(dh.generateKeys() !== dh.getPublicKey());
  assertEquals(dh.getPublicKey(), dh.getPublicKey());
  assertEquals(dh.getPrivateKey(), dh.getPrivateKey());
});

Deno.test("[node/crypto.DiffieHellman] a caller cannot mutate the stored key", () => {
  const dh = newDh();
  const publicKey = dh.getPublicKey();
  const privateKey = dh.getPrivateKey();

  publicKey[0] ^= 0xff;
  privateKey[0] ^= 0xff;

  assert(dh.getPublicKey()[0] !== publicKey[0]);
  assert(dh.getPrivateKey()[0] !== privateKey[0]);
});

Deno.test("[node/crypto.DiffieHellman] a setter copies its argument", () => {
  const dh = newDh();
  // A fixed pattern with no leading zero byte, so the stored key round-trips
  // byte for byte.
  const publicKey = Buffer.alloc(128, 0x5a);
  const privateKey = Buffer.alloc(128, 0xa5);

  dh.setPublicKey(publicKey);
  dh.setPrivateKey(privateKey);
  assertEquals(dh.getPublicKey(), publicKey);
  assertEquals(dh.getPrivateKey(), privateKey);

  // A later mutation of the argument must not reach the stored key.
  publicKey[0] ^= 0xff;
  privateKey[0] ^= 0xff;
  assertEquals(dh.getPublicKey()[0], 0x5a);
  assertEquals(dh.getPrivateKey()[0], 0xa5);
});

Deno.test("[node/crypto.DiffieHellman] a setter reads raw bytes", () => {
  const dh = newDh();
  const view = new Uint16Array([0xaabb, 0xccdd]);

  dh.setPrivateKey(view);

  // Node hands the view's bytes to OpenSSL, so the stored key keeps all four
  // of them rather than truncating each element to one byte.
  assertEquals(
    (dh.getPrivateKey() as Buffer).toString("hex"),
    Buffer.from(view.buffer, view.byteOffset, view.byteLength).toString("hex"),
  );
});

Deno.test("[node/crypto.DiffieHellman] a setter accepts a shorter key", () => {
  const dh = newDh();
  const short = Buffer.from([0x01, 0x02, 0x03]);

  dh.setPublicKey(short);
  assertEquals(dh.getPublicKey(), short);

  const long = Buffer.alloc(128, 0x07);
  dh.setPublicKey(long);
  assertEquals(dh.getPublicKey(), long);
});

Deno.test("[node/crypto.DiffieHellman] a setter loop does not grow the heap", () => {
  const dh = newDh();
  const publicKey = dh.getPublicKey();
  const privateKey = dh.getPrivateKey();

  // The setters must not allocate per call. Node keeps this loop flat because
  // it overwrites one BIGNUM; the polyfill keeps it flat by overwriting one
  // buffer in place.
  const before = Deno.memoryUsage().heapUsed;
  for (let i = 0; i < 5e4; i += 1) {
    dh.setPublicKey(publicKey);
    dh.setPrivateKey(privateKey);
  }
  const after = Deno.memoryUsage().heapUsed;

  assert(
    after - before < 8 << 20,
    `heapUsed grew by ${after - before} bytes across 100000 setter calls`,
  );
});

Deno.test("[node/crypto.DiffieHellman] a shared secret still agrees", () => {
  const alice = createDiffieHellman(1024);
  const alicePublicKey = alice.generateKeys();

  const bob = createDiffieHellman(alice.getPrime(), alice.getGenerator());
  const bobPublicKey = bob.generateKeys();

  // Round-trip both key pairs through the setters before deriving, so a
  // setter that stored the wrong bytes would break agreement.
  alice.setPrivateKey(alice.getPrivateKey());
  alice.setPublicKey(alicePublicKey);
  bob.setPrivateKey(bob.getPrivateKey());
  bob.setPublicKey(bobPublicKey);

  assertEquals(
    alice.computeSecret(bobPublicKey),
    bob.computeSecret(alicePublicKey),
  );
});
