// An embedder can remove globalThis.SharedArrayBuffer before user code runs.
// node:stream/iter must still load, and it must still tell
// SharedArrayBuffer-backed chunks from ArrayBuffer-backed chunks. Node
// v26.10.0 prints the same lines.
const { isSharedArrayBuffer } = require("node:util").types;

const fixed = new SharedArrayBuffer(4);
const growable = new SharedArrayBuffer(4, { maxByteLength: 8 });
new Uint8Array(fixed).set([1, 2, 3, 4]);
new Uint8Array(growable).set([5, 6, 7, 8]);
delete globalThis.SharedArrayBuffer;
console.log("global", typeof globalThis.SharedArrayBuffer);

const iter = require("node:stream/iter");
console.log("loaded", typeof iter.push);

for (const [label, buffer] of [["fixed", fixed], ["growable", growable]]) {
  const chunk = new Uint8Array(buffer);
  const bytes = iter.bytesSync(iter.fromSync(chunk));
  console.log(
    label,
    "bytes",
    Array.from(bytes).join(),
    bytes === chunk,
    isSharedArrayBuffer(bytes.buffer),
  );
  const copy = iter.arrayBufferSync(iter.fromSync(chunk));
  console.log(label, "arrayBuffer", copy.byteLength, isSharedArrayBuffer(copy));
}

const plain = new Uint8Array([9, 10]);
console.log("plain bytes same", iter.bytesSync(iter.fromSync(plain)) === plain);

(async () => {
  const { writer, readable } = iter.push();
  writer.writeSync(new Uint8Array(growable));
  writer.endSync();
  console.log("push", Array.from(await iter.bytes(readable)).join());
})();
