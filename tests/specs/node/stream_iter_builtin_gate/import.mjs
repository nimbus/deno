// Node only loads node:stream/iter and node:zlib/iter with
// --experimental-stream-iter. Without the flag, the ESM loader rejects them
// with ERR_UNKNOWN_BUILTIN_MODULE, and a second import fails the same way.

async function report(label, load) {
  try {
    const mod = await load();
    console.log(label, "loaded", typeof mod.default);
  } catch (e) {
    console.log(label, `${e.name} ${e.code}: ${e.message}`);
  }
}

await report("dynamic stream/iter", () => import("node:stream/iter"));
await report("dynamic zlib/iter", () => import("node:zlib/iter"));
await report("dynamic stream/iter again", () => import("node:stream/iter"));
await report("static stream/iter", () => import("./static_import.mjs"));
