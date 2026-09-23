// Node only loads node:stream/iter and node:zlib/iter with
// --experimental-stream-iter. Without the flag, the ESM loader rejects them
// with ERR_UNKNOWN_BUILTIN_MODULE, and a second import fails the same way.
// The bare `stream/iter` and `zlib/iter` specifiers are not builtins then,
// so they resolve as packages and fail with ERR_MODULE_NOT_FOUND.

async function report(label, load) {
  try {
    const mod = await load();
    console.log(label, "loaded", typeof mod.default);
  } catch (e) {
    console.log(label, `${e.name} ${e.code}: ${e.message}`);
  }
}

async function reportBare(label, load) {
  try {
    const mod = await load();
    console.log(label, "loaded", typeof mod.default);
  } catch (e) {
    console.log(label, e.code);
  }
}

await report("dynamic stream/iter", () => import("node:stream/iter"));
await report("dynamic zlib/iter", () => import("node:zlib/iter"));
await report("dynamic stream/iter again", () => import("node:stream/iter"));
await report("static stream/iter", () => import("./static_import.mjs"));
await reportBare("dynamic bare stream/iter", () => import("stream/iter"));
await reportBare("dynamic bare zlib/iter", () => import("zlib/iter"));
await reportBare("static bare", () => import("./static_bare_import.mjs"));

for (const specifier of ["node:stream/iter", "stream/iter", "zlib/iter"]) {
  try {
    console.log("resolve", specifier, import.meta.resolve(specifier));
  } catch {
    console.log("resolve", specifier, "threw");
  }
}
