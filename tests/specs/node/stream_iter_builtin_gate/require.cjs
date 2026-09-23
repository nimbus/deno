const { builtinModules } = require("node:module");

console.log(
  "builtinModules",
  builtinModules.includes("stream/iter"),
  builtinModules.includes("zlib/iter"),
);
for (const id of ["node:stream/iter", "node:zlib/iter", "stream/iter"]) {
  try {
    console.log(id, "loaded", typeof require(id).from);
  } catch (e) {
    console.log(id, `${e.name} ${e.code}: ${e.message.split("\n")[0]}`);
  }
}
