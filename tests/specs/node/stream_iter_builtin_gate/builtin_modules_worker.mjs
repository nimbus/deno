import { builtinModules } from "node:module";
import { Worker } from "node:worker_threads";

console.log(builtinModules.filter((id) => id.endsWith("/iter")));
new Worker(
  `const { builtinModules } = require("node:module");
console.log(builtinModules.filter((id) => id.endsWith("/iter")));`,
  { eval: true, execArgv: ["--experimental-stream-iter", "--no-warnings"] },
);
