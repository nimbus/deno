import Module, { builtinModules } from "node:module";

console.log(builtinModules === Module.builtinModules);
console.log(builtinModules.filter((id) => id.endsWith("/iter")));
