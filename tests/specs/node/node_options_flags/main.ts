import process from "node:process";
import { deprecate } from "node:util";

// `process.noDeprecation` and `process.throwDeprecation` are read-only
// aliases of `--no-deprecation` and `--throw-deprecation`, and
// `util.deprecate` honors them.
console.log(`noDeprecation=${process.noDeprecation}`);
console.log(`throwDeprecation=${process.throwDeprecation}`);

// Node defers the `--throw-deprecation` throw to `process.nextTick`, so the
// call below still returns and the warning surfaces as an uncaught error.
const deprecated = deprecate(() => "called", "DEP0000 message", "DEP0000");
try {
  console.log(`deprecate=${deprecated()}`);
} catch (error) {
  console.log(`deprecate threw ${error.name} ${error.code}`);
}
