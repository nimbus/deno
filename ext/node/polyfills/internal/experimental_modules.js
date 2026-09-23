// Copyright 2018-2026 the Deno authors. MIT license.

// Match Node's experimentalModuleList (lib/internal/bootstrap/realm.js):
// these builtins are only available when their flag is set (see
// setupStreamIter in lib/internal/process/pre_execution.js). The table lives
// in node_resolver (EXPERIMENTAL_BUILTIN_NODE_MODULES), which also gates bare
// ESM specifiers such as `import "stream/iter"`.
(function () {
const { core, primordials } = __bootstrap;
const { ArrayPrototypeForEach } = primordials;
const { op_require_experimental_builtin_modules } = core.ops;

let experimentalModuleFlags;
let getOptionValue;

function experimentalModuleIsEnabled(id) {
  if (experimentalModuleFlags === undefined) {
    experimentalModuleFlags = { __proto__: null };
    ArrayPrototypeForEach(
      op_require_experimental_builtin_modules(),
      ({ 0: moduleId, 1: flag }) => {
        experimentalModuleFlags[moduleId] = flag;
      },
    );
  }
  const flag = experimentalModuleFlags[id];
  if (flag === undefined) {
    return true;
  }
  getOptionValue ??= core.loadExtScript("ext:deno_node/internal/options.ts")
    .getOptionValue;
  return getOptionValue(flag) === true;
}

return { experimentalModuleIsEnabled };
})();
