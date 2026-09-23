// Copyright 2018-2026 the Deno authors. MIT license.

// Match Node's experimentalModuleList (lib/internal/bootstrap/realm.js):
// these builtins are only available when their flag is set (see
// setupStreamIter in lib/internal/process/pre_execution.js).
(function () {
const { core } = __bootstrap;

const experimentalModuleFlags = {
  __proto__: null,
  "stream/iter": "--experimental-stream-iter",
  "zlib/iter": "--experimental-stream-iter",
};

let getOptionValue;

function experimentalModuleIsEnabled(id) {
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
