// Copyright 2018-2026 the Deno authors. MIT license.

// The `synthetic_esm_gate` of deno_node. deno_core calls it before it builds
// a `synthetic_esm` builtin for an import. Match Node's ESM builtin
// translator (builtinStrategy in lib/internal/modules/esm/translators.js),
// which throws ERR_UNKNOWN_BUILTIN_MODULE for a builtin that users cannot
// load, such as an experimental module whose flag is not set.
(function () {
const { core, primordials } = __bootstrap;
const { StringPrototypeSlice, StringPrototypeStartsWith } = primordials;
const { experimentalModuleIsEnabled } = core.loadExtScript(
  "ext:deno_node/internal/experimental_modules.js",
);

return function checkBuiltinModuleImport(specifier) {
  if (
    StringPrototypeStartsWith(specifier, "node:") &&
    !experimentalModuleIsEnabled(StringPrototypeSlice(specifier, 5))
  ) {
    const { ERR_UNKNOWN_BUILTIN_MODULE } = core.loadExtScript(
      "ext:deno_node/internal/errors.ts",
    );
    throw new ERR_UNKNOWN_BUILTIN_MODULE(specifier);
  }
};
})();
