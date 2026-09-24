// Copyright 2018-2026 the Deno authors. MIT license.
(function () {
const inner = Deno.core.loadExtScript("ext:test_ext/lazy_script_throw.js");
return { inner };
})();
