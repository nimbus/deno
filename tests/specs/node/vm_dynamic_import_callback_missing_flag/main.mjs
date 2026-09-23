// Without `--experimental-vm-modules`, Node accepts an `importModuleDynamically`
// callback but never invokes it: the first `import()` rejects with
// ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING_FLAG. The positive path runs in
// `vm_dynamic_import_callback` with the flag set through NODE_OPTIONS.

import vm from "node:vm";

function mustNotCall() {
  return () => {
    throw new Error("importModuleDynamically must not be invoked");
  };
}

function report(label, promise) {
  return promise.then(
    () => console.log(label, "FAIL: import resolved"),
    (e) => console.log(label, `${e.name} ${e.code}: ${e.message}`),
  );
}

// new vm.Script(source, { importModuleDynamically })
{
  const script = new vm.Script("import('node:fs')", {
    importModuleDynamically: mustNotCall(),
  });
  await report("Script", script.runInThisContext());
}

// vm.compileFunction(code, params, { importModuleDynamically })
{
  const fn = vm.compileFunction("return import('node:fs');", [], {
    importModuleDynamically: mustNotCall(),
  });
  await report("compileFunction", fn());
}

// vm.createContext(sandbox, { importModuleDynamically })
{
  const context = vm.createContext({ Promise }, {
    importModuleDynamically: mustNotCall(),
  });
  vm.runInContext("globalThis.value = import('node:fs')", context);
  await report("createContext", context.value);
}

// new vm.SourceTextModule(source, { importModuleDynamically })
{
  const module = new vm.SourceTextModule(
    "globalThis.__stm = import('node:fs');",
    { importModuleDynamically: mustNotCall() },
  );
  await module.link(() => {
    throw new Error("unexpected static import");
  });
  await module.evaluate();
  await report("SourceTextModule", globalThis.__stm);
}

// USE_MAIN_CONTEXT_DEFAULT_LOADER does not need the flag.
{
  const script = new vm.Script(
    "import('node:process').then((m) => typeof m.argv)",
    { importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER },
  );
  console.log(
    "USE_MAIN_CONTEXT_DEFAULT_LOADER",
    await script.runInThisContext(),
  );
}
