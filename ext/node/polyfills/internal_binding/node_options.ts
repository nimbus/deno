// Copyright 2018-2026 the Deno authors. MIT license.
(function () {
const { primordials } = __bootstrap;
const {
  SafeMap,
  ArrayPrototypeForEach,
  ArrayPrototypePush,
  ArrayPrototypeConcat,
  ArrayPrototypeSlice,
  StringPrototypeSlice,
  StringPrototypeStartsWith,
} = primordials;

// This module ports:
// - https://github.com/nodejs/node/blob/master/src/node_options-inl.h
// - https://github.com/nodejs/node/blob/master/src/node_options.cc
// - https://github.com/nodejs/node/blob/master/src/node_options.h

// Quote-aware tokenizer for NODE_OPTIONS. Node.js uses a shell-like parser
// that respects single and double quotes, so `--title="hello world"` is a
// single token whose value is `hello world`, not two tokens.
function splitNodeOptions(input: string): string[] {
  const args: string[] = [];
  let current = "";
  let inDouble = false;
  let inSingle = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (
      (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") && !inDouble &&
      !inSingle
    ) {
      if (current.length > 0) {
        ArrayPrototypePush(args, current);
        current = "";
      }
    } else {
      current += ch;
    }
  }
  if (current.length > 0) {
    ArrayPrototypePush(args, current);
  }
  return args;
}

/** Gets the all options for Node.js
 * This function is expensive to execute. `getOptionValue` in `internal/options.ts`
 * should be used instead to get a specific option. */
type OptionValue = { value: string | boolean };

let optionsMap: Map<string, OptionValue> | undefined;
let execArgvOptionsMap: Map<string, OptionValue> | undefined;
let execArgvSnapshot: string[] | undefined;
const optionSourceListeners: (() => void)[] = [];

// State derived from option values (such as the experimental entries of
// `Module.builtinModules`) registers here, so that it follows a change of
// the option source.
function onOptionSourceChange(listener: () => void) {
  ArrayPrototypePush(optionSourceListeners, listener);
}

function setOptionSourceExecArgv(execArgv: string[]) {
  execArgvSnapshot = ArrayPrototypeSlice(execArgv);
  optionsMap = undefined;
  execArgvOptionsMap = undefined;
  ArrayPrototypeForEach(optionSourceListeners, (listener) => listener());
}

// Defaults are listed only for options whose Node default is the same on
// every supported Node release line. `getOptionValueFromMap` in
// `internal/options.ts` answers `--no-<name>` by negating `--<name>`, so
// negatable options are stored under their positive name (`--no-deprecation`
// sets `--deprecation` to `false`).
function createDefaultOptions() {
  return new SafeMap([
    ["--warnings", { value: true }],
    ["--deprecation", { value: true }],
    ["--throw-deprecation", { value: false }],
    ["--trace-warnings", { value: false }],
    ["--pending-deprecation", { value: false }],
    ["--expose-internals", { value: false }],
    ["--enable-source-maps", { value: false }],
    ["--experimental-require-module", { value: true }],
    ["--experimental-stream-iter", { value: false }],
    ["--experimental-vm-modules", { value: false }],
    ["--preserve-symlinks", { value: false }],
    ["--preserve-symlinks-main", { value: false }],
    ["--title", { value: "" }],
    ["--unhandled-rejections", { value: "throw" }],
  ]);
}

function parseOption(options: Map<string, OptionValue>, arg: string) {
  if (StringPrototypeStartsWith(arg, "--title=")) {
    options.set("--title", { value: StringPrototypeSlice(arg, 8) });
    return;
  }
  if (StringPrototypeStartsWith(arg, "--tls-cipher-list=")) {
    options.set("--tls-cipher-list", {
      value: StringPrototypeSlice(arg, "--tls-cipher-list=".length),
    });
    return;
  }
  if (StringPrototypeStartsWith(arg, "--unhandled-rejections=")) {
    options.set("--unhandled-rejections", {
      value: StringPrototypeSlice(arg, "--unhandled-rejections=".length),
    });
    return;
  }
  if (StringPrototypeStartsWith(arg, "--trace-require-module=")) {
    options.set("--trace-require-module", {
      value: StringPrototypeSlice(arg, "--trace-require-module=".length),
    });
    return;
  }
  switch (arg) {
    case "--no-warnings":
      options.set("--warnings", { value: false });
      break;
    case "--no-deprecation":
      options.set("--deprecation", { value: false });
      break;
    case "--throw-deprecation":
      options.set("--throw-deprecation", { value: true });
      break;
    case "--no-throw-deprecation":
      options.set("--throw-deprecation", { value: false });
      break;
    case "--trace-warnings":
      options.set("--trace-warnings", { value: true });
      break;
    case "--no-trace-warnings":
      options.set("--trace-warnings", { value: false });
      break;
    case "--pending-deprecation":
      options.set("--pending-deprecation", { value: true });
      break;
    case "--expose-internals":
    case "--expose_internals":
      options.set("--expose-internals", { value: true });
      break;
    case "--enable-source-maps":
      options.set("--enable-source-maps", { value: true });
      break;
    case "--no-enable-source-maps":
      options.set("--enable-source-maps", { value: false });
      break;
    // `--async-context-frame` has no default here: Node 22 defaults it off
    // and Node 24 defaults it on, so only an explicit flag is recorded.
    case "--async-context-frame":
      options.set("--async-context-frame", { value: true });
      break;
    case "--no-async-context-frame":
      options.set("--async-context-frame", { value: false });
      break;
    case "--experimental-require-module":
    case "--require-module":
      options.set("--experimental-require-module", { value: true });
      break;
    case "--no-experimental-require-module":
    case "--no-require-module":
      options.set("--experimental-require-module", { value: false });
      break;
    case "--experimental-print-required-tla":
      options.set("--experimental-print-required-tla", { value: true });
      break;
    case "--experimental-eventsource":
      options.set("--experimental-eventsource", { value: true });
      break;
    // `--experimental-sqlite` has no default here: Node 22.13 unflagged it
    // and Node 20 never shipped it, so only an explicit flag is recorded.
    case "--experimental-sqlite":
      options.set("--experimental-sqlite", { value: true });
      break;
    case "--no-experimental-sqlite":
      options.set("--experimental-sqlite", { value: false });
      break;
    case "--experimental-stream-iter":
      options.set("--experimental-stream-iter", { value: true });
      break;
    case "--experimental-vm-modules":
      options.set("--experimental-vm-modules", { value: true });
      break;
    case "--no-experimental-vm-modules":
      options.set("--experimental-vm-modules", { value: false });
      break;
    case "--preserve-symlinks":
      options.set("--preserve-symlinks", { value: true });
      break;
    case "--no-preserve-symlinks":
      options.set("--preserve-symlinks", { value: false });
      break;
    case "--preserve-symlinks-main":
      options.set("--preserve-symlinks-main", { value: true });
      break;
    case "--no-preserve-symlinks-main":
      options.set("--preserve-symlinks-main", { value: false });
      break;
    case "--trace-events-enabled":
      options.set("--trace-events-enabled", { value: true });
      break;
    case "--turbo-fast-api-calls":
      options.set("--turbo-fast-api-calls", { value: true });
      break;
    case "--no-turbo-fast-api-calls":
      options.set("--turbo-fast-api-calls", { value: false });
      break;
    case "--tls-min-v1.0":
    case "--tls-min-v1.1":
    case "--tls-min-v1.2":
    case "--tls-min-v1.3":
    case "--tls-max-v1.2":
    case "--tls-max-v1.3":
    case "--use-bundled-ca":
    case "--use-openssl-ca":
    case "--use-system-ca":
      options.set(arg, { value: true });
      break;
    case "--no-tls-min-v1.0":
      options.set("--tls-min-v1.0", { value: false });
      break;
    case "--no-tls-min-v1.1":
      options.set("--tls-min-v1.1", { value: false });
      break;
    case "--no-tls-min-v1.2":
      options.set("--tls-min-v1.2", { value: false });
      break;
    case "--no-tls-min-v1.3":
      options.set("--tls-min-v1.3", { value: false });
      break;
    case "--no-tls-max-v1.2":
      options.set("--tls-max-v1.2", { value: false });
      break;
    case "--no-tls-max-v1.3":
      options.set("--tls-max-v1.3", { value: false });
      break;
    case "--no-use-bundled-ca":
      options.set("--use-bundled-ca", { value: false });
      break;
    case "--no-use-openssl-ca":
      options.set("--use-openssl-ca", { value: false });
      break;
    case "--no-use-system-ca":
      options.set("--use-system-ca", { value: false });
      break;
    default:
      if (StringPrototypeStartsWith(arg, "--dns-result-order=")) {
        const value = StringPrototypeSlice(
          arg,
          "--dns-result-order=".length,
        );
        options.set("--dns-result-order", { value });
      }
      break;
  }
}

function getExecArgv() {
  if (execArgvSnapshot) {
    return execArgvSnapshot;
  }
  // `globalThis.process` is a lazy getter that loads `node:process`. During
  // node:process's OWN cold bootstrap (when the require system is deferred
  // out of the snapshot), reading it re-enters that load and the `default`
  // export is still in the temporal dead zone -- accessing the getter throws
  // rather than yielding undefined, so `?.` doesn't help. Guard it: no exec
  // args are available pre-bootstrap anyway, so fall back to `[]`.
  try {
    return globalThis.process?.execArgv ?? [];
  } catch {
    return [];
  }
}

function getOptions() {
  if (optionsMap) {
    return { options: optionsMap };
  }

  const options = createDefaultOptions();
  const nodeOptions = Deno.env.get("NODE_OPTIONS");
  const envArgs = nodeOptions ? splitNodeOptions(nodeOptions) : [];
  const execArgv = getExecArgv();
  const args = ArrayPrototypeConcat(envArgs, execArgv);
  ArrayPrototypeForEach(args, (arg) => parseOption(options, arg));
  optionsMap = options;
  return { options };
}

function getExecArgvOptions() {
  if (execArgvOptionsMap) {
    return { options: execArgvOptionsMap };
  }
  const options = new SafeMap();
  ArrayPrototypeForEach(getExecArgv(), (arg) => parseOption(options, arg));
  execArgvOptionsMap = options;
  return { options };
}

return {
  getExecArgvOptions,
  getOptions,
  onOptionSourceChange,
  setOptionSourceExecArgv,
};
})();
