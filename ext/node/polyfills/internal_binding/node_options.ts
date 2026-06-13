// Copyright 2018-2026 the Deno authors. MIT license.
(function () {
const { primordials } = __bootstrap;
const {
  SafeMap,
  ArrayPrototypeForEach,
  ArrayPrototypeJoin,
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
let defaultExecArgvSnapshot: string[] | undefined;
let nodeOptionsSnapshot: string | undefined;
let optionsMapCacheKey: string | undefined;
let execArgvOptionsMapCacheKey: string | undefined;

function setOptionSourceExecArgv(execArgv: string[]) {
  execArgvSnapshot = ArrayPrototypeSlice(execArgv);
  optionsMap = undefined;
  execArgvOptionsMap = undefined;
  optionsMapCacheKey = undefined;
  execArgvOptionsMapCacheKey = undefined;
}

function createDefaultOptions() {
  return new SafeMap([
    ["--warnings", { value: true }],
    ["--pending-deprecation", { value: false }],
    ["--expose-internals", { value: false }],
    ["--experimental-require-module", { value: true }],
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
  switch (arg) {
    case "--no-warnings":
      options.set("--warnings", { value: false });
      break;
    case "--pending-deprecation":
      options.set("--pending-deprecation", { value: true });
      break;
    case "--enable-source-maps":
      options.set("--enable-source-maps", { value: true });
      break;
    case "--no-enable-source-maps":
      options.set("--enable-source-maps", { value: false });
      break;
    case "--expose-internals":
    case "--expose_internals":
      options.set("--expose-internals", { value: true });
      break;
    case "--experimental-require-module":
    case "--require-module":
      options.set("--experimental-require-module", { value: true });
      break;
    case "--no-experimental-require-module":
    case "--no-require-module":
      options.set("--experimental-require-module", { value: false });
      break;
    case "--preserve-symlinks":
      options.set("--preserve-symlinks", { value: true });
      break;
    case "--preserve-symlinks-main":
      options.set("--preserve-symlinks-main", { value: true });
      break;
    case "--no-preserve-symlinks":
      options.set("--preserve-symlinks", { value: false });
      break;
    case "--no-preserve-symlinks-main":
      options.set("--preserve-symlinks-main", { value: false });
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
  if (execArgvSnapshot !== undefined) {
    return execArgvSnapshot;
  }
  if (defaultExecArgvSnapshot === undefined) {
    defaultExecArgvSnapshot = ArrayPrototypeSlice(
      globalThis.process?.execArgv ?? [],
    );
  }
  return defaultExecArgvSnapshot;
}

function getNodeOptionsEnv() {
  if (nodeOptionsSnapshot === undefined) {
    try {
      nodeOptionsSnapshot = Deno.env.get("NODE_OPTIONS") ?? "";
    } catch {
      nodeOptionsSnapshot = globalThis.process?.env?.NODE_OPTIONS ?? "";
    }
  }
  return nodeOptionsSnapshot;
}

function getExecArgvCacheKey(execArgv: string[]) {
  return ArrayPrototypeJoin(execArgv, "\0");
}

function getOptions() {
  const nodeOptions = getNodeOptionsEnv();
  const execArgv = getExecArgv();
  const cacheKey = nodeOptions + "\0" + getExecArgvCacheKey(execArgv);
  if (optionsMap && optionsMapCacheKey === cacheKey) {
    return { options: optionsMap };
  }

  const options = createDefaultOptions();
  const envArgs = nodeOptions ? splitNodeOptions(nodeOptions) : [];
  const args = ArrayPrototypeConcat(envArgs, execArgv);
  ArrayPrototypeForEach(args, (arg) => parseOption(options, arg));
  optionsMap = options;
  optionsMapCacheKey = cacheKey;
  return { options };
}

function getExecArgvOptions() {
  const execArgv = getExecArgv();
  const cacheKey = getExecArgvCacheKey(execArgv);
  if (execArgvOptionsMap && execArgvOptionsMapCacheKey === cacheKey) {
    return { options: execArgvOptionsMap };
  }
  const options = new SafeMap();
  ArrayPrototypeForEach(execArgv, (arg) => parseOption(options, arg));
  execArgvOptionsMap = options;
  execArgvOptionsMapCacheKey = cacheKey;
  return { options };
}

return {
  getExecArgvOptions,
  getOptions,
  setOptionSourceExecArgv,
};
})();
