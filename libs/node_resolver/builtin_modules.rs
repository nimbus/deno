// Copyright 2018-2026 the Deno authors. MIT license.

pub trait IsBuiltInNodeModuleChecker: std::fmt::Debug {
  /// e.g. `is_builtin_node_module("assert")`
  fn is_builtin_node_module(&self, module_name: &str) -> bool;

  /// Whether a bare specifier without the `node:` scheme resolves to this
  /// built-in module, e.g. `import "stream/iter"`. This is Node's
  /// `BuiltinModule.canBeRequiredWithoutScheme()` for experimental modules:
  /// they stay hidden until their flag is set.
  fn is_schemeless_builtin_node_module(&self, module_name: &str) -> bool {
    self.is_builtin_node_module(module_name)
  }
}

/// An implementation of IsBuiltInNodeModuleChecker that uses
/// the list of built-in node_modules that are supported by Deno
/// in the `deno_node` crate (ext/node).
#[derive(Debug, Default, Clone)]
pub struct DenoIsBuiltInNodeModuleChecker {
  /// The flags from `EXPERIMENTAL_BUILTIN_NODE_MODULES` that are set.
  enabled_experimental_flags: Vec<&'static str>,
}

impl DenoIsBuiltInNodeModuleChecker {
  /// Reads the experimental module flags from the `NODE_OPTIONS` environment
  /// variable. The `node` shim forwards them there, and the `require` side
  /// reads them from there too (`getOptionValue()`).
  pub fn from_env(sys: &impl sys_traits::EnvVar) -> Self {
    Self::from_node_options(sys.env_var("NODE_OPTIONS").ok().as_deref())
  }

  pub fn from_node_options(node_options: Option<&str>) -> Self {
    let args = node_options
      .and_then(|value| node_shim::parse_node_options_env_var(value).ok())
      .unwrap_or_default();
    let mut enabled_experimental_flags = Vec::new();
    for (_, flag) in EXPERIMENTAL_BUILTIN_NODE_MODULES {
      if enabled_experimental_flags.contains(flag) {
        continue;
      }
      let negated_flag = format!("--no-{}", &flag[2..]);
      // The last occurrence wins, as in Node's option parser.
      let is_set = args
        .iter()
        .rev()
        .find_map(|arg| {
          if arg == flag {
            Some(true)
          } else if *arg == negated_flag {
            Some(false)
          } else {
            None
          }
        })
        .unwrap_or(false);
      if is_set {
        enabled_experimental_flags.push(*flag);
      }
    }
    Self {
      enabled_experimental_flags,
    }
  }
}

impl IsBuiltInNodeModuleChecker for DenoIsBuiltInNodeModuleChecker {
  #[inline(always)]
  fn is_builtin_node_module(&self, module_name: &str) -> bool {
    DENO_SUPPORTED_BUILTIN_NODE_MODULES
      .binary_search(&module_name)
      .is_ok()
  }

  fn is_schemeless_builtin_node_module(&self, module_name: &str) -> bool {
    self.is_builtin_node_module(module_name)
      && experimental_builtin_node_module_flag(module_name)
        .is_none_or(|flag| self.enabled_experimental_flags.contains(&flag))
  }
}

/// Built-in modules that Node hides until a flag enables them, with that flag.
/// Mirrors `experimentalModuleList` in `lib/internal/bootstrap/realm.js` and the
/// `allowRequireByUsers()` calls in `lib/internal/process/pre_execution.js`.
/// ext/node gives this table to `require` and to the ESM builtin gate.
pub static EXPERIMENTAL_BUILTIN_NODE_MODULES: &[(&str, &str)] = &[
  ("stream/iter", "--experimental-stream-iter"),
  ("zlib/iter", "--experimental-stream-iter"),
];

/// e.g. `experimental_builtin_node_module_flag("stream/iter")`
fn experimental_builtin_node_module_flag(
  module_name: &str,
) -> Option<&'static str> {
  EXPERIMENTAL_BUILTIN_NODE_MODULES
    .iter()
    .find(|(name, _)| *name == module_name)
    .map(|(_, flag)| *flag)
}

/// Collection of built-in node_modules supported by Deno.
pub static DENO_SUPPORTED_BUILTIN_NODE_MODULES: &[&str] = &[
  // NOTE(bartlomieju): keep this list in sync with `ext/node/polyfills/01_require.js`
  "_http_agent",
  "_http_common",
  "_http_outgoing",
  "_http_server",
  "_stream_duplex",
  "_stream_passthrough",
  "_stream_readable",
  "_stream_transform",
  "_stream_writable",
  "_tls_common",
  "_tls_wrap",
  "assert",
  "assert/strict",
  "async_hooks",
  "buffer",
  "child_process",
  "cluster",
  "console",
  "constants",
  "crypto",
  "dgram",
  "diagnostics_channel",
  "dns",
  "dns/promises",
  "domain",
  "events",
  "fs",
  "fs/promises",
  "http",
  "http2",
  "https",
  "inspector",
  "inspector/promises",
  "module",
  "net",
  "os",
  "path",
  "path/posix",
  "path/win32",
  "perf_hooks",
  "process",
  "punycode",
  "querystring",
  "readline",
  "readline/promises",
  "repl",
  "sqlite",
  "stream",
  "stream/consumers",
  "stream/iter",
  "stream/promises",
  "stream/web",
  "string_decoder",
  "sys",
  "test",
  "test/reporters",
  "timers",
  "timers/promises",
  "tls",
  "trace_events",
  "tty",
  "url",
  "util",
  "util/types",
  "v8",
  "vm",
  "wasi",
  "worker_threads",
  "zlib",
  "zlib/iter",
];

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn test_builtins_are_sorted() {
    let mut builtins_list = DENO_SUPPORTED_BUILTIN_NODE_MODULES.to_vec();
    builtins_list.sort();
    assert_eq!(DENO_SUPPORTED_BUILTIN_NODE_MODULES, builtins_list);
  }

  #[test]
  fn test_experimental_builtins_are_supported() {
    let checker = DenoIsBuiltInNodeModuleChecker::default();
    for (module_name, flag) in EXPERIMENTAL_BUILTIN_NODE_MODULES {
      assert!(checker.is_builtin_node_module(module_name), "{module_name}");
      assert!(flag.starts_with("--"), "{flag}");
    }
  }

  #[test]
  fn test_schemeless_experimental_builtin_gate() {
    let checker = DenoIsBuiltInNodeModuleChecker::from_node_options(None);
    // The `node:` scheme always names the module. The ESM loader and
    // `require` throw ERR_UNKNOWN_BUILTIN_MODULE for it when it is hidden.
    assert!(checker.is_builtin_node_module("stream/iter"));
    assert!(checker.is_builtin_node_module("zlib/iter"));
    assert!(!checker.is_schemeless_builtin_node_module("stream/iter"));
    assert!(!checker.is_schemeless_builtin_node_module("zlib/iter"));
    assert!(checker.is_schemeless_builtin_node_module("stream"));
    assert!(checker.is_schemeless_builtin_node_module("zlib"));
    assert!(!checker.is_schemeless_builtin_node_module("not-a-builtin"));

    for node_options in [
      "--experimental-stream-iter",
      "--no-warnings --experimental-stream-iter",
      "--no-experimental-stream-iter --experimental-stream-iter",
      "--title \"a b\" --experimental-stream-iter",
    ] {
      let checker =
        DenoIsBuiltInNodeModuleChecker::from_node_options(Some(node_options));
      assert!(
        checker.is_schemeless_builtin_node_module("stream/iter"),
        "{node_options}"
      );
      assert!(
        checker.is_schemeless_builtin_node_module("zlib/iter"),
        "{node_options}"
      );
    }

    for node_options in [
      "",
      "--no-warnings",
      "--experimental-stream-iter --no-experimental-stream-iter",
      "--experimental-stream-iterx",
      // Node does not start with an invalid NODE_OPTIONS value.
      "--experimental-stream-iter \"unterminated",
    ] {
      let checker =
        DenoIsBuiltInNodeModuleChecker::from_node_options(Some(node_options));
      assert!(
        !checker.is_schemeless_builtin_node_module("stream/iter"),
        "{node_options}"
      );
      assert!(
        !checker.is_schemeless_builtin_node_module("zlib/iter"),
        "{node_options}"
      );
    }
  }

  #[test]
  fn test_schemeless_gate_reads_node_options_env_var() {
    use sys_traits::EnvSetVar;

    let sys = sys_traits::impls::InMemorySys::default();
    let checker = DenoIsBuiltInNodeModuleChecker::from_env(&sys);
    assert!(!checker.is_schemeless_builtin_node_module("stream/iter"));

    sys.env_set_var("NODE_OPTIONS", "--experimental-stream-iter");
    let checker = DenoIsBuiltInNodeModuleChecker::from_env(&sys);
    assert!(checker.is_schemeless_builtin_node_module("stream/iter"));
  }
}
