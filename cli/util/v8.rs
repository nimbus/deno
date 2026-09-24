// Copyright 2018-2026 the Deno authors. MIT license.

use deno_lib::util::v8::construct_v8_flags;

pub mod convert;

#[inline(always)]
pub fn get_v8_flags_from_env() -> Vec<String> {
  std::env::var("DENO_V8_FLAGS")
    .ok()
    .map(|flags| flags.split(',').map(String::from).collect::<Vec<String>>())
    .unwrap_or_default()
}

/// Whether V8 aborts the process on an uncaught exception, as with
/// `--abort-on-uncaught-exception`. The last flag wins, like in V8.
pub fn aborts_on_uncaught_exception(v8_flags: &[String]) -> bool {
  let mut aborts = false;
  for flag in get_v8_flags_from_env().iter().chain(v8_flags) {
    match flag.replace('_', "-").as_str() {
      "--abort-on-uncaught-exception" => aborts = true,
      "--no-abort-on-uncaught-exception" => aborts = false,
      _ => {}
    }
  }
  aborts
}

pub fn init_v8_flags(
  default_v8_flags: &[String],
  v8_flags: &[String],
  env_v8_flags: Vec<String>,
) {
  if default_v8_flags.is_empty()
    && v8_flags.is_empty()
    && env_v8_flags.is_empty()
  {
    return;
  }

  let v8_flags_includes_help = env_v8_flags
    .iter()
    .chain(v8_flags)
    .any(|flag| flag == "-help" || flag == "--help");
  // Keep in sync with `standalone.rs`.
  let v8_flags = construct_v8_flags(default_v8_flags, v8_flags, env_v8_flags);
  let unrecognized_v8_flags = deno_core::v8_set_flags(v8_flags)
    .into_iter()
    .skip(1)
    .collect::<Vec<_>>();

  if !unrecognized_v8_flags.is_empty() {
    for f in unrecognized_v8_flags {
      log::error!("error: V8 did not recognize flag '{f}'");
    }
    log::error!("\nFor a list of V8 flags, use '--v8-flags=--help'");
    deno_runtime::exit(1);
  }
  if v8_flags_includes_help {
    deno_runtime::exit(0);
  }
}
