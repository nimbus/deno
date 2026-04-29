// Copyright 2018-2026 the Deno authors. MIT license.

use crate::JsRuntime;
use crate::RuntimeOptions;

#[test]
fn locker_runtime_basic() {
  let mut runtime = JsRuntime::new(RuntimeOptions {
    use_locker: true,
    ..Default::default()
  });

  assert!(runtime.is_v8_lock_held());

  let result = {
    let mut locked = runtime.acquire_v8_lock();
    locked.execute_script("test.js", "1 + 1").unwrap()
  };

  assert!(!runtime.is_v8_lock_held());

  let _scope = runtime.v8_isolate();
  drop(result);
}

#[test]
fn locker_runtime_two_runtimes_same_thread() {
  let mut rt1 = JsRuntime::new(RuntimeOptions {
    use_locker: true,
    ..Default::default()
  });
  assert!(rt1.release_v8_lock());
  assert!(!rt1.is_v8_lock_held());

  let mut rt2 = JsRuntime::new(RuntimeOptions {
    use_locker: true,
    ..Default::default()
  });
  assert!(rt2.release_v8_lock());
  assert!(!rt2.is_v8_lock_held());

  {
    let mut locked = rt1.acquire_v8_lock();
    locked.execute_script("rt1.js", "1 + 1").unwrap();
  }
  assert!(!rt1.is_v8_lock_held());

  {
    let mut locked = rt2.acquire_v8_lock();
    locked.execute_script("rt2.js", "2 + 2").unwrap();
  }
  assert!(!rt2.is_v8_lock_held());

  {
    let mut locked = rt1.acquire_v8_lock();
    locked.execute_script("rt1b.js", "3 + 3").unwrap();
  }
  {
    let mut locked = rt2.acquire_v8_lock();
    locked.execute_script("rt2b.js", "4 + 4").unwrap();
  }
}

#[test]
fn locker_runtime_mixed_with_standard() {
  let mut standard = JsRuntime::new(RuntimeOptions {
    use_locker: false,
    ..Default::default()
  });
  let mut lockable = JsRuntime::new(RuntimeOptions {
    use_locker: true,
    ..Default::default()
  });

  assert!(lockable.release_v8_lock());
  standard.execute_script("std.js", "10 + 10").unwrap();
  {
    let mut locked = lockable.acquire_v8_lock();
    locked.execute_script("lock.js", "20 + 20").unwrap();
  }
  standard.execute_script("std2.js", "30 + 30").unwrap();
}
