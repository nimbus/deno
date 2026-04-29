// Copyright 2018-2026 the Deno authors. MIT license.

use std::future::poll_fn;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Poll;

use crate::JsRuntime;
use crate::JsRuntimeForSnapshot;
use crate::RuntimeOptions;
use crate::error::CoreErrorKind;
use crate::error::ExtensionLazyInitCountMismatchError;
use crate::error::ExtensionLazyInitOrderMismatchError;
use crate::modules::StaticModuleLoader;
use crate::op2;
use crate::url::Url;
use deno_error::JsErrorBox;

fn eval_integer(runtime: &mut JsRuntime, expr: &str) -> i64 {
  let value = runtime.execute_script("", expr.to_string()).unwrap();
  deno_core::scope!(scope, runtime);
  let value = v8::Local::new(scope, value);
  value.integer_value(scope).unwrap()
}

#[test]
fn test_set_format_exception_callback_realms() {
  let mut runtime = JsRuntime::new(RuntimeOptions::default());
  let main_realm = runtime.main_realm();

  let realm_expectations = &[(&main_realm, "main_realm")];

  // Set up format exception callbacks.
  for (realm, realm_name) in realm_expectations {
    realm
      .execute_script(
        runtime.v8_isolate(),
        "",
        format!(
          r#"
          Deno.core.ops.op_set_format_exception_callback((error) => {{
            Deno.core.isNativeError(error); // test reentrancy
            return `{realm_name} / ${{error}}`;
          }});
        "#
        ),
      )
      .unwrap();
  }

  for (realm, realm_name) in realm_expectations {
    // Immediate exceptions
    {
      let result = realm.execute_script(
        runtime.v8_isolate(),
        "",
        format!("throw new Error('{realm_name}');"),
      );
      assert!(result.is_err());
      let error = result.unwrap_err();
      assert_eq!(
        error.exception_message,
        format!("{realm_name} / Error: {realm_name}")
      );
    }

    // Promise rejections
    {
      realm
        .execute_script(
          runtime.v8_isolate(),
          "",
          format!("Promise.reject(new Error('{realm_name}'));"),
        )
        .unwrap();

      let result =
        futures::executor::block_on(runtime.run_event_loop(Default::default()));
      assert!(result.is_err());
      let CoreErrorKind::Js(error) = result.unwrap_err().into_kind() else {
        unreachable!()
      };
      assert_eq!(
        error.exception_message,
        format!("Uncaught (in promise) {realm_name} / Error: {realm_name}")
      );
    }
  }
}

#[tokio::test]
async fn js_realm_ref_unref_ops() {
  // Never resolves.
  #[op2]
  async fn op_pending() {
    std::future::pending().await
  }

  deno_core::extension!(test_ext, ops = [op_pending]);
  let mut runtime = JsRuntime::new(RuntimeOptions {
    extensions: vec![test_ext::init()],
    ..Default::default()
  });

  poll_fn(move |cx| {
    let main_realm = runtime.main_realm();

    main_realm
      .execute_script(
        runtime.v8_isolate(),
        "",
        r#"
        const { op_pending } = Deno.core.ops;
        var promise = op_pending();
        "#,
      )
      .unwrap();
    assert!(matches!(
      runtime.poll_event_loop(cx, Default::default()),
      Poll::Pending
    ));

    main_realm
      .execute_script(
        runtime.v8_isolate(),
        "",
        r#"
          Deno.core.unrefOpPromise(promise);
        "#,
      )
      .unwrap();

    assert!(matches!(
      runtime.poll_event_loop(cx, Default::default()),
      Poll::Ready(Ok(()))
    ));
    Poll::Ready(())
  })
  .await;
}

#[test]
fn es_snapshot() {
  let startup_data = {
    deno_core::extension!(
      module_snapshot,
      esm_entry_point = "mod:test",
      esm = ["mod:test" =
        { source = "globalThis.TEST = 'foo'; export const TEST = 'bar';" },]
    );

    let runtime = JsRuntimeForSnapshot::new(RuntimeOptions {
      extensions: vec![module_snapshot::init()],
      module_loader: Some(Rc::new(StaticModuleLoader::default())),
      ..Default::default()
    });
    runtime.snapshot()
  };
  let snapshot = Box::leak(startup_data);
  let mut runtime = JsRuntime::new(RuntimeOptions {
    module_loader: None,
    startup_snapshot: Some(snapshot),
    ..Default::default()
  });

  // The module was evaluated ahead of time
  {
    let global_test = runtime.execute_script("", "globalThis.TEST").unwrap();
    deno_core::scope!(scope, runtime);
    let global_test = v8::Local::new(scope, global_test);
    assert!(global_test.is_string());
    assert_eq!(global_test.to_rust_string_lossy(scope).as_str(), "foo");
  }

  // The module can be imported
  {
    let test_export_promise = runtime
      .execute_script("", "import('mod:test').then(module => module.TEST)")
      .unwrap();
    #[allow(deprecated, reason = "test code")]
    let test_export =
      futures::executor::block_on(runtime.resolve_value(test_export_promise))
        .unwrap();

    deno_core::scope!(scope, runtime);
    let test_export = v8::Local::new(scope, test_export);
    assert!(test_export.is_string());
    assert_eq!(test_export.to_rust_string_lossy(scope).as_str(), "bar");
  }
}

#[test]
fn lazy() {
  static CALLED: AtomicBool = AtomicBool::new(false);

  deno_core::extension!(
    lazy_ext,
    options = {
      a: String,
      b: bool,
    },
    state = |_state, _options| {
      CALLED.store(true, Ordering::Relaxed);
    },
  );

  deno_core::extension!(lazy_bad, state = |_state| {},);

  let extensions = vec![lazy_ext::lazy_init()];

  let runtime = JsRuntime::new(RuntimeOptions {
    extensions,
    ..Default::default()
  });

  let err = runtime
    .lazy_init_extensions(vec![])
    .unwrap_err()
    .into_kind();
  assert!(matches!(
    err,
    CoreErrorKind::ExtensionLazyInitCountMismatch(
      ExtensionLazyInitCountMismatchError {
        lazy_init_extensions_len: 1,
        arguments_len: 0,
      }
    )
  ));

  let err = runtime
    .lazy_init_extensions(vec![lazy_bad::args()])
    .unwrap_err()
    .into_kind();
  assert!(matches!(
    err,
    CoreErrorKind::ExtensionLazyInitOrderMismatch(
      ExtensionLazyInitOrderMismatchError {
        expected: "lazy_ext",
        actual: "lazy_bad",
      }
    )
  ));

  assert!(!CALLED.load(Ordering::Relaxed));

  runtime
    .lazy_init_extensions(vec![lazy_ext::args("".into(), true)])
    .unwrap();

  assert!(CALLED.load(Ordering::Relaxed));
}

// ============================================================================
// Warm reuse tests
// ============================================================================

#[tokio::test]
async fn warm_reuse_reset_preserves_evaluated_modules() {
  let mut runtime = JsRuntime::new(RuntimeOptions::default());

  let specifier = Url::parse("file:///mod.js").unwrap();
  let module_source = r#"
    globalThis.counter = (globalThis.counter ?? 0) + 1;
    export const counter = globalThis.counter;
  "#;

  let module_id = runtime
    .load_main_es_module_from_code(&specifier, module_source)
    .await
    .unwrap();
  let evaluation = runtime.mod_evaluate(module_id);
  runtime.run_event_loop(Default::default()).await.unwrap();
  evaluation.await.unwrap();

  assert_eq!(eval_integer(&mut runtime, "globalThis.counter"), 1);
  assert!(runtime.is_warm_reuse_safe());

  runtime.reset_request_state().unwrap();

  assert_eq!(eval_integer(&mut runtime, "globalThis.counter"), 1);
}

#[tokio::test]
async fn warm_reuse_reset_clears_exception_state() {
  let mut runtime = JsRuntime::new(RuntimeOptions::default());

  runtime.execute_script("", "1 + 1".to_string()).unwrap();

  assert!(runtime.is_warm_reuse_safe());
  runtime.reset_request_state().unwrap();

  assert_eq!(eval_integer(&mut runtime, "2 + 2"), 4);
}

#[tokio::test]
async fn warm_reuse_quiescent_after_async_op() {
  #[op2]
  async fn op_warm_test_async() -> Result<i32, JsErrorBox> {
    tokio::task::yield_now().await;
    Ok(42)
  }
  deno_core::extension!(warm_test_ext, ops = [op_warm_test_async]);

  let mut runtime = JsRuntime::new(RuntimeOptions {
    extensions: vec![warm_test_ext::init()],
    ..Default::default()
  });

  let promise = runtime
    .execute_script(
      "",
      "(async () => { return await Deno.core.ops.op_warm_test_async(); })()"
        .to_string(),
    )
    .unwrap();

  runtime.run_event_loop(Default::default()).await.unwrap();

  {
    deno_core::scope!(scope, &mut runtime);
    let local = v8::Local::new(scope, promise);
    assert!(local.is_promise());
    let p = v8::Local::<v8::Promise>::try_from(local).unwrap();
    assert_eq!(p.state(), v8::PromiseState::Fulfilled);
  }

  assert!(runtime.is_warm_reuse_safe());
  runtime.reset_request_state().unwrap();
  assert_eq!(eval_integer(&mut runtime, "1 + 1"), 2);
}

#[tokio::test]
async fn warm_reuse_repeated_cycles() {
  let mut runtime = JsRuntime::new(RuntimeOptions::default());

  for cycle in 0..8 {
    let result = eval_integer(&mut runtime, &format!("{cycle} + 1"));
    assert_eq!(result, cycle + 1);
    assert!(
      runtime.is_warm_reuse_safe(),
      "cycle {cycle}: runtime should be quiescent after sync eval"
    );
    runtime.reset_request_state().unwrap_or_else(|e| {
      panic!("cycle {cycle}: reset_request_state should succeed: {e}")
    });
  }
}

#[tokio::test]
async fn warm_reuse_rejects_pending_op() {
  #[op2]
  async fn op_warm_test_never() -> Result<(), JsErrorBox> {
    std::future::pending::<()>().await;
    Ok(())
  }
  deno_core::extension!(warm_never_ext, ops = [op_warm_test_never]);

  let mut runtime = JsRuntime::new(RuntimeOptions {
    extensions: vec![warm_never_ext::init()],
    ..Default::default()
  });

  runtime
    .execute_script("", "Deno.core.ops.op_warm_test_never()".to_string())
    .unwrap();

  poll_fn(|cx| {
    let _ = runtime.poll_event_loop(cx, Default::default());
    Poll::Ready(())
  })
  .await;

  assert!(!runtime.is_warm_reuse_safe());
  let err = runtime.reset_request_state().unwrap_err();
  assert!(
    err.to_string().contains("fully quiescent"),
    "error should mention quiescence: {err}"
  );
}

#[tokio::test]
async fn warm_reuse_rejects_scheduled_tick() {
  let mut runtime = JsRuntime::new(RuntimeOptions::default());

  runtime
    .execute_script("", "Deno.core.setHasTickScheduled(true)".to_string())
    .unwrap();

  assert!(!runtime.is_warm_reuse_safe());

  runtime
    .execute_script("", "Deno.core.setHasTickScheduled(false)".to_string())
    .unwrap();

  assert!(runtime.is_warm_reuse_safe());
}

#[test]
fn warm_reuse_with_locker() {
  let worker_thread = std::thread::spawn(|| {
    let rt = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    rt.block_on(async {
      let mut runtime = JsRuntime::new(RuntimeOptions {
        use_locker: true,
        ..Default::default()
      });

      runtime
        .execute_script("", "globalThis.warmCounter = 0".to_string())
        .unwrap();

      for cycle in 0..4 {
        runtime
          .execute_script("", "globalThis.warmCounter++".to_string())
          .unwrap();

        assert!(
          runtime.is_warm_reuse_safe(),
          "cycle {cycle}: locker runtime should be quiescent"
        );
        runtime.reset_request_state().unwrap_or_else(|e| {
          panic!("cycle {cycle}: reset should succeed with locker: {e}")
        });
      }

      assert_eq!(eval_integer(&mut runtime, "globalThis.warmCounter"), 4);
    });
  });
  worker_thread.join().unwrap();
}

#[test]
fn warm_reuse_with_locker_async_ops() {
  #[op2]
  async fn op_warm_locker_async() -> Result<i32, JsErrorBox> {
    tokio::task::yield_now().await;
    Ok(99)
  }
  deno_core::extension!(warm_locker_ext, ops = [op_warm_locker_async]);

  let worker_thread = std::thread::spawn(|| {
    let rt = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    rt.block_on(async {
      let mut runtime = JsRuntime::new(RuntimeOptions {
        use_locker: true,
        extensions: vec![warm_locker_ext::init()],
        ..Default::default()
      });

      for cycle in 0..4 {
        let promise = runtime
          .execute_script(
            "",
            "(async () => { return await Deno.core.ops.op_warm_locker_async(); })()"
              .to_string(),
          )
          .unwrap();

        runtime.run_event_loop(Default::default()).await.unwrap();

        {
          deno_core::scope!(scope, &mut runtime);
          let local = v8::Local::new(scope, promise);
          let p = v8::Local::<v8::Promise>::try_from(local).unwrap();
          assert_eq!(p.state(), v8::PromiseState::Fulfilled);
          assert_eq!(p.result(scope).int32_value(scope).unwrap(), 99);
        }

        assert!(
          runtime.is_warm_reuse_safe(),
          "cycle {cycle}: should be quiescent after async op"
        );
        runtime.reset_request_state().unwrap_or_else(|e| {
          panic!("cycle {cycle}: reset should succeed: {e}")
        });
      }
    });
  });
  worker_thread.join().unwrap();
}
