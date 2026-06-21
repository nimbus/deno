// Copyright 2018-2026 the Deno authors. MIT license.

use std::future::poll_fn;
use std::rc::Rc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Poll;

use deno_error::JsErrorBox;

use crate::JsRuntime;
use crate::JsRuntimeForSnapshot;
use crate::ModuleSpecifier;
use crate::RuntimeOptions;
use crate::error::CoreErrorKind;
use crate::error::ExtensionLazyInitCountMismatchError;
use crate::error::ExtensionLazyInitOrderMismatchError;
use crate::modules::StaticModuleLoader;
use crate::op2;
use crate::runtime::CreateRealmOptions;

static EXTENSION_JS_REPLAY_TEST_LOCK: Mutex<()> = Mutex::new(());

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

#[test]
fn create_realm_produces_fresh_global_context_with_core_ops() {
  #[allow(clippy::unnecessary_wraps, reason = "test op mirrors op2 API")]
  #[op2(fast)]
  #[number]
  fn op_realm_value() -> Result<i64, JsErrorBox> {
    Ok(7)
  }

  deno_core::extension!(test_ext, ops = [op_realm_value]);
  let mut runtime = JsRuntime::new(RuntimeOptions {
    extensions: vec![test_ext::init()],
    ..Default::default()
  });

  let main_realm = runtime.main_realm();
  main_realm
    .execute_script(
      runtime.v8_isolate(),
      "main.js",
      "globalThis.realmMarker = 'main';",
    )
    .unwrap();

  let fresh_realm = runtime.create_realm(Default::default()).unwrap();
  fresh_realm
    .execute_script(
      runtime.v8_isolate(),
      "fresh.js",
      r#"
        if ("realmMarker" in globalThis) {
          throw new Error("fresh realm inherited main global");
        }
        if (Deno.core.ops.op_realm_value() !== 7) {
          throw new Error("fresh realm did not install ops");
        }
        globalThis.realmMarker = "fresh";
      "#,
    )
    .unwrap();

  main_realm
    .execute_script(
      runtime.v8_isolate(),
      "main-check.js",
      r#"
        if (globalThis.realmMarker !== "main") {
          throw new Error("main realm was polluted");
        }
      "#,
    )
    .unwrap();
  fresh_realm
    .execute_script(
      runtime.v8_isolate(),
      "fresh-check.js",
      r#"
        if (globalThis.realmMarker !== "fresh") {
          throw new Error("fresh realm marker was not retained");
        }
      "#,
    )
    .unwrap();

  assert_eq!(fresh_realm.num_pending_ops(), 0);
  assert_eq!(fresh_realm.num_unrefed_ops(), 0);
}

#[test]
fn init_extension_js_in_realm_replays_extension_globals() {
  let _guard = EXTENSION_JS_REPLAY_TEST_LOCK.lock().unwrap();

  deno_core::extension!(
    realm_replay_ext,
    esm_entry_point = "ext:realm_replay_ext/entry.js",
    esm = ["ext:realm_replay_ext/entry.js" = {
      source = "globalThis.realmReplayModule = (globalThis.realmReplayModule ?? 0) + 1; export {};"
    }],
    js = ["ext:realm_replay_ext/script.js" = {
      source = "globalThis.realmReplayScript = (globalThis.realmReplayScript ?? 0) + 1;"
    }],
  );
  let mut runtime = JsRuntime::new(RuntimeOptions {
    extensions: vec![realm_replay_ext::init()],
    ..Default::default()
  });

  runtime
    .execute_script(
      "main-extension-check.js",
      r#"
        if (globalThis.realmReplayScript !== 1) {
          throw new Error(`main script count: ${globalThis.realmReplayScript}`);
        }
        if (globalThis.realmReplayModule !== 1) {
          throw new Error(`main module count: ${globalThis.realmReplayModule}`);
        }
      "#,
    )
    .unwrap();

  let fresh_realm = runtime.create_realm(Default::default()).unwrap();
  fresh_realm
    .execute_script(
      runtime.v8_isolate(),
      "fresh-before-extension-replay.js",
      r#"
        if ("realmReplayScript" in globalThis) {
          throw new Error("fresh realm inherited extension script global");
        }
        if ("realmReplayModule" in globalThis) {
          throw new Error("fresh realm inherited extension module global");
        }
      "#,
    )
    .unwrap();

  runtime
    .init_extension_js_in_realm(&fresh_realm)
    .expect("fresh realm extension JS should replay");
  fresh_realm
    .execute_script(
      runtime.v8_isolate(),
      "fresh-after-extension-replay.js",
      r#"
        if (globalThis.realmReplayScript !== 1) {
          throw new Error(`fresh script count: ${globalThis.realmReplayScript}`);
        }
        if (globalThis.realmReplayModule !== 1) {
          throw new Error(`fresh module count: ${globalThis.realmReplayModule}`);
        }
        globalThis.realmReplayScript = 9;
      "#,
    )
    .unwrap();

  runtime
    .execute_script(
      "main-extension-isolation-check.js",
      r#"
        if (globalThis.realmReplayScript !== 1) {
          throw new Error(`fresh realm polluted main script count: ${globalThis.realmReplayScript}`);
        }
      "#,
    )
    .unwrap();
}

#[test]
fn init_extension_js_in_realm_replays_snapshot_seeded_extension_globals() {
  let _guard = EXTENSION_JS_REPLAY_TEST_LOCK.lock().unwrap();

  deno_core::extension!(
    realm_replay_snapshot_ext,
    esm_entry_point = "ext:realm_replay_snapshot_ext/entry.js",
    esm = ["ext:realm_replay_snapshot_ext/entry.js" = {
      source = "globalThis.realmReplaySnapshotModule = (globalThis.realmReplaySnapshotModule ?? 0) + 1; export {};"
    }],
    js = ["ext:realm_replay_snapshot_ext/script.js" = {
      source = "globalThis.realmReplaySnapshotScript = (globalThis.realmReplaySnapshotScript ?? 0) + 1;"
    }],
  );

  let snapshot = {
    let runtime = JsRuntimeForSnapshot::new(RuntimeOptions {
      extensions: vec![realm_replay_snapshot_ext::init()],
      ..Default::default()
    });
    Box::leak(runtime.snapshot())
  };

  let mut runtime = JsRuntime::new(RuntimeOptions {
    startup_snapshot: Some(snapshot),
    extensions: vec![realm_replay_snapshot_ext::init()],
    ..Default::default()
  });
  runtime
    .execute_script(
      "main-snapshot-extension-check.js",
      r#"
        if (globalThis.realmReplaySnapshotScript !== 1) {
          throw new Error(`main snapshot script count: ${globalThis.realmReplaySnapshotScript}`);
        }
        if (globalThis.realmReplaySnapshotModule !== 1) {
          throw new Error(`main snapshot module count: ${globalThis.realmReplaySnapshotModule}`);
        }
      "#,
    )
    .unwrap();

  let fresh_realm = runtime.create_realm(Default::default()).unwrap();
  fresh_realm
    .execute_script(
      runtime.v8_isolate(),
      "fresh-snapshot-before-extension-replay.js",
      r#"
        if ("realmReplaySnapshotScript" in globalThis) {
          throw new Error("fresh realm inherited snapshotted extension script global");
        }
        if ("realmReplaySnapshotModule" in globalThis) {
          throw new Error("fresh realm inherited snapshotted extension module global");
        }
      "#,
    )
    .unwrap();

  runtime
    .init_extension_js_in_realm(&fresh_realm)
    .expect("fresh realm extension JS should replay after snapshot startup");
  fresh_realm
    .execute_script(
      runtime.v8_isolate(),
      "fresh-snapshot-after-extension-replay.js",
      r#"
        if (globalThis.realmReplaySnapshotScript !== 1) {
          throw new Error(`fresh snapshot script count: ${globalThis.realmReplaySnapshotScript}`);
        }
        if (globalThis.realmReplaySnapshotModule !== 1) {
          throw new Error(`fresh snapshot module count: ${globalThis.realmReplaySnapshotModule}`);
        }
      "#,
    )
    .unwrap();
}

#[test]
fn init_extension_js_in_realm_replays_snapshot_seeded_file_backed_extension_modules()
 {
  let _guard = EXTENSION_JS_REPLAY_TEST_LOCK.lock().unwrap();

  deno_core::extension!(
    realm_replay_snapshot_fs_ext,
    esm_entry_point = "ext:realm_replay_snapshot_fs_ext/entry.js",
    esm = ["ext:realm_replay_snapshot_fs_ext/entry.js" =
      "runtime/tests/testdata/realm_replay_snapshot_fs_entry.js"],
  );

  let snapshot = {
    let runtime = JsRuntimeForSnapshot::new(RuntimeOptions {
      extensions: vec![realm_replay_snapshot_fs_ext::init()],
      ..Default::default()
    });
    Box::leak(runtime.snapshot())
  };

  let mut runtime = JsRuntime::new(RuntimeOptions {
    startup_snapshot: Some(snapshot),
    extensions: vec![realm_replay_snapshot_fs_ext::init()],
    extension_replay_esm_sources: &[(
      "ext:realm_replay_snapshot_fs_ext/entry.js",
      include_str!("testdata/realm_replay_snapshot_fs_entry.js"),
    )],
    extension_replay_esm_entry_points: &[
      "ext:realm_replay_snapshot_fs_ext/entry.js",
    ],
    ..Default::default()
  });
  runtime
    .execute_script(
      "main-snapshot-fs-extension-check.js",
      r#"
        if (globalThis.realmReplaySnapshotFsModule !== 1) {
          throw new Error(`main file-backed snapshot module count: ${globalThis.realmReplaySnapshotFsModule}`);
        }
      "#,
    )
    .unwrap();

  let fresh_realm = runtime.create_realm(Default::default()).unwrap();
  fresh_realm
    .execute_script(
      runtime.v8_isolate(),
      "fresh-snapshot-fs-before-extension-replay.js",
      r#"
        if ("realmReplaySnapshotFsModule" in globalThis) {
          throw new Error("fresh realm inherited file-backed snapshotted extension module global");
        }
      "#,
    )
    .unwrap();

  runtime
    .init_extension_js_in_realm(&fresh_realm)
    .expect("fresh realm file-backed extension ESM should replay");
  fresh_realm
    .execute_script(
      runtime.v8_isolate(),
      "fresh-snapshot-fs-after-extension-replay.js",
      r#"
        if (globalThis.realmReplaySnapshotFsModule !== 1) {
          throw new Error(`fresh file-backed snapshot module count: ${globalThis.realmReplaySnapshotFsModule}`);
        }
      "#,
    )
    .unwrap();
}

#[tokio::test]
async fn create_realm_loads_modules_in_realm_module_map() {
  #[op2]
  #[number]
  async fn op_realm_async_value() -> Result<i64, JsErrorBox> {
    tokio::task::yield_now().await;
    Ok(19)
  }

  deno_core::extension!(realm_event_loop_ext, ops = [op_realm_async_value]);

  let main_specifier = ModuleSpecifier::parse("file:///main.js").unwrap();
  let dep_specifier = ModuleSpecifier::parse("file:///dep.js").unwrap();
  let loader = Rc::new(StaticModuleLoader::new([
    (
      main_specifier.clone(),
      r#"
        import { depLoadCount } from "./dep.js";
        globalThis.entryLoadCount = (globalThis.entryLoadCount ?? 0) + 1;
        globalThis.importMetaMain = import.meta.main;
        globalThis.asyncOpValue = await Deno.core.ops.op_realm_async_value();
        globalThis.observedDepLoadCount = depLoadCount;
      "#,
    ),
    (
      dep_specifier,
      r#"
        globalThis.depLoadCount = (globalThis.depLoadCount ?? 0) + 1;
        export const depLoadCount = globalThis.depLoadCount;
      "#,
    ),
  ]));
  let mut runtime = JsRuntime::new(RuntimeOptions {
    extensions: vec![realm_event_loop_ext::init()],
    module_loader: Some(loader.clone()),
    ..Default::default()
  });

  let first_realm = runtime
    .create_realm(CreateRealmOptions {
      module_loader: Some(loader.clone()),
    })
    .unwrap();
  let first_id = runtime
    .load_main_es_module_in_realm(&first_realm, &main_specifier)
    .await
    .unwrap();
  let first_evaluation = runtime.mod_evaluate_in_realm(&first_realm, first_id);
  runtime
    .run_event_loop_in_realm(&first_realm, Default::default())
    .await
    .unwrap();
  first_evaluation.await.unwrap();

  let second_realm = runtime
    .create_realm(CreateRealmOptions {
      module_loader: Some(loader.clone()),
    })
    .unwrap();
  let second_id = runtime
    .load_main_es_module_in_realm(&second_realm, &main_specifier)
    .await
    .unwrap();
  let second_evaluation =
    runtime.mod_evaluate_in_realm(&second_realm, second_id);
  runtime
    .run_event_loop_in_realm(&second_realm, Default::default())
    .await
    .unwrap();
  second_evaluation.await.unwrap();

  let fresh_promise = first_realm
    .execute_script(
      runtime.v8_isolate(),
      "first-realm-promise.js",
      r#"
        Deno.core.ops.op_realm_async_value().then((value) => {
          globalThis.promiseResolvedValue = value;
          return value;
        })
      "#,
    )
    .unwrap();
  let resolve = runtime.resolve_in_realm(&first_realm, fresh_promise);
  runtime
    .with_event_loop_promise_in_realm(&first_realm, resolve, Default::default())
    .await
    .unwrap();

  for (realm, script_name) in [
    (&first_realm, "first-realm-check.js"),
    (&second_realm, "second-realm-check.js"),
  ] {
    realm
      .execute_script(
        runtime.v8_isolate(),
        script_name,
        r#"
          if (globalThis.entryLoadCount !== 1) {
            throw new Error(`entry load count leaked: ${globalThis.entryLoadCount}`);
          }
          if (globalThis.importMetaMain !== true) {
            throw new Error(`import.meta.main was not preserved: ${globalThis.importMetaMain}`);
          }
          if (globalThis.asyncOpValue !== 19) {
            throw new Error(`realm async op did not resolve: ${globalThis.asyncOpValue}`);
          }
          if (globalThis.depLoadCount !== 1) {
            throw new Error(`dependency load count leaked: ${globalThis.depLoadCount}`);
          }
          if (globalThis.observedDepLoadCount !== 1) {
            throw new Error(`dependency export leaked: ${globalThis.observedDepLoadCount}`);
          }
        "#,
      )
      .unwrap();
  }
  first_realm
    .execute_script(
      runtime.v8_isolate(),
      "first-realm-promise-check.js",
      r#"
        if (globalThis.promiseResolvedValue !== 19) {
          throw new Error(`realm promise did not resolve: ${globalThis.promiseResolvedValue}`);
        }
      "#,
    )
    .unwrap();

  runtime
    .execute_script(
      "main-realm-check.js",
      r#"
        if ("entryLoadCount" in globalThis || "depLoadCount" in globalThis) {
          throw new Error("realm module globals polluted the main realm");
        }
      "#,
    )
    .unwrap();
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
