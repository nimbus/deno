// Copyright 2018-2026 the Deno authors. MIT license.

//! The Node.js "arrow" of an exception: the `file:line` header, the source
//! line and the caret underline that Node.js prints above an uncaught
//! exception and prepends to the stack of an error that escapes `node:vm`.
//!
//! Port of `GetErrorSource`, `AppendExceptionLine` and `DecorateErrorStack`
//! from Node.js `src/node_errors.cc`. Node.js knows two arrows:
//!
//! - The stored arrow: `node:vm` stores it on an object that a script throws
//!   ([`decorate_error_stack`]), and the first one is kept.
//! - The fatal message arrow: the location of the V8 message of an exception
//!   when it becomes fatal, which is the location of the last throw. The
//!   runtime catches most exceptions in JavaScript, where that message is
//!   lost, so it is recorded where an exception leaves native code:
//!   [`op_node_apply_recording_error_arrow`], and `node:vm` for a primitive.
//!
//! The fatal exception report reads them back through [`op_node_error_arrow`]
//! and [`op_node_fatal_message_arrow`].

use deno_core::error::JsError;
use deno_core::op2;
use deno_core::v8;

const ARROW_MESSAGE_KEY: &str = "node:arrowMessage";
const DECORATED_KEY: &str = "node:decorated";
const FATAL_MESSAGE_ARROW_KEY: &str = "node:fatalMessageArrow";

/// Node.js caps the underline at this many bytes.
const UNDERLINE_LIMIT: usize = 1020;

/// The fatal message arrow of the last primitive that was thrown. A primitive
/// cannot hold a private property, so the arrow is kept here and matched by
/// value when the primitive becomes fatal.
struct FatalPrimitiveArrow {
  key: PrimitiveKey,
  arrow: String,
}

#[derive(PartialEq)]
enum PrimitiveKey {
  Undefined,
  Null,
  Boolean(bool),
  Number(u64),
  String(String),
  BigInt(String),
}

impl PrimitiveKey {
  fn from_value(
    scope: &mut v8::PinScope<'_, '_>,
    value: v8::Local<v8::Value>,
  ) -> Option<Self> {
    if value.is_undefined() {
      Some(Self::Undefined)
    } else if value.is_null() {
      Some(Self::Null)
    } else if value.is_boolean() {
      Some(Self::Boolean(value.is_true()))
    } else if let Ok(number) = v8::Local::<v8::Number>::try_from(value) {
      Some(Self::Number(number.value().to_bits()))
    } else if let Ok(string) = v8::Local::<v8::String>::try_from(value) {
      Some(Self::String(string.to_rust_string_lossy(scope)))
    } else if let Ok(bigint) = v8::Local::<v8::BigInt>::try_from(value) {
      Some(Self::BigInt(bigint.to_rust_string_lossy(scope)))
    } else {
      // Symbols have no identity that outlives the handle.
      None
    }
  }
}

fn private_key<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  name: &str,
) -> v8::Local<'s, v8::Private> {
  let name = v8::String::new(scope, name).unwrap();
  v8::Private::for_api(scope, Some(name))
}

/// Builds the arrow for `message`: `file:line\nsource line\n` and, when the
/// columns are in range, a caret underline and a newline.
pub fn get_error_source(
  scope: &mut v8::PinScope<'_, '_>,
  message: v8::Local<v8::Message>,
) -> Option<String> {
  let source_line = message
    .get_source_line(scope)
    .map(|line| line.to_rust_string_lossy(scope))
    .unwrap_or_default();
  if source_line.contains("node-do-not-add-exception-line") {
    return None;
  }

  let filename = match message.get_script_resource_name(scope) {
    Some(name) if !name.is_undefined() => name.to_rust_string_lossy(scope),
    _ => "<anonymous_script>".to_string(),
  };
  let line_number = message.get_line_number(scope).unwrap_or(0);
  let mut arrow = format!("{filename}:{line_number}\n{source_line}\n");

  // Like Node.js, compare V8 columns with UTF-8 byte offsets.
  let start = message.get_start_column();
  let end = message.get_end_column();
  let bytes = source_line.as_bytes();
  if start > end || end > bytes.len() {
    return Some(arrow);
  }
  let mut underline = Vec::with_capacity(end.min(UNDERLINE_LIMIT) + 1);
  for &byte in &bytes[..start] {
    if byte == 0 || underline.len() >= UNDERLINE_LIMIT {
      break;
    }
    underline.push(if byte == b'\t' { b'\t' } else { b' ' });
  }
  for &byte in &bytes[start..end] {
    if byte == 0 || underline.len() >= UNDERLINE_LIMIT {
      break;
    }
    underline.push(b'^');
  }
  underline.push(b'\n');
  // The underline holds only ASCII bytes.
  arrow.push_str(std::str::from_utf8(&underline).unwrap());
  Some(arrow)
}

/// Records `arrow` as the fatal message arrow of `exception`, or removes the
/// fatal message arrow of `exception` when `arrow` is `None`. Like the V8
/// message, the last record replaces an earlier one.
fn set_fatal_message_arrow(
  scope: &mut v8::PinScope<'_, '_>,
  exception: v8::Local<v8::Value>,
  arrow: Option<String>,
) {
  let Ok(err_obj) = v8::Local::<v8::Object>::try_from(exception) else {
    let key = PrimitiveKey::from_value(scope, exception);
    match (key, arrow) {
      (Some(key), Some(arrow)) => {
        scope.set_slot(FatalPrimitiveArrow { key, arrow });
      }
      (key, _) => {
        let stale = scope
          .get_slot::<FatalPrimitiveArrow>()
          .is_some_and(|stored| key.as_ref().is_none_or(|k| *k == stored.key));
        if stale {
          scope.remove_slot::<FatalPrimitiveArrow>();
        }
      }
    }
    return;
  };

  let key = private_key(scope, FATAL_MESSAGE_ARROW_KEY);
  match arrow {
    Some(arrow) => {
      let arrow = v8::String::new(scope, &arrow).unwrap().into();
      err_obj.set_private(scope, key, arrow);
    }
    None => {
      err_obj.delete_private(scope, key);
    }
  }
}

/// Records the arrow of an exception that escaped a `node:vm` script. An
/// object keeps the first arrow that is stored on it and, when its stack is a
/// string, gets the arrow prepended to the stack. A primitive gets the arrow
/// as its fatal message arrow, because V8 keeps the message of a rethrown
/// primitive.
pub fn decorate_error_stack<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  exception: v8::Local<'s, v8::Value>,
  message: v8::Local<'s, v8::Message>,
) {
  let Ok(err_obj) = v8::Local::<v8::Object>::try_from(exception) else {
    let arrow = get_error_source(scope, message);
    set_fatal_message_arrow(scope, exception, arrow);
    return;
  };

  let decorated_key = private_key(scope, DECORATED_KEY);
  if err_obj
    .get_private(scope, decorated_key)
    .is_some_and(|value| value.is_true())
  {
    return;
  }

  let arrow_key = private_key(scope, ARROW_MESSAGE_KEY);
  let arrow = match err_obj.get_private(scope, arrow_key) {
    Some(value) if value.is_string() => value,
    _ => {
      let Some(arrow) = get_error_source(scope, message) else {
        return;
      };
      let arrow = v8::String::new(scope, &arrow).unwrap().into();
      err_obj.set_private(scope, arrow_key, arrow);
      arrow
    }
  };

  // Like Node.js, ignore exceptions that the stack accessor throws.
  v8::tc_scope!(let scope, scope);
  let stack_key = v8::String::new_external_onebyte_static(scope, b"stack")
    .unwrap()
    .into();
  let Some(stack) = err_obj.get(scope, stack_key) else {
    return;
  };
  let Ok(stack) = v8::Local::<v8::String>::try_from(stack) else {
    return;
  };
  let arrow = arrow.to_rust_string_lossy(scope);
  let stack = stack.to_rust_string_lossy(scope);
  let decorated_stack =
    v8::String::new(scope, &format!("{arrow}\n{stack}")).unwrap();
  err_obj.set(scope, stack_key, decorated_stack.into());
  let decorated_key = private_key(scope, DECORATED_KEY);
  let true_value = v8::Boolean::new(scope, true).into();
  err_obj.set_private(scope, decorated_key, true_value);
}

/// Calls `func` like `Reflect.apply`. If the call throws, records the
/// location of the throw as the fatal message arrow of the exception and
/// rethrows the exception. A throw inside the runtime gets no arrow: its
/// source is not the Node.js source, so the report uses a user frame of the
/// stack instead.
#[op2(reentrant)]
pub fn op_node_apply_recording_error_arrow<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  func: v8::Local<'s, v8::Function>,
  this: v8::Local<'s, v8::Value>,
  args: v8::Local<'s, v8::Array>,
) -> v8::Local<'s, v8::Value> {
  let args = (0..args.length())
    .map(|i| {
      args
        .get_index(scope, i)
        .unwrap_or_else(|| v8::undefined(scope).into())
    })
    .collect::<Vec<_>>();

  v8::tc_scope!(let scope, scope);
  if let Some(result) = func.call(scope, this, &args) {
    return result;
  }
  if !scope.has_terminated()
    && let Some(exception) = scope.exception()
  {
    let arrow = scope
      .message()
      .filter(|message| !is_runtime_resource(scope, *message))
      .and_then(|message| get_source_mapped_error_source(scope, message));
    set_fatal_message_arrow(scope, exception, arrow);
  }
  scope.rethrow();
  v8::undefined(scope).into()
}

/// Like [`get_error_source`], but at the source-mapped location of
/// `message`. The runtime compiles TypeScript to JavaScript, while Node.js
/// strips the types in place, so the arrow of a compiled script shows the
/// original source line, with a caret at the original column.
fn get_source_mapped_error_source<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  message: v8::Local<'s, v8::Message>,
) -> Option<String> {
  let resource_name = message
    .get_script_resource_name(scope)
    .map(|name| name.to_rust_string_lossy(scope));
  let line_number = message.get_line_number(scope).map(|line| line as i64);
  let column_number = message.get_start_column() as i64 + 1;
  let js_error = JsError::from_v8_message(scope, message);
  let Some(frame) = js_error.frames.first() else {
    return get_error_source(scope, message);
  };
  if frame.file_name == resource_name
    && frame.line_number == line_number
    && frame.column_number == Some(column_number)
  {
    return get_error_source(scope, message);
  }

  let file_name = frame.file_name.as_deref()?;
  let line_number = frame.line_number?;
  let source_line = js_error.source_line.as_deref()?;
  let mut arrow = format!("{file_name}:{line_number}\n{source_line}\n");
  let start = frame.column_number? - 1;
  if start < 0 || start as usize >= source_line.chars().count() {
    return Some(arrow);
  }
  for c in source_line.chars().take(start as usize) {
    arrow.push(if c == '\t' { '\t' } else { ' ' });
  }
  arrow.push_str("^\n");
  Some(arrow)
}

fn is_runtime_resource(
  scope: &mut v8::PinScope<'_, '_>,
  message: v8::Local<v8::Message>,
) -> bool {
  message
    .get_script_resource_name(scope)
    .map(|name| name.to_rust_string_lossy(scope))
    .is_some_and(|name| name.starts_with("ext:") || name.starts_with("node:"))
}

/// Returns the arrow that is stored on `value`: a string when an arrow is
/// stored, `null` when the stack of `value` already holds it, and
/// `undefined` otherwise.
#[op2]
pub fn op_node_error_arrow<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  value: v8::Local<'s, v8::Value>,
) -> v8::Local<'s, v8::Value> {
  let Ok(err_obj) = v8::Local::<v8::Object>::try_from(value) else {
    return v8::undefined(scope).into();
  };

  let decorated_key = private_key(scope, DECORATED_KEY);
  if err_obj
    .get_private(scope, decorated_key)
    .is_some_and(|value| value.is_true())
  {
    return v8::null(scope).into();
  }
  let arrow_key = private_key(scope, ARROW_MESSAGE_KEY);
  match err_obj.get_private(scope, arrow_key) {
    Some(arrow) if arrow.is_string() => arrow,
    _ => v8::undefined(scope).into(),
  }
}

/// Returns the fatal message arrow of `value` as a string, or `undefined`
/// when none is known.
#[op2]
pub fn op_node_fatal_message_arrow<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  value: v8::Local<'s, v8::Value>,
) -> v8::Local<'s, v8::Value> {
  let Ok(err_obj) = v8::Local::<v8::Object>::try_from(value) else {
    let key = PrimitiveKey::from_value(scope, value);
    let arrow = scope
      .get_slot::<FatalPrimitiveArrow>()
      .filter(|stored| Some(&stored.key) == key.as_ref())
      .map(|stored| stored.arrow.clone());
    return match arrow {
      Some(arrow) => v8::String::new(scope, &arrow).unwrap().into(),
      None => v8::undefined(scope).into(),
    };
  };

  let key = private_key(scope, FATAL_MESSAGE_ARROW_KEY);
  match err_obj.get_private(scope, key) {
    Some(arrow) if arrow.is_string() => arrow,
    _ => v8::undefined(scope).into(),
  }
}
