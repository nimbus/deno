// Copyright 2018-2026 the Deno authors. MIT license.
// Locker-aware isolate management for the agentstation/deno fork.

use std::ops::Deref;
use std::ops::DerefMut;

/// An isolate that is either auto-entered (`OwnedIsolate`) or cooperatively
/// locked (`UnenteredIsolate` + `Locker`).
///
/// Both variants deref to `v8::Isolate`, so existing deno code can keep using
/// `&mut v8::Isolate` call sites regardless of which variant is active.
pub(crate) enum ManagedIsolate {
  /// Standard auto-entered isolate (upstream default path).
  Owned(v8::OwnedIsolate),
  /// Locker-based isolate for cooperative same-thread scheduling.
  ///
  /// The `Locker` borrows from the `UnenteredIsolate` via a raw pointer with
  /// lifetime erased to `'static`. Safety invariant: the `Locker` is always
  /// dropped before the `UnenteredIsolate`.
  Lockable(LockerIsolate),
}

pub(crate) struct LockerIsolate {
  /// Raw pointer to the heap-allocated `UnenteredIsolate`.
  /// Owned by this struct and freed on drop.
  unentered: *mut v8::UnenteredIsolate,
  /// Locker that enters the isolate.
  ///
  /// The lifetime is erased to `'static` because the locker and unentered
  /// isolate are co-owned by this struct and we guarantee the locker is always
  /// dropped first.
  locker: Option<v8::Locker<'static>>,
}

impl LockerIsolate {
  pub fn new(params: v8::CreateParams) -> Self {
    let unentered = Box::into_raw(Box::new(v8::Isolate::new_unentered(params)));
    let locker = unsafe { Some(v8::Locker::new(&mut *unentered)) };
    Self { unentered, locker }
  }

  pub fn acquire_lock(&mut self) {
    if self.locker.is_some() {
      return;
    }
    let locker = unsafe { v8::Locker::new(&mut *self.unentered) };
    self.locker = Some(locker);
  }

  pub fn release_lock(&mut self) -> bool {
    let Some(locker) = self.locker.take() else {
      return false;
    };
    drop(locker);
    true
  }

  pub fn is_locked(&self) -> bool {
    self.locker.is_some()
  }
}

impl Drop for LockerIsolate {
  fn drop(&mut self) {
    self.locker.take();
    unsafe {
      drop(Box::from_raw(self.unentered));
    }
  }
}

impl Deref for ManagedIsolate {
  type Target = v8::Isolate;

  fn deref(&self) -> &Self::Target {
    match self {
      ManagedIsolate::Owned(iso) => iso,
      ManagedIsolate::Lockable(li) => {
        li.locker.as_ref().expect("V8 lock not held")
      }
    }
  }
}

impl DerefMut for ManagedIsolate {
  fn deref_mut(&mut self) -> &mut Self::Target {
    match self {
      ManagedIsolate::Owned(iso) => iso,
      ManagedIsolate::Lockable(li) => {
        li.locker.as_mut().expect("V8 lock not held")
      }
    }
  }
}

impl AsMut<v8::Isolate> for ManagedIsolate {
  fn as_mut(&mut self) -> &mut v8::Isolate {
    &mut **self
  }
}

impl ManagedIsolate {
  pub fn is_lockable(&self) -> bool {
    matches!(self, ManagedIsolate::Lockable(_))
  }

  pub fn is_lock_held(&self) -> bool {
    match self {
      ManagedIsolate::Owned(_) => true,
      ManagedIsolate::Lockable(li) => li.is_locked(),
    }
  }

  pub fn ensure_lock_held(&mut self) {
    if let ManagedIsolate::Lockable(li) = self {
      li.acquire_lock();
    }
  }

  pub fn release_lock(&mut self) -> bool {
    match self {
      ManagedIsolate::Owned(_) => false,
      ManagedIsolate::Lockable(li) => li.release_lock(),
    }
  }
}
