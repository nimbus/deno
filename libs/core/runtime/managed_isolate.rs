// Copyright 2018-2026 the Deno authors. MIT license.
// Locker-aware isolate management for the Nimbus Deno fork.

use std::ops::Deref;
use std::ops::DerefMut;
use std::pin::Pin;

/// An isolate that is either auto-entered or cooperatively locked.
pub(crate) enum ManagedIsolate {
  /// The standard auto-entered isolate.
  Owned(v8::OwnedIsolate),
  /// An isolate that uses `v8::Locker` for cooperative scheduling.
  Lockable(LockerIsolate),
}

pub(crate) struct LockerIsolate {
  /// The active Locker. This field must drop before `unentered`.
  locker: Option<v8::Locker<'static>>,
  /// The pinned isolate that this struct owns.
  unentered: Pin<Box<v8::UnenteredIsolate>>,
}

impl LockerIsolate {
  pub fn new(params: v8::CreateParams) -> Self {
    // SAFETY: `LockerIsolate` owns this unentered isolate and enters it only
    // through the paired Locker below.
    let mut unentered = Box::pin(unsafe { v8::Isolate::new_unentered(params) });
    let unentered_ptr = unsafe {
      Pin::get_unchecked_mut(unentered.as_mut()) as *mut v8::UnenteredIsolate
    };
    // SAFETY: the pinned allocation stays live until after `locker` drops.
    let locker = unsafe { Some(v8::Locker::new(&mut *unentered_ptr)) };
    Self { locker, unentered }
  }

  pub fn acquire_lock(&mut self) {
    if self.locker.is_some() {
      return;
    }
    let unentered_ptr = unsafe {
      Pin::get_unchecked_mut(self.unentered.as_mut())
        as *mut v8::UnenteredIsolate
    };
    // SAFETY: the pinned allocation stays live and address-stable until after
    // the Locker drops.
    let locker = unsafe { v8::Locker::new(&mut *unentered_ptr) };
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
  }
}

impl Deref for ManagedIsolate {
  type Target = v8::Isolate;

  fn deref(&self) -> &Self::Target {
    match self {
      ManagedIsolate::Owned(isolate) => isolate,
      ManagedIsolate::Lockable(isolate) => {
        isolate.locker.as_ref().expect("V8 lock not held")
      }
    }
  }
}

impl DerefMut for ManagedIsolate {
  fn deref_mut(&mut self) -> &mut Self::Target {
    match self {
      ManagedIsolate::Owned(isolate) => isolate,
      ManagedIsolate::Lockable(isolate) => {
        isolate.locker.as_mut().expect("V8 lock not held")
      }
    }
  }
}

impl AsMut<v8::Isolate> for ManagedIsolate {
  fn as_mut(&mut self) -> &mut v8::Isolate {
    self
  }
}

impl ManagedIsolate {
  pub fn is_lockable(&self) -> bool {
    matches!(self, ManagedIsolate::Lockable(_))
  }

  pub fn is_lock_held(&self) -> bool {
    match self {
      ManagedIsolate::Owned(_) => true,
      ManagedIsolate::Lockable(isolate) => isolate.is_locked(),
    }
  }

  pub fn ensure_lock_held(&mut self) {
    if let ManagedIsolate::Lockable(isolate) = self {
      isolate.acquire_lock();
    }
  }

  pub fn release_lock(&mut self) -> bool {
    match self {
      ManagedIsolate::Owned(_) => false,
      ManagedIsolate::Lockable(isolate) => isolate.release_lock(),
    }
  }
}
