use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

#[derive(Debug)]
struct SharedHandleRecord {
    kind: String,
    payload: RefCell<Box<dyn Any>>,
    refcount: Cell<u32>,
}

/// Stores one closed emulated handle entry and its associated metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleEntry {
    pub value: u32,
    pub kind: String,
}

/// Allocates stable emulated handles for runtime objects and preserves alias refcounts.
#[derive(Debug, Default)]
pub struct HandleTable {
    next_handle: u32,
    entries: BTreeMap<u32, Rc<SharedHandleRecord>>,
}

impl HandleTable {
    /// Builds a new handle table starting from the requested base handle value.
    pub fn new(start: u32) -> Self {
        Self {
            next_handle: start,
            entries: BTreeMap::new(),
        }
    }

    /// Allocates a new handle for the requested object kind and payload.
    pub fn allocate<T: 'static>(&mut self, kind: &str, payload: T) -> u32 {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(4);
        self.entries.insert(
            handle,
            Rc::new(SharedHandleRecord {
                kind: kind.to_string(),
                payload: RefCell::new(Box::new(payload)),
                refcount: Cell::new(1),
            }),
        );
        handle
    }

    /// Replaces the payload stored behind an existing handle.
    pub fn set_payload<T: 'static>(&self, handle: u32, payload: T) -> bool {
        let Some(record) = self.entries.get(&handle) else {
            return false;
        };
        *record.payload.borrow_mut() = Box::new(payload);
        true
    }

    /// Returns the current handle kind when the handle exists.
    pub fn kind(&self, handle: u32) -> Option<&str> {
        self.entries.get(&handle).map(|record| record.kind.as_str())
    }

    /// Runs a typed read-only closure over one handle payload.
    pub fn with_payload<T: 'static, R, F: FnOnce(&T) -> R>(&self, handle: u32, f: F) -> Option<R> {
        let record = self.entries.get(&handle)?;
        let payload = record.payload.borrow();
        let payload = payload.as_ref().downcast_ref::<T>()?;
        Some(f(payload))
    }

    /// Runs a typed mutable closure over one handle payload.
    pub fn with_payload_mut<T: 'static, R, F: FnOnce(&mut T) -> R>(
        &self,
        handle: u32,
        f: F,
    ) -> Option<R> {
        let record = self.entries.get(&handle)?;
        let mut payload = record.payload.borrow_mut();
        let payload = payload.as_mut().downcast_mut::<T>()?;
        Some(f(payload))
    }

    /// Duplicates one existing handle so both handles share payload and refcount.
    pub fn duplicate(&mut self, handle: u32) -> Option<u32> {
        let record = self.entries.get(&handle)?.clone();
        record.refcount.set(record.refcount.get().saturating_add(1));
        let alias = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(4);
        self.entries.insert(alias, record);
        Some(alias)
    }

    /// Returns the current shared refcount for a handle.
    pub fn refcount(&self, handle: u32) -> u32 {
        self.entries
            .get(&handle)
            .map(|record| record.refcount.get())
            .unwrap_or(0)
    }

    /// Closes one handle and returns the removed entry plus whether it was the final alias.
    pub fn close_ex(&mut self, handle: u32) -> (Option<HandleEntry>, bool) {
        let Some(record) = self.entries.remove(&handle) else {
            return (None, false);
        };
        let current = record.refcount.get();
        let remaining = current.saturating_sub(1);
        record.refcount.set(remaining);
        (
            Some(HandleEntry {
                value: handle,
                kind: record.kind.clone(),
            }),
            remaining == 0,
        )
    }

    /// Closes one handle alias.
    pub fn close(&mut self, handle: u32) -> bool {
        self.close_ex(handle).0.is_some()
    }
}
