use std::collections::{BTreeMap, BTreeSet};

/// Tracks allocated TLS slots and their current emulated values.
#[derive(Debug, Default)]
pub struct TlsManager {
    next_slot: usize,
    allocated: BTreeSet<usize>,
    thread_values: BTreeMap<u32, BTreeMap<usize, u64>>,
}

impl TlsManager {
    /// Builds an empty TLS manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates one TLS slot.
    pub fn alloc(&mut self) -> Option<usize> {
        self.alloc_for_thread(0)
    }

    /// Allocates one TLS slot for a specific emulated thread.
    pub fn alloc_for_thread(&mut self, thread_id: u32) -> Option<usize> {
        let slot = self.next_slot;
        self.next_slot = self.next_slot.saturating_add(1);
        self.allocated.insert(slot);
        self.thread_values
            .entry(thread_id)
            .or_default()
            .entry(slot)
            .or_insert(0);
        Some(slot)
    }

    /// Releases one TLS slot and clears any per-thread values associated with it.
    pub fn free(&mut self, slot: usize) -> bool {
        if !self.allocated.remove(&slot) {
            return false;
        }
        for values in self.thread_values.values_mut() {
            values.remove(&slot);
        }
        true
    }

    /// Stores a TLS value for an allocated slot.
    pub fn set_value(&mut self, slot: usize, value: u64) -> bool {
        self.set_value_for_thread(0, slot, value)
    }

    /// Stores a TLS value for a specific emulated thread.
    pub fn set_value_for_thread(&mut self, thread_id: u32, slot: usize, value: u64) -> bool {
        if !self.allocated.contains(&slot) {
            return false;
        }
        self.thread_values
            .entry(thread_id)
            .or_default()
            .insert(slot, value);
        true
    }

    /// Reads a TLS slot value, defaulting to zero like Win32.
    pub fn get_value(&self, slot: usize) -> u64 {
        self.get_value_for_thread(0, slot)
    }

    /// Reads a TLS slot value for a specific emulated thread.
    pub fn get_value_for_thread(&self, thread_id: u32, slot: usize) -> u64 {
        self.thread_values
            .get(&thread_id)
            .and_then(|values| values.get(&slot))
            .copied()
            .unwrap_or(0)
    }

    /// Returns the allocated slot set for environment mirroring.
    pub fn allocated_snapshot(&self) -> BTreeSet<usize> {
        self.allocated.clone()
    }

    /// Returns the current slot-value map for environment mirroring.
    pub fn snapshot(&self) -> BTreeMap<usize, u64> {
        self.snapshot_for_thread(0)
    }

    /// Returns the current slot-value map for one emulated thread.
    pub fn snapshot_for_thread(&self, thread_id: u32) -> BTreeMap<usize, u64> {
        self.thread_values
            .get(&thread_id)
            .cloned()
            .unwrap_or_default()
    }
}
