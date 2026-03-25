use super::*;

impl WindowsProcessEnvironment {
    /// Allocates one TLS slot and marks its bit in the mirrored bitmap.
    pub fn allocate_tls_slot(&mut self) -> Result<usize, MemoryError> {
        let slot = self.next_tls_slot;
        if slot >= 64 {
            return Err(MemoryError::OutOfMemory { size: 64 });
        }
        self.next_tls_slot = self.next_tls_slot.saturating_add(1);
        self.allocated_tls_slots.insert(slot);
        self.set_bitmap_bit(slot);
        Ok(slot)
    }

    /// Writes a TLS slot value into the mirrored TEB TLS slots array.
    pub fn set_tls_value(&mut self, slot: usize, value: u64) -> Result<(), MemoryError> {
        if !self.allocated_tls_slots.contains(&slot) {
            return Err(MemoryError::MissingRegion {
                address: 0,
                size: self.pointer_size() as u64,
            });
        }
        let tls_slots_base = self.current_tls_slots_base()?;
        self.write_pointer(tls_slots_base + (slot * self.pointer_size()) as u64, value);
        Ok(())
    }

    /// Releases one mirrored TLS slot and clears its per-thread storage.
    pub fn free_tls_slot(&mut self, slot: usize) -> Result<bool, MemoryError> {
        if !self.allocated_tls_slots.remove(&slot) {
            return Ok(false);
        }
        self.clear_bitmap_bit(slot);
        let mut tls_bases = self.thread_tls_slots.values().copied().collect::<Vec<_>>();
        tls_bases.sort_unstable();
        tls_bases.dedup();
        for base in tls_bases {
            self.write_pointer(base + (slot * self.pointer_size()) as u64, 0);
        }
        Ok(true)
    }

    /// Reads one mirrored TLS slot value from pseudo-memory.
    pub fn read_tls_value(&self, slot: usize) -> Result<u64, MemoryError> {
        self.read_pointer(self.current_tls_slots_base()? + (slot * self.pointer_size()) as u64)
    }
}
