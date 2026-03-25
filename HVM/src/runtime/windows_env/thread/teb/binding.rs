use super::*;

impl WindowsProcessEnvironment {
    /// Allocates one synthetic TEB layout for a newly created thread and returns its context.
    pub fn allocate_thread_teb(
        &mut self,
        stack_base: u64,
        stack_limit: u64,
    ) -> Result<ThreadContext, MemoryError> {
        let teb_base = self.next_teb_base;
        self.next_teb_base = self.next_teb_base.saturating_add(TEB_REGION_SIZE);
        let context = ThreadContext {
            teb_base,
            stack_base,
            stack_limit,
        };
        self.initialize_teb(context);
        if self.current_teb_base == self.layout.teb_base && self.thread_contexts.len() == 2 {
            self.bind_current_thread(teb_base)?;
        }
        Ok(context)
    }

    /// Binds the current-thread mirror to the given TEB base.
    pub fn bind_current_thread(&mut self, teb_base: u64) -> Result<(), MemoryError> {
        if !self.thread_contexts.contains_key(&teb_base) {
            return Err(MemoryError::MissingRegion {
                address: teb_base,
                size: 0x2000,
            });
        }
        self.current_teb_base = teb_base;
        if self.arch.is_x86() {
            self.refresh_x86_gdt(teb_base);
        }
        Ok(())
    }

    /// Mirrors the current Win32 last-error value into the active TEB.
    pub fn sync_last_error(&mut self, value: u32) {
        self.write_u32(
            self.current_teb() + self.offsets.teb_last_error as u64,
            value,
        );
    }

    /// Mirrors the current process/thread identifiers into one TEB's CLIENT_ID fields.
    pub fn sync_teb_client_id(&mut self, teb_base: u64, process_id: u32, thread_id: u32) {
        self.write_pointer(
            teb_base + self.offsets.teb_client_id as u64,
            process_id as u64,
        );
        self.write_pointer(
            teb_base + self.offsets.teb_client_id as u64 + self.pointer_size() as u64,
            thread_id as u64,
        );
    }

    pub(in crate::runtime::windows_env) fn current_tls_slots_base(
        &self,
    ) -> Result<u64, MemoryError> {
        self.thread_tls_slots
            .get(&self.current_teb_base)
            .copied()
            .ok_or(MemoryError::MissingRegion {
                address: self.current_teb_base,
                size: 0x2000,
            })
    }
}
