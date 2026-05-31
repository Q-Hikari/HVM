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
        if self.current_teb_base == teb_base {
            return Ok(());
        }
        self.current_teb_base = teb_base;
        if self.arch.is_x86() {
            self.refresh_x86_gdt(teb_base);
        }
        Ok(())
    }

    /// Updates the current-thread TEB StackLimit mirror and cached thread context.
    pub fn set_current_thread_stack_limit(&mut self, stack_limit: u64) -> Result<(), MemoryError> {
        let teb_base = self.current_teb_base;
        let Some(context) = self.thread_contexts.get_mut(&teb_base) else {
            return Err(MemoryError::MissingRegion {
                address: teb_base,
                size: 0x2000,
            });
        };
        context.stack_limit = stack_limit;
        self.write_pointer(teb_base + self.offsets.teb_stack_limit as u64, stack_limit);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_current_thread_is_noop_when_teb_is_already_active() {
        let mut env = WindowsProcessEnvironment::for_tests_x86();
        env.dirty = false;
        env.dirty_pages.clear();

        env.bind_current_thread(env.current_teb()).unwrap();

        assert!(!env.dirty);
        assert!(env.dirty_pages.is_empty());
    }

    #[test]
    fn x86_exception_list_seed_is_stack_backed_and_includes_prefix_frame() {
        let mut env = WindowsProcessEnvironment::for_tests_x86();
        let stack_base = 0x8000_0000u64;
        let stack_limit = 0x7FF0_0000u64;
        let ctx = env.allocate_thread_teb(stack_base, stack_limit).unwrap();

        // Read ExceptionList from TEB
        let exception_list = env
            .read_u32(ctx.teb_base + env.offsets().teb_exception_list as u64)
            .unwrap() as u64;

        // ExceptionList should not be the bare sentinel 0xFFFFFFFF
        assert_ne!(
            exception_list,
            u32::MAX as u64,
            "ExceptionList should point to a seeded frame, not the bare sentinel"
        );

        // The registration record should live on the committed stack, not in the TEB/TLS area.
        assert!(
            exception_list >= stack_limit && exception_list < stack_base,
            "ExceptionList should be stack-backed"
        );
        assert_ne!(
            exception_list,
            ctx.teb_base + env.offsets().teb_tls_slots as u64,
            "ExceptionList must not overlap TEB TLS slots"
        );

        // Verify registration record: Next = 0xFFFFFFFF (chain end)
        let next = env.read_u32(exception_list).unwrap();
        assert_eq!(next, u32::MAX, "registration Next should be 0xFFFFFFFF");

        // Verify registration record: Handler = 0 (no handler)
        let handler = env.read_u32(exception_list + 4).unwrap();
        assert_eq!(handler, 0u32, "registration Handler should be 0");

        // Verify prefix area at ExceptionList - 0x10
        let prefix_base = exception_list - 0x10;

        // prefix +0x00 = 0
        assert_eq!(env.read_u32(prefix_base).unwrap(), 0u32);

        // prefix +0x04 = 0xFFFFFFFF
        assert_eq!(env.read_u32(prefix_base + 4).unwrap(), u32::MAX);

        // prefix +0x08 = stack_base
        assert_eq!(env.read_u32(prefix_base + 8).unwrap(), stack_base as u32);

        // prefix +0x0C = 0
        assert_eq!(env.read_u32(prefix_base + 0xC).unwrap(), 0u32);
    }

    #[test]
    fn x86_exception_list_seed_survives_tls_slot_writes() {
        let mut env = WindowsProcessEnvironment::for_tests_x86();
        let ctx = env.allocate_thread_teb(0x8000_0000, 0x7FF0_0000).unwrap();
        env.bind_current_thread(ctx.teb_base).unwrap();

        let exception_list = env
            .read_pointer(ctx.teb_base + env.offsets().teb_exception_list as u64)
            .unwrap();
        assert_eq!(env.read_pointer(exception_list).unwrap(), u32::MAX as u64);
        assert_eq!(env.read_pointer(exception_list + 4).unwrap(), 0);

        let slot = env.allocate_tls_slot().unwrap();
        env.set_tls_value(slot, 0x1122_3344).unwrap();

        assert_eq!(slot, 0, "test assumes first TLS slot lands at TlsSlots[0]");
        assert_eq!(env.read_pointer(exception_list).unwrap(), u32::MAX as u64);
        assert_eq!(env.read_pointer(exception_list + 4).unwrap(), 0);
    }
}
