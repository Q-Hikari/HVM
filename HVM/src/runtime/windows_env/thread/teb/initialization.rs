use super::*;

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env) fn initialize_teb(&mut self, context: ThreadContext) {
        let tls_slots_base = context.teb_base + self.offsets.teb_tls_slots as u64;
        self.write_zeroes(context.teb_base, 0x2000);
        self.write_zeroes(tls_slots_base, 64 * self.pointer_size());
        let exception_list_value = if self.pointer_size() == 4 {
            // x86: seed a stack-backed initial SEH frame.  Some samples read
            // ExceptionList and then access ExceptionList - 0x10, so keep a
            // 16-byte prefix immediately ahead of the registration record.
            if context.stack_base > context.stack_limit
                && context.stack_base.saturating_sub(0x18) >= context.stack_limit
            {
                let registration = context.stack_base - 8;
                let prefix_base = registration - 0x10;
                self.write_u32(prefix_base + 0x00, 0);
                self.write_u32(prefix_base + 0x04, u32::MAX);
                self.write_u32(prefix_base + 0x08, context.stack_base as u32);
                self.write_u32(prefix_base + 0x0C, 0);
                self.write_u32(registration + 0x00, u32::MAX);
                self.write_u32(registration + 0x04, 0);
                registration
            } else {
                u32::MAX as u64
            }
        } else {
            // x64: ExceptionList uses 0xFFFFFFFFFFFFFFFF as the chain-end sentinel
            u64::MAX
        };
        self.write_pointer(
            context.teb_base + self.offsets.teb_exception_list as u64,
            exception_list_value,
        );
        self.write_pointer(
            context.teb_base + self.offsets.teb_stack_base as u64,
            context.stack_base,
        );
        self.write_pointer(
            context.teb_base + self.offsets.teb_stack_limit as u64,
            context.stack_limit,
        );
        self.write_pointer(
            context.teb_base + self.offsets.teb_self as u64,
            context.teb_base,
        );
        self.write_pointer(
            context.teb_base + self.offsets.teb_tls_pointer as u64,
            tls_slots_base,
        );
        self.write_pointer(
            context.teb_base + self.offsets.teb_peb as u64,
            self.layout.peb_base,
        );
        self.write_pointer(context.teb_base + self.offsets.teb_client_id as u64, 0);
        self.write_pointer(
            context.teb_base + self.offsets.teb_client_id as u64 + self.pointer_size() as u64,
            0,
        );
        self.write_u32(context.teb_base + self.offsets.teb_last_error as u64, 0);
        self.thread_contexts.insert(context.teb_base, context);
        self.thread_tls_slots
            .insert(context.teb_base, tls_slots_base);
    }
}
