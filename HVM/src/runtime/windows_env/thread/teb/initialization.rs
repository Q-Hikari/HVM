use super::*;

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env) fn initialize_teb(&mut self, context: ThreadContext) {
        let tls_slots_base = context.teb_base + self.offsets.teb_tls_slots as u64;
        self.write_zeroes(context.teb_base, 0x2000);
        self.write_zeroes(tls_slots_base, 64 * self.pointer_size());
        self.write_pointer(
            context.teb_base + self.offsets.teb_exception_list as u64,
            if self.pointer_size() == 4 {
                u32::MAX as u64
            } else {
                u64::MAX
            },
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
