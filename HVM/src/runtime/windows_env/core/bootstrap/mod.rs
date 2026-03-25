use super::*;

mod buffers;

impl WindowsProcessEnvironment {
    pub(super) fn initialize_reserved_layout(&mut self) {
        self.initialize_peb_layout();
        self.write_zeroes(self.layout.ldr_base, LDR_REGION_SIZE as usize);
        self.write_zeroes(
            self.layout.process_parameters_base,
            PROCESS_PARAMETERS_REGION_SIZE as usize,
        );
        self.initialize_tls_bitmap_layout();
        self.initialize_process_parameter_buffers();
        if self.layout.gdt_base != 0 {
            self.write_zeroes(self.layout.gdt_base, GDT_REGION_SIZE as usize);
        }
        self.initialize_teb(ThreadContext {
            teb_base: self.layout.teb_base,
            stack_base: 0,
            stack_limit: 0,
        });
        self.write_process_parameters_metadata();
        self.initialize_loader_lists();
        if self.arch.is_x86() {
            self.refresh_x86_gdt(self.layout.teb_base);
        }
    }
}
