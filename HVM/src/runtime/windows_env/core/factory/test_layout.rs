use super::*;

impl WindowsProcessEnvironment {
    pub fn for_tests(arch: &'static ArchSpec) -> Self {
        let offsets = Self::offsets_for_arch(arch);
        let layout = Self::test_layout_for_arch(arch, offsets);
        let mut env = Self::new(arch, layout, offsets);
        env.initialize_reserved_layout();
        env
    }

    fn test_layout_for_arch(
        arch: &'static ArchSpec,
        offsets: ProcessEnvironmentOffsets,
    ) -> ProcessEnvironmentLayout {
        let teb_base = if arch.is_x86() {
            0x7000_0000
        } else {
            0x0000_7FF0_0000_0000
        };
        ProcessEnvironmentLayout {
            teb_base,
            peb_base: teb_base + 0x0100_0000,
            ldr_base: teb_base + 0x0200_0000,
            process_parameters_base: teb_base + 0x0400_0000,
            tls_slots_base: teb_base + offsets.teb_tls_slots as u64,
            tls_bitmap_base: teb_base + 0x0300_0000,
            tls_bitmap_buffer: teb_base + 0x0300_0100,
            image_path_buffer: teb_base + 0x0400_2000,
            command_line_buffer: teb_base + 0x0400_3000,
            command_line_ansi_buffer: teb_base + 0x0400_4000,
            current_directory_buffer: teb_base + 0x0400_5000,
            dll_path_buffer: teb_base + 0x0400_6000,
            environment_w_buffer: teb_base + 0x0400_7000,
            environment_a_buffer: teb_base + 0x0400_B000,
            gdt_base: if arch.is_x86() {
                teb_base + 0x0400_D000
            } else {
                0
            },
        }
    }
}
