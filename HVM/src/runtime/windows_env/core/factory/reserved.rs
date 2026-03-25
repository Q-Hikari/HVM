use crate::memory::manager::MemoryRegion;

use super::*;

impl WindowsProcessEnvironment {
    /// Builds a process environment mirror using the already-reserved Python-compatible
    /// memory footprint from the runtime memory manager.
    pub fn from_reserved(
        memory: &MemoryManager,
        arch: &'static ArchSpec,
    ) -> Result<Self, MemoryError> {
        let offsets = Self::offsets_for_arch(arch);
        let layout = Self::reserved_layout_for_arch(memory, arch, offsets)?;
        let mut env = Self::new(arch, layout, offsets);
        env.initialize_reserved_layout();
        Ok(env)
    }

    fn reserved_layout_for_arch(
        memory: &MemoryManager,
        arch: &'static ArchSpec,
        offsets: ProcessEnvironmentOffsets,
    ) -> Result<ProcessEnvironmentLayout, MemoryError> {
        let teb_base = Self::find_reserved_region_base(memory, "teb")?;
        Ok(ProcessEnvironmentLayout {
            teb_base,
            peb_base: Self::find_reserved_region_base(memory, "peb")?,
            ldr_base: Self::find_reserved_region_base(memory, "ldr")?,
            process_parameters_base: Self::find_reserved_region_base(memory, "params")?,
            tls_slots_base: teb_base + offsets.teb_tls_slots as u64,
            tls_bitmap_base: Self::find_reserved_region_base(memory, "tls_bitmap")?,
            tls_bitmap_buffer: Self::find_reserved_region_base(memory, "tls_bitmap_bits")?,
            image_path_buffer: Self::find_reserved_region_base(memory, "params_image")?,
            command_line_buffer: Self::find_reserved_region_base(memory, "params_command")?,
            command_line_ansi_buffer: Self::find_reserved_region_base(memory, "params_command_a")?,
            current_directory_buffer: Self::find_reserved_region_base(
                memory,
                "params_current_directory",
            )?,
            dll_path_buffer: Self::find_reserved_region_base(memory, "params_dll_path")?,
            environment_w_buffer: Self::find_reserved_region_base(memory, "params_environment_w")?,
            environment_a_buffer: Self::find_reserved_region_base(memory, "params_environment_a")?,
            gdt_base: if arch.is_x86() {
                Self::find_reserved_region_base(memory, "gdt")?
            } else {
                0
            },
        })
    }

    pub(super) fn find_reserved_region_base(
        memory: &MemoryManager,
        tag: &str,
    ) -> Result<u64, MemoryError> {
        memory
            .regions
            .iter()
            .find(|region: &&MemoryRegion| region.tag == tag)
            .map(|region| region.base)
            .ok_or(MemoryError::MissingRegion {
                address: 0,
                size: 0,
            })
    }
}
