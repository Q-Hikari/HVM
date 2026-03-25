use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::runtime::windows_env) struct PebOffsetGroup {
    pub image_base: usize,
    pub ldr: usize,
    pub process_parameters: usize,
    pub tls_bitmap: usize,
}

pub(in crate::runtime::windows_env) fn peb_offsets_for_arch(
    arch: &'static ArchSpec,
) -> PebOffsetGroup {
    if arch.is_x86() {
        PebOffsetGroup {
            image_base: 0x08,
            ldr: 0x0C,
            process_parameters: 0x10,
            tls_bitmap: 0x40,
        }
    } else {
        PebOffsetGroup {
            image_base: 0x10,
            ldr: 0x18,
            process_parameters: 0x20,
            tls_bitmap: 0x78,
        }
    }
}

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env) fn initialize_peb_layout(&mut self) {
        self.write_zeroes(self.layout.peb_base, PEB_REGION_SIZE as usize);
        self.write_pointer(
            self.layout.peb_base + self.offsets.peb_tls_bitmap as u64,
            self.layout.tls_bitmap_base,
        );
        self.write_pointer(
            self.layout.peb_base + self.offsets.peb_ldr as u64,
            self.layout.ldr_base,
        );
        self.write_pointer(
            self.layout.peb_base + self.offsets.peb_process_parameters as u64,
            self.layout.process_parameters_base,
        );
    }

    /// Mirrors the mapped image base into the PEB so `fs:[0x30]` walks can resolve it.
    pub fn sync_image_base(&mut self, image_base: u64) {
        self.write_pointer(
            self.layout.peb_base + self.offsets.peb_image_base as u64,
            image_base,
        );
    }
}
