use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::runtime::windows_env) struct PebOffsetGroup {
    pub image_base: usize,
    pub ldr: usize,
    pub process_parameters: usize,
    pub process_heap: usize,
    pub number_of_heaps: usize,
    pub process_heaps: usize,
    pub tls_bitmap: usize,
    pub being_debugged: usize,
    pub nt_global_flag: usize,
}

pub(in crate::runtime::windows_env) fn peb_offsets_for_arch(
    arch: &'static ArchSpec,
) -> PebOffsetGroup {
    if arch.is_x86() {
        PebOffsetGroup {
            being_debugged: 0x02,
            image_base: 0x08,
            ldr: 0x0C,
            process_parameters: 0x10,
            process_heap: 0x18,
            number_of_heaps: 0x1C,
            process_heaps: 0x20,
            tls_bitmap: 0x40,
            nt_global_flag: 0x68,
        }
    } else {
        PebOffsetGroup {
            being_debugged: 0x02,
            image_base: 0x10,
            ldr: 0x18,
            process_parameters: 0x20,
            process_heap: 0x30,
            number_of_heaps: 0x38,
            process_heaps: 0x40,
            tls_bitmap: 0x78,
            nt_global_flag: 0xBC,
        }
    }
}

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env) fn initialize_peb_layout(&mut self) {
        self.write_zeroes(self.layout.peb_base, PEB_REGION_SIZE as usize);

        // Set anti-debug fields to bypass detection
        // PEB.BeingDebugged = 0 (offset 0x02)
        self.write_u8(self.layout.peb_base + 0x02, 0);

        // PEB.NtGlobalFlag = 0 (normal process, not debugged)
        // For x86: offset 0x68, for x64: offset 0xBC
        let nt_global_flag_offset = if self.arch.is_x86() { 0x68u64 } else { 0xBCu64 };
        self.write_u32(self.layout.peb_base + nt_global_flag_offset, 0);

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

    /// Mirrors the default process heap handle so CRT code can read `PEB.ProcessHeap`.
    pub fn sync_process_heap(&mut self, heap_handle: u64) {
        self.write_pointer(
            self.layout.peb_base + self.offsets.peb_process_heap as u64,
            heap_handle,
        );
    }
}
