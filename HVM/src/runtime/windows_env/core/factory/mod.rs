use crate::arch::{ArchSpec, X64_ARCH, X86_ARCH};

use super::*;

mod reserved;
mod test_layout;

impl WindowsProcessEnvironment {
    pub fn for_tests_x86() -> Self {
        Self::for_tests(&X86_ARCH)
    }

    pub fn for_tests_x64() -> Self {
        Self::for_tests(&X64_ARCH)
    }

    pub fn from_reserved_x86(memory: &MemoryManager) -> Result<Self, MemoryError> {
        Self::from_reserved(memory, &X86_ARCH)
    }

    fn new(
        arch: &'static ArchSpec,
        layout: ProcessEnvironmentLayout,
        offsets: ProcessEnvironmentOffsets,
    ) -> Self {
        Self {
            arch,
            layout,
            offsets,
            allocated_tls_slots: BTreeSet::new(),
            memory: HashMap::new(),
            dirty: true,
            dirty_pages: BTreeSet::new(),
            current_teb_base: layout.teb_base,
            thread_contexts: HashMap::new(),
            thread_tls_slots: HashMap::new(),
            loader_entries: HashMap::new(),
            next_loader_cursor: layout.ldr_base + 0x100,
            next_tls_slot: 0,
            next_teb_base: layout.teb_base + TEB_REGION_SIZE,
        }
    }
}
