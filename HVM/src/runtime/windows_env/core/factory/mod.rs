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
            memory: BTreeMap::new(),
            dirty: true,
            dirty_pages: BTreeSet::new(),
            current_teb_base: layout.teb_base,
            thread_contexts: BTreeMap::new(),
            thread_tls_slots: BTreeMap::new(),
            next_tls_slot: 0,
            next_teb_base: layout.teb_base + TEB_REGION_SIZE,
        }
    }
}
