use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::runtime::windows_env::process::loader) struct LoaderEntryOffsets {
    pub in_load_order: u64,
    pub in_memory_order: u64,
    pub in_initialization_order: u64,
    pub dll_base: u64,
    pub entry_point: u64,
    pub size_of_image: u64,
    pub full_dll_name: u64,
    pub base_dll_name: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::runtime::windows_env::process::loader) struct LoaderHeaderLayout {
    pub length: u32,
    pub initialized: u64,
    pub in_load_order: u64,
    pub in_memory_order: u64,
    pub in_initialization_order: u64,
}

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env::process::loader) fn loader_entry_offsets(
        &self,
    ) -> LoaderEntryOffsets {
        if self.arch.is_x86() {
            LoaderEntryOffsets {
                in_load_order: 0x00,
                in_memory_order: 0x08,
                in_initialization_order: 0x10,
                dll_base: 0x18,
                entry_point: 0x1C,
                size_of_image: 0x20,
                full_dll_name: 0x24,
                base_dll_name: 0x2C,
            }
        } else {
            LoaderEntryOffsets {
                in_load_order: 0x00,
                in_memory_order: 0x10,
                in_initialization_order: 0x20,
                dll_base: 0x30,
                entry_point: 0x38,
                size_of_image: 0x40,
                full_dll_name: 0x48,
                base_dll_name: 0x58,
            }
        }
    }

    pub(in crate::runtime::windows_env::process::loader) fn loader_header_layout(
        &self,
    ) -> LoaderHeaderLayout {
        if self.arch.is_x86() {
            LoaderHeaderLayout {
                length: 0x30,
                initialized: 0x04,
                in_load_order: 0x0C,
                in_memory_order: 0x14,
                in_initialization_order: 0x1C,
            }
        } else {
            LoaderHeaderLayout {
                length: 0x58,
                initialized: 0x04,
                in_load_order: 0x10,
                in_memory_order: 0x20,
                in_initialization_order: 0x30,
            }
        }
    }

    pub(in crate::runtime::windows_env::process::loader) fn loader_entry_size(&self) -> usize {
        if self.arch.is_x86() {
            0x38
        } else {
            0x70
        }
    }

    pub(in crate::runtime::windows_env::process::loader) fn loader_entry_is_dll(
        module: &ModuleRecord,
    ) -> bool {
        module
            .path
            .as_ref()
            .and_then(|path| path.extension())
            .map(|extension| extension.to_string_lossy().eq_ignore_ascii_case("dll"))
            .unwrap_or_else(|| module.name.ends_with(".dll"))
    }

    pub(in crate::runtime::windows_env::process::loader) fn align_loader_cursor(
        value: u64,
        alignment: u64,
    ) -> u64 {
        if alignment <= 1 {
            value
        } else {
            (value + alignment - 1) & !(alignment - 1)
        }
    }
}
