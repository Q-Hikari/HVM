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
    pub flags: u64,
    pub load_count: u64,
    pub tls_index: u64,
    pub hash_links: u64,
    pub time_date_stamp: u64,
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
        LoaderEntryOffsets {
            in_load_order: self.offsets.ldr_entry_in_load_order,
            in_memory_order: self.offsets.ldr_entry_in_memory_order,
            in_initialization_order: self.offsets.ldr_entry_in_initialization_order,
            dll_base: self.offsets.ldr_entry_dll_base,
            entry_point: self.offsets.ldr_entry_entry_point,
            size_of_image: self.offsets.ldr_entry_size_of_image,
            full_dll_name: self.offsets.ldr_entry_full_dll_name,
            base_dll_name: self.offsets.ldr_entry_base_dll_name,
            flags: self.offsets.ldr_entry_flags,
            load_count: self.offsets.ldr_entry_load_count,
            tls_index: self.offsets.ldr_entry_tls_index,
            hash_links: self.offsets.ldr_entry_hash_links,
            time_date_stamp: self.offsets.ldr_entry_time_date_stamp,
        }
    }

    pub(in crate::runtime::windows_env::process::loader) fn loader_header_layout(
        &self,
    ) -> LoaderHeaderLayout {
        LoaderHeaderLayout {
            length: self.offsets.ldr_length,
            initialized: self.offsets.ldr_initialized,
            in_load_order: self.offsets.ldr_in_load_order,
            in_memory_order: self.offsets.ldr_in_memory_order,
            in_initialization_order: self.offsets.ldr_in_initialization_order,
        }
    }

    pub(in crate::runtime::windows_env::process::loader) fn loader_entry_size(&self) -> usize {
        self.offsets.ldr_entry_size
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
