use crate::models::ModuleRecord;

use super::*;

mod layout;
mod lists;

impl WindowsProcessEnvironment {
    pub(super) fn ldr_list_head_offsets(&self) -> [u64; 3] {
        let layout = self.loader_header_layout();
        [
            layout.in_load_order,
            layout.in_memory_order,
            layout.in_initialization_order,
        ]
    }

    pub(in crate::runtime::windows_env) fn initialize_loader_lists(&mut self) {
        let layout = self.loader_header_layout();
        self.write_u32(self.layout.ldr_base, layout.length);
        self.write_u32(self.layout.ldr_base + layout.initialized, 1);
        for offset in self.ldr_list_head_offsets() {
            let head = self.layout.ldr_base + offset;
            self.write_pointer(head, head);
            self.write_pointer(head + self.pointer_size() as u64, head);
        }
    }

    /// Rebuilds the mirrored PEB loader lists from the currently loaded module set.
    pub fn sync_modules(&mut self, modules: &[ModuleRecord]) -> Result<(), MemoryError> {
        self.write_zeroes(self.layout.ldr_base, LDR_REGION_SIZE as usize);
        self.initialize_loader_lists();

        let entry_offsets = self.loader_entry_offsets();
        let entry_size = self.loader_entry_size() as u64;
        let region_end = self.layout.ldr_base + LDR_REGION_SIZE;
        let mut cursor = self.layout.ldr_base + 0x100;
        let mut load_nodes = Vec::with_capacity(modules.len());
        let mut memory_nodes = Vec::with_capacity(modules.len());
        let mut init_nodes = Vec::with_capacity(modules.len());

        for module in modules {
            let entry_base = Self::align_loader_cursor(cursor, self.pointer_size() as u64);
            cursor = entry_base + entry_size;

            let full_name = module
                .path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_else(|| module.name.clone());
            let base_name = module
                .path
                .as_ref()
                .and_then(|path| path.file_name())
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| module.name.clone());
            let full_name_bytes = layout::encode_loader_string(&full_name);
            let base_name_bytes = layout::encode_loader_string(&base_name);
            let full_name_buffer = Self::align_loader_cursor(cursor, 2);
            cursor = full_name_buffer + full_name_bytes.len() as u64;
            let base_name_buffer = Self::align_loader_cursor(cursor, 2);
            cursor = base_name_buffer + base_name_bytes.len() as u64;

            if cursor > region_end {
                return Err(MemoryError::OutOfMemory {
                    size: cursor - self.layout.ldr_base,
                });
            }

            self.write_zeroes(entry_base, entry_size as usize);
            self.write_bytes(full_name_buffer, &full_name_bytes);
            self.write_bytes(base_name_buffer, &base_name_bytes);
            self.write_pointer(entry_base + entry_offsets.dll_base, module.base);
            self.write_pointer(entry_base + entry_offsets.entry_point, module.entrypoint);
            self.write_u32(
                entry_base + entry_offsets.size_of_image,
                module.size.min(u32::MAX as u64) as u32,
            );
            self.write_unicode_string_descriptor(
                entry_base + entry_offsets.full_dll_name,
                full_name_buffer,
                &full_name,
            );
            self.write_unicode_string_descriptor(
                entry_base + entry_offsets.base_dll_name,
                base_name_buffer,
                &base_name,
            );

            load_nodes.push(entry_base + entry_offsets.in_load_order);
            memory_nodes.push(entry_base + entry_offsets.in_memory_order);
            if Self::loader_entry_is_dll(module) {
                init_nodes.push(entry_base + entry_offsets.in_initialization_order);
            }
        }

        let [load_head_offset, memory_head_offset, init_head_offset] = self.ldr_list_head_offsets();
        self.link_loader_list(self.layout.ldr_base + load_head_offset, &load_nodes);
        self.link_loader_list(self.layout.ldr_base + memory_head_offset, &memory_nodes);
        self.link_loader_list(self.layout.ldr_base + init_head_offset, &init_nodes);
        Ok(())
    }

    /// Returns the loader-ordered module base addresses currently mirrored under `PEB.Ldr`.
    pub fn loader_module_bases(&self) -> Result<Vec<u64>, MemoryError> {
        let entry_offsets = self.loader_entry_offsets();
        let [load_head_offset, ..] = self.ldr_list_head_offsets();
        self.walk_loader_list(
            self.layout.ldr_base + load_head_offset,
            entry_offsets.in_load_order,
        )?
        .into_iter()
        .map(|entry_base| self.read_pointer(entry_base + entry_offsets.dll_base))
        .collect()
    }

    /// Returns the loader-ordered module base names currently mirrored under `PEB.Ldr`.
    pub fn loader_module_names(&self) -> Result<Vec<String>, MemoryError> {
        let entry_offsets = self.loader_entry_offsets();
        let [load_head_offset, ..] = self.ldr_list_head_offsets();
        self.walk_loader_list(
            self.layout.ldr_base + load_head_offset,
            entry_offsets.in_load_order,
        )?
        .into_iter()
        .map(|entry_base| self.read_loader_string(entry_base + entry_offsets.base_dll_name))
        .collect()
    }
}
