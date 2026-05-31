use std::collections::{HashMap, HashSet};

use crate::models::ModuleRecord;
use crate::runtime::windows_env::{
    path_mapping::VirtualPathMapper, LoaderAddressInfo, LoaderAddressKind,
};

use super::*;

mod layout;
mod lists;

impl WindowsProcessEnvironment {
    fn loader_entry_flags(module: &ModuleRecord) -> u32 {
        let mut flags = 0u32;
        if Self::loader_entry_is_dll(module) {
            flags |= 0x0000_0004;
        }
        if !module.synthetic {
            flags |= 0x0000_0002;
        }
        flags
    }

    fn loader_entry_load_count(module: &ModuleRecord) -> u16 {
        if module.synthetic {
            1
        } else {
            u16::MAX
        }
    }

    fn loader_entry_tls_index(module: &ModuleRecord) -> u16 {
        if module.tls_callbacks.is_empty() {
            0
        } else {
            1
        }
    }

    fn loader_entry_visible_entrypoint(module: &ModuleRecord) -> u64 {
        if module.entrypoint >= module.base && module.entrypoint < module.base + module.size {
            module.visible_base + (module.entrypoint - module.base)
        } else {
            module.entrypoint
        }
    }

    fn ordered_loader_nodes<I>(
        preferred_bases: &[u64],
        fallback_bases: I,
        nodes_by_base: &HashMap<u64, u64>,
    ) -> Vec<u64>
    where
        I: IntoIterator<Item = u64>,
    {
        let mut ordered = Vec::with_capacity(nodes_by_base.len());
        let mut seen = HashSet::with_capacity(nodes_by_base.len());

        for base in preferred_bases
            .iter()
            .copied()
            .chain(fallback_bases.into_iter())
        {
            if !seen.insert(base) {
                continue;
            }
            if let Some(node) = nodes_by_base.get(&base).copied() {
                ordered.push(node);
            }
        }

        ordered
    }

    fn reserve_loader_entry_allocation(
        &mut self,
        module_base: u64,
        full_name_len: usize,
        base_name_len: usize,
    ) -> Result<LoaderEntryAllocation, MemoryError> {
        let region_end = self.layout.ldr_base + self.loader_region_size();
        let entry_size = self.loader_entry_size() as u64;
        let mut allocation = self
            .loader_entries
            .get(&module_base)
            .copied()
            .unwrap_or_else(|| {
                let entry_base =
                    Self::align_loader_cursor(self.next_loader_cursor, self.pointer_size() as u64);
                self.next_loader_cursor = entry_base + entry_size;
                LoaderEntryAllocation {
                    entry_base,
                    full_name_buffer: 0,
                    full_name_reserved: 0,
                    base_name_buffer: 0,
                    base_name_reserved: 0,
                }
            });

        if allocation.full_name_buffer == 0 || allocation.full_name_reserved < full_name_len as u64
        {
            let full_name_buffer = Self::align_loader_cursor(self.next_loader_cursor, 2);
            self.next_loader_cursor = full_name_buffer + full_name_len as u64;
            allocation.full_name_buffer = full_name_buffer;
            allocation.full_name_reserved = full_name_len as u64;
        }
        if allocation.base_name_buffer == 0 || allocation.base_name_reserved < base_name_len as u64
        {
            let base_name_buffer = Self::align_loader_cursor(self.next_loader_cursor, 2);
            self.next_loader_cursor = base_name_buffer + base_name_len as u64;
            allocation.base_name_buffer = base_name_buffer;
            allocation.base_name_reserved = base_name_len as u64;
        }

        if self.next_loader_cursor > region_end {
            return Err(MemoryError::OutOfMemory {
                size: self.next_loader_cursor - self.layout.ldr_base,
                tag: Some("process:loader_entries".to_string()),
                preferred: None,
                avoid_history: None,
            });
        }

        self.loader_entries.insert(module_base, allocation);
        Ok(allocation)
    }

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
    /// Uses the default fallback mapper.
    pub fn sync_modules(&mut self, modules: &[ModuleRecord]) -> Result<(), MemoryError> {
        let fallback_mapper = VirtualPathMapper::default();
        self.sync_modules_with_mapper_and_orders(modules, &[], &[], &fallback_mapper)
    }

    /// Uses profile-derived virtual Windows paths so `FullDllName` matches the guest image.
    pub fn sync_modules_with_mapper(
        &mut self,
        modules: &[ModuleRecord],
        path_mapper: &VirtualPathMapper,
    ) -> Result<(), MemoryError> {
        self.sync_modules_with_mapper_and_orders(modules, &[], &[], path_mapper)
    }

    /// Rebuilds the mirrored PEB loader lists from one visible module set while allowing
    /// distinct list orders for `InMemoryOrder` and `InInitializationOrder`.
    pub fn sync_modules_with_mapper_and_orders(
        &mut self,
        modules: &[ModuleRecord],
        memory_order_bases: &[u64],
        initialization_order_bases: &[u64],
        path_mapper: &VirtualPathMapper,
    ) -> Result<(), MemoryError> {
        self.write_zeroes(self.layout.ldr_base, 0x100);
        self.initialize_loader_lists();

        // Find the main module (first module with base address)
        let main_module_base = modules.first().map(|m| m.base).unwrap_or(0);

        let entry_offsets = self.loader_entry_offsets();
        let entry_size = self.loader_entry_size() as u64;
        let mut load_nodes = Vec::with_capacity(modules.len());
        let mut memory_nodes_by_base = HashMap::with_capacity(modules.len());
        let mut init_nodes_by_base = HashMap::with_capacity(modules.len());

        for (index, module) in modules.iter().enumerate() {
            // Determine if this is the main module or a system DLL
            let is_main_module = index == 0 || module.base == main_module_base;
            let is_system_dll = !is_main_module && VirtualPathMapper::is_system_dll(&module.name);

            // Generate Windows-style virtual path for FullDllName
            let full_name = if let Some(ref path) = module.path {
                path_mapper.map_path(
                    &path.to_string_lossy(),
                    &module.name,
                    is_main_module,
                    is_system_dll,
                )
            } else {
                // Fallback: just use the module name
                if is_main_module {
                    format!("F:\\{}", module.name)
                } else if is_system_dll {
                    format!("C:\\Windows\\System32\\{}", module.name)
                } else {
                    module.name.clone()
                }
            };

            // BaseDllName is just the filename
            let base_name = module
                .path
                .as_ref()
                .and_then(|path| path.file_name())
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| module.name.clone());

            let full_name_bytes = layout::encode_loader_string(&full_name);
            let base_name_bytes = layout::encode_loader_string(&base_name);
            let allocation = self.reserve_loader_entry_allocation(
                module.base,
                full_name_bytes.len(),
                base_name_bytes.len(),
            )?;

            self.write_zeroes(allocation.entry_base, entry_size as usize);
            self.write_zeroes(
                allocation.full_name_buffer,
                allocation.full_name_reserved as usize,
            );
            self.write_zeroes(
                allocation.base_name_buffer,
                allocation.base_name_reserved as usize,
            );
            self.write_bytes(allocation.full_name_buffer, &full_name_bytes);
            self.write_bytes(allocation.base_name_buffer, &base_name_bytes);
            self.write_pointer(
                allocation.entry_base + entry_offsets.dll_base,
                module.visible_base,
            );
            self.write_pointer(
                allocation.entry_base + entry_offsets.entry_point,
                Self::loader_entry_visible_entrypoint(module),
            );
            self.write_u32(
                allocation.entry_base + entry_offsets.size_of_image,
                module.size.min(u32::MAX as u64) as u32,
            );
            self.write_unicode_string_descriptor(
                allocation.entry_base + entry_offsets.full_dll_name,
                allocation.full_name_buffer,
                &full_name,
            );
            self.write_unicode_string_descriptor(
                allocation.entry_base + entry_offsets.base_dll_name,
                allocation.base_name_buffer,
                &base_name,
            );
            self.write_u32(
                allocation.entry_base + entry_offsets.flags,
                Self::loader_entry_flags(module),
            );
            self.write_u16(
                allocation.entry_base + entry_offsets.load_count,
                Self::loader_entry_load_count(module),
            );
            self.write_u16(
                allocation.entry_base + entry_offsets.tls_index,
                Self::loader_entry_tls_index(module),
            );
            let hash_links = allocation.entry_base + entry_offsets.hash_links;
            self.write_pointer(hash_links, hash_links);
            self.write_pointer(hash_links + self.pointer_size() as u64, hash_links);
            self.write_u32(
                allocation.entry_base + entry_offsets.time_date_stamp,
                module.time_date_stamp,
            );

            load_nodes.push(allocation.entry_base + entry_offsets.in_load_order);
            memory_nodes_by_base.insert(
                module.base,
                allocation.entry_base + entry_offsets.in_memory_order,
            );
            if Self::loader_entry_is_dll(module) {
                init_nodes_by_base.insert(
                    module.base,
                    allocation.entry_base + entry_offsets.in_initialization_order,
                );
            }
        }

        let memory_nodes = Self::ordered_loader_nodes(
            memory_order_bases,
            modules.iter().map(|module| module.base),
            &memory_nodes_by_base,
        );
        let init_nodes = Self::ordered_loader_nodes(
            initialization_order_bases,
            modules
                .iter()
                .filter(|module| Self::loader_entry_is_dll(module))
                .map(|module| module.base),
            &init_nodes_by_base,
        );

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

    /// Returns one mirrored loader entry base for the requested module image base.
    pub fn loader_entry_for_module_base(
        &self,
        module_base: u64,
    ) -> Result<Option<u64>, MemoryError> {
        let entry_offsets = self.loader_entry_offsets();
        let [load_head_offset, ..] = self.ldr_list_head_offsets();
        for entry_base in self.walk_loader_list(
            self.layout.ldr_base + load_head_offset,
            entry_offsets.in_load_order,
        )? {
            if self.read_pointer(entry_base + entry_offsets.dll_base)? == module_base {
                return Ok(Some(entry_base));
            }
        }
        Ok(None)
    }

    /// Resolves which loader entry or loader-owned string buffer contains `address`.
    pub fn loader_address_info(
        &self,
        address: u64,
    ) -> Result<Option<LoaderAddressInfo>, MemoryError> {
        let entry_offsets = self.loader_entry_offsets();
        let [load_head_offset, ..] = self.ldr_list_head_offsets();
        for (entry_index, entry_base) in self
            .walk_loader_list(
                self.layout.ldr_base + load_head_offset,
                entry_offsets.in_load_order,
            )?
            .into_iter()
            .enumerate()
        {
            let module_base = self.read_pointer(entry_base + entry_offsets.dll_base)?;
            let Some(allocation) = self
                .loader_entries
                .values()
                .find(|allocation| allocation.entry_base == entry_base)
                .copied()
            else {
                continue;
            };
            let module_name = self.read_loader_string(entry_base + entry_offsets.base_dll_name)?;
            let full_name = self.read_loader_string(entry_base + entry_offsets.full_dll_name)?;
            let entry_end = allocation.entry_base + self.loader_entry_size() as u64;
            let full_name_end = allocation.full_name_buffer + allocation.full_name_reserved;
            let base_name_end = allocation.base_name_buffer + allocation.base_name_reserved;
            let kind = if address >= allocation.entry_base && address < entry_end {
                Some(LoaderAddressKind::Entry)
            } else if address >= allocation.full_name_buffer && address < full_name_end {
                Some(LoaderAddressKind::FullDllNameBuffer)
            } else if address >= allocation.base_name_buffer && address < base_name_end {
                Some(LoaderAddressKind::BaseDllNameBuffer)
            } else {
                None
            };
            if let Some(kind) = kind {
                return Ok(Some(LoaderAddressInfo {
                    entry_base,
                    entry_index,
                    module_base,
                    module_name,
                    full_name,
                    kind,
                }));
            }
        }
        Ok(None)
    }
}
