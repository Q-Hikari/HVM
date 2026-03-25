use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn mapped_file_path_for_process(
        &mut self,
        process_handle: u64,
        address: u64,
    ) -> Option<String> {
        let process_key = self.process_space_key_for_handle(process_handle)?;
        if let Ok(Some(module)) = self.process_module_by_address(process_handle, address) {
            module
                .path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string())
        } else {
            self.file_mappings
                .mapped_path_for_address(process_key, address)
                .map(str::to_string)
        }
    }

    pub(in crate::runtime::engine) fn memory_region_type_for_process(
        &mut self,
        process_handle: u64,
        address: u64,
    ) -> u32 {
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return MEM_PRIVATE;
        };
        if self
            .process_module_by_address(process_handle, address)
            .ok()
            .flatten()
            .is_some()
        {
            MEM_IMAGE
        } else if let Some(image) = self.file_mappings.view_is_image(process_key, address) {
            if image {
                MEM_IMAGE
            } else {
                MEM_MAPPED
            }
        } else {
            MEM_PRIVATE
        }
    }

    pub(in crate::runtime::engine) fn query_memory_basic_information_for_process(
        &mut self,
        process_handle: u64,
        address: u64,
    ) -> Option<MemoryBasicInfoSnapshot> {
        let page_address = address & !(PAGE_SIZE - 1);
        if let Some(info) =
            self.virtual_allocation_snapshot_for_process(process_handle, page_address)
        {
            return Some(info);
        }
        let region = self.with_process_memory(process_handle, |memory| {
            memory.find_region(address, 1).map(|region| {
                (
                    region.base,
                    region.size,
                    Self::page_protect_from_perms(region.perms),
                )
            })
        })?;
        if let Some((base, region_size, protect)) = region {
            return Some(MemoryBasicInfoSnapshot {
                base_address: base,
                allocation_base: base,
                allocation_protect: protect,
                region_size,
                state: MEM_COMMIT,
                protect,
                region_type: self.memory_region_type_for_process(process_handle, address),
            });
        }

        let mut free_base = 0u64;
        let mut free_end = if self.arch.is_x86() {
            (u32::MAX as u64).saturating_add(1)
        } else {
            0x0000_8000_0000_0000
        };
        let regions = self.with_process_memory(process_handle, |memory| {
            memory
                .regions
                .iter()
                .map(|region| (region.base, region.end()))
                .collect::<Vec<_>>()
        })?;
        for (region_base, region_end) in regions {
            if region_end <= page_address {
                free_base = region_end;
                continue;
            }
            if region_base > page_address {
                free_end = region_base;
                break;
            }
        }
        if free_end <= free_base {
            free_end = free_base.saturating_add(PAGE_SIZE);
        }

        Some(MemoryBasicInfoSnapshot {
            base_address: free_base,
            allocation_base: 0,
            allocation_protect: 0,
            region_size: free_end.saturating_sub(free_base).max(PAGE_SIZE),
            state: MEM_FREE,
            protect: 0,
            region_type: 0,
        })
    }

    pub(in crate::runtime::engine) fn query_memory_basic_information(
        &mut self,
        address: u64,
    ) -> MemoryBasicInfoSnapshot {
        self.query_memory_basic_information_for_process(self.current_process_space_key(), address)
            .unwrap_or(MemoryBasicInfoSnapshot {
                base_address: address & !(PAGE_SIZE - 1),
                allocation_base: 0,
                allocation_protect: 0,
                region_size: PAGE_SIZE,
                state: MEM_FREE,
                protect: 0,
                region_type: 0,
            })
    }

    pub(in crate::runtime::engine) fn memory_basic_information_size(&self) -> usize {
        if self.arch.is_x86() {
            28
        } else {
            48
        }
    }

    pub(in crate::runtime::engine) fn write_memory_basic_information(
        &mut self,
        address: u64,
        capacity: usize,
        info: MemoryBasicInfoSnapshot,
    ) -> Result<usize, VmError> {
        let struct_size = self.memory_basic_information_size();
        let mut bytes = vec![0u8; struct_size];
        if self.arch.is_x86() {
            bytes[0..4].copy_from_slice(&(info.base_address as u32).to_le_bytes());
            bytes[4..8].copy_from_slice(&(info.allocation_base as u32).to_le_bytes());
            bytes[8..12].copy_from_slice(&info.allocation_protect.to_le_bytes());
            bytes[12..16].copy_from_slice(&(info.region_size as u32).to_le_bytes());
            bytes[16..20].copy_from_slice(&info.state.to_le_bytes());
            bytes[20..24].copy_from_slice(&info.protect.to_le_bytes());
            bytes[24..28].copy_from_slice(&info.region_type.to_le_bytes());
        } else {
            bytes[0..8].copy_from_slice(&info.base_address.to_le_bytes());
            bytes[8..16].copy_from_slice(&info.allocation_base.to_le_bytes());
            bytes[16..20].copy_from_slice(&info.allocation_protect.to_le_bytes());
            bytes[24..32].copy_from_slice(&info.region_size.to_le_bytes());
            bytes[32..36].copy_from_slice(&info.state.to_le_bytes());
            bytes[36..40].copy_from_slice(&info.protect.to_le_bytes());
            bytes[40..44].copy_from_slice(&info.region_type.to_le_bytes());
        }
        self.modules
            .memory_mut()
            .write(address, &bytes[..capacity.min(bytes.len())])?;
        Ok(struct_size)
    }

    pub(in crate::runtime::engine) fn read_large_integer(
        &self,
        address: u64,
    ) -> Result<u64, VmError> {
        Ok(u64::from_le_bytes(
            self.read_bytes_from_memory(address, 8)?.try_into().unwrap(),
        ))
    }

    pub(in crate::runtime::engine) fn read_unicode_string_value(
        &self,
        address: u64,
    ) -> Result<String, VmError> {
        if address == 0 {
            return Ok(String::new());
        }
        let length = self.read_u16(address)? as usize;
        let buffer = if self.arch.is_x86() {
            self.read_u32(address + 4)? as u64
        } else {
            self.read_pointer_value(address + 8)?
        };
        if buffer == 0 || length == 0 {
            return Ok(String::new());
        }
        self.read_wide_counted_string_from_memory(buffer, length / 2)
    }

    pub(in crate::runtime::engine) fn read_object_attributes_name(
        &self,
        address: u64,
    ) -> Result<String, VmError> {
        if address == 0 {
            return Ok(String::new());
        }
        let object_name = if self.arch.is_x86() {
            self.read_u32(address + 8)? as u64
        } else {
            self.read_pointer_value(address + 16)?
        };
        self.read_unicode_string_value(object_name)
    }

    pub(in crate::runtime::engine) fn create_file_mapping_handle(
        &mut self,
        file_handle: u64,
        protect: u32,
        maximum_size: u64,
        name: &str,
    ) -> Result<u64, VmError> {
        let pagefile_backed = file_handle == 0 || self.is_invalid_handle_value(file_handle);
        let source = if pagefile_backed {
            None
        } else {
            let Some(state) = self.file_handles.get(&(file_handle as u32)) else {
                self.set_last_error(ERROR_INVALID_HANDLE as u32);
                return Ok(0);
            };
            Some(MappingSource {
                path: state.path.clone(),
                file: state
                    .file
                    .try_clone()
                    .map_err(|source| VmError::CommandIo {
                        program: "file try_clone".to_string(),
                        source,
                    })?,
                writable: state.writable,
            })
        };

        let Some(result) = self.file_mappings.create_mapping(
            file_handle as u32,
            protect,
            maximum_size,
            name,
            false,
            source,
        ) else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        };
        self.set_last_error(if result.already_exists {
            ERROR_ALREADY_EXISTS as u32
        } else {
            ERROR_SUCCESS as u32
        });
        Ok(result.handle as u64)
    }

    pub(in crate::runtime::engine) fn open_file_mapping_handle(&mut self, name: &str) -> u64 {
        let Some(handle) = self.file_mappings.open_named_mapping(name) else {
            self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
            return 0;
        };
        self.set_last_error(ERROR_SUCCESS as u32);
        handle as u64
    }

    pub(in crate::runtime::engine) fn map_view_of_file(
        &mut self,
        handle: u32,
        desired_access: u32,
        offset: u64,
        size: u64,
    ) -> Result<u64, VmError> {
        let process_key = self.current_process_space_key();
        let view = {
            let (file_mappings, modules) = (&mut self.file_mappings, &mut self.modules);
            file_mappings.map_view(
                handle,
                process_key,
                desired_access,
                offset,
                size,
                None,
                None,
                "MapViewOfFile",
                modules.memory_mut(),
            )
        };
        let Some(view) = view else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        };
        self.register_mapped_view_allocation(process_key, &view)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(view.base)
    }

    pub(in crate::runtime::engine) fn flush_view_of_file(
        &mut self,
        base: u64,
        size: u64,
    ) -> Result<u64, VmError> {
        let process_key = self.current_process_space_key();
        let (file_mappings, modules) = (&mut self.file_mappings, &mut self.modules);
        if !file_mappings.flush_view(process_key, base, size, modules.memory_mut()) {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn unmap_view_of_file(
        &mut self,
        base: u64,
    ) -> Result<u64, VmError> {
        let process_key = self.current_process_space_key();
        let unmapped = {
            let (file_mappings, modules) = (&mut self.file_mappings, &mut self.modules);
            file_mappings.unmap_view(process_key, base, modules.memory_mut())
        };
        if !unmapped {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        self.unregister_process_virtual_allocation(process_key, base);
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn nt_create_section(
        &mut self,
        section_handle_ptr: u64,
        object_attributes_ptr: u64,
        maximum_size_ptr: u64,
        section_page_protection: u32,
        allocation_attributes: u32,
        file_handle: u64,
    ) -> Result<u64, VmError> {
        if section_handle_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        if !matches!(
            section_page_protection,
            PAGE_NOACCESS
                | PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        ) {
            return Ok(STATUS_INVALID_PAGE_PROTECTION as u64);
        }

        let image = allocation_attributes & SEC_IMAGE != 0;
        let pagefile_backed = file_handle == 0 || self.is_invalid_handle_value(file_handle);
        if image && pagefile_backed {
            return Ok(STATUS_INVALID_FILE_FOR_SECTION as u64);
        }

        let name = self.read_object_attributes_name(object_attributes_ptr)?;
        let maximum_size = if maximum_size_ptr == 0 {
            0
        } else {
            self.read_large_integer(maximum_size_ptr)?
        };
        let source = if pagefile_backed {
            None
        } else {
            let Some(state) = self.file_handles.get(&(file_handle as u32)) else {
                return Ok(STATUS_INVALID_HANDLE as u64);
            };
            Some(MappingSource {
                path: state.path.clone(),
                file: state
                    .file
                    .try_clone()
                    .map_err(|source| VmError::CommandIo {
                        program: "file try_clone".to_string(),
                        source,
                    })?,
                writable: state.writable,
            })
        };

        let Some(result) = self.file_mappings.create_mapping(
            file_handle as u32,
            section_page_protection,
            maximum_size,
            &name,
            image,
            source,
        ) else {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        };
        self.write_pointer_value(section_handle_ptr, result.handle as u64)?;
        Ok(if result.already_exists {
            STATUS_OBJECT_NAME_EXISTS as u64
        } else {
            STATUS_SUCCESS as u64
        })
    }

    pub(in crate::runtime::engine) fn nt_map_view_of_section(
        &mut self,
        section_handle: u32,
        process_handle: u64,
        base_address_ptr: u64,
        section_offset_ptr: u64,
        view_size_ptr: u64,
        protect: u32,
    ) -> Result<u64, VmError> {
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return Ok(STATUS_INVALID_HANDLE as u64);
        };
        if base_address_ptr == 0 || view_size_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let requested_base = self.read_pointer_value(base_address_ptr)?;
        let requested_size = self.read_pointer_value(view_size_ptr)?;
        let section_offset = if section_offset_ptr == 0 {
            0
        } else {
            u64::from_le_bytes(
                self.read_bytes_from_memory(section_offset_ptr, 8)?
                    .try_into()
                    .unwrap(),
            )
        };
        let desired_access = if matches!(protect, PAGE_READWRITE | PAGE_EXECUTE_READWRITE) {
            FILE_MAP_WRITE | FILE_MAP_READ
        } else if matches!(protect, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY) {
            FILE_MAP_COPY | FILE_MAP_READ
        } else if protect == PAGE_NOACCESS {
            0
        } else {
            FILE_MAP_READ
        };
        let view = if process_key == self.current_process_space_key() {
            let (file_mappings, modules) = (&mut self.file_mappings, &mut self.modules);
            file_mappings.map_view(
                section_handle,
                process_key,
                desired_access,
                section_offset,
                requested_size,
                Some(requested_base),
                Some(protect),
                "NtMapViewOfSection",
                modules.memory_mut(),
            )
        } else {
            let arch = self.arch;
            let memory = &mut self
                .process_spaces
                .entry(process_key)
                .or_insert_with(|| SyntheticProcessSpace::new(arch))
                .memory;
            self.file_mappings.map_view(
                section_handle,
                process_key,
                desired_access,
                section_offset,
                requested_size,
                Some(requested_base),
                Some(protect),
                "NtMapViewOfSection",
                memory,
            )
        };
        let Some(view) = view else {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        };
        self.register_mapped_view_allocation(process_handle, &view)?;
        self.write_pointer_value(base_address_ptr, view.base)?;
        self.write_pointer_value(view_size_ptr, view.size)?;
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn nt_unmap_view_of_section(
        &mut self,
        process_handle: u64,
        base_address: u64,
    ) -> Result<u64, VmError> {
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return Ok(STATUS_INVALID_HANDLE as u64);
        };
        let unmapped = if process_key == self.current_process_space_key() {
            let (file_mappings, modules) = (&mut self.file_mappings, &mut self.modules);
            file_mappings.unmap_view(process_key, base_address, modules.memory_mut())
        } else if let Some(space) = self.process_spaces.get_mut(&process_key) {
            self.file_mappings
                .unmap_view(process_key, base_address, &mut space.memory)
        } else {
            false
        };
        if !unmapped {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        self.unregister_process_virtual_allocation(process_handle, base_address);
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn nt_query_virtual_memory(
        &mut self,
        process_handle: u64,
        base_address: u64,
        info_class: u64,
        info_ptr: u64,
        info_len: usize,
        return_len_ptr: u64,
    ) -> Result<u64, VmError> {
        if !self.is_known_process_target(process_handle) {
            return Ok(STATUS_INVALID_HANDLE as u64);
        }
        if info_class != MEMORY_BASIC_INFORMATION_CLASS {
            return Ok(STATUS_INVALID_INFO_CLASS as u64);
        }

        let required = self.memory_basic_information_size();
        if return_len_ptr != 0 {
            self.write_pointer_value(return_len_ptr, required as u64)?;
        }
        if info_ptr == 0 || info_len < required {
            return Ok(STATUS_INFO_LENGTH_MISMATCH as u64);
        }

        let Some(info) =
            self.query_memory_basic_information_for_process(process_handle, base_address)
        else {
            return Ok(STATUS_INVALID_HANDLE as u64);
        };
        let _ = self.write_memory_basic_information(info_ptr, info_len, info)?;
        Ok(STATUS_SUCCESS as u64)
    }
}
