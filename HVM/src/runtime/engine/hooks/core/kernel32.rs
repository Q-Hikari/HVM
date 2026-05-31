use super::*;

const IMAGE_DIRECTORY_ENTRY_RESOURCE: u32 = 2;
const IMAGE_RESOURCE_NAME_IS_STRING: u32 = 0x8000_0000;
const IMAGE_RESOURCE_DATA_IS_DIRECTORY: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResourceIdentifier {
    Id(u16),
    Text(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResourceDataDescriptor {
    module_base: u64,
    entry_address: u64,
    data_address: u64,
    size: u32,
}

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_kernel32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        signature: &HookSignature,
        stub_address: u64,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        if module_name != "kernel32.dll" {
            return None;
        }

        // Delegate to sub-dispatchers grouped by functionality.
        // Each returns Some(result) if it handles the function, None otherwise.
        self.dispatch_k32_handle_sync(function, signature, stub_address, ctx)
            .or_else(|| self.dispatch_k32_system_query(function, signature, stub_address, ctx))
            .or_else(|| self.dispatch_k32_time_file(function, signature, stub_address, ctx))
            .or_else(|| self.dispatch_k32_heap_memory(function, signature, stub_address, ctx))
            .or_else(|| {
                self.log_unsupported_runtime_stub(
                    signature,
                    stub_address,
                    "missing runtime implementation",
                )
                .ok()?;
                Some(Err(VmError::NativeExecution {
                    op: "dispatch",
                    detail: format!(
                        "missing runtime implementation for {}!{}",
                        signature.module, signature.function
                    ),
                }))
            })
    }
}

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn find_resource_common(
        &mut self,
        module_handle: u64,
        name_ptr: u64,
        type_ptr: u64,
        wide: bool,
        language: Option<u16>,
    ) -> Result<u64, VmError> {
        let Some(module) = self.module_record_for_handle(module_handle).cloned() else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let Some(resource_type) = self.read_resource_identifier(type_ptr, wide)? else {
            self.set_last_error(ERROR_RESOURCE_TYPE_NOT_FOUND as u32);
            return Ok(0);
        };
        let Some(resource_name) = self.read_resource_identifier(name_ptr, wide)? else {
            self.set_last_error(ERROR_RESOURCE_NAME_NOT_FOUND as u32);
            return Ok(0);
        };
        let Some((resource_root, _)) = self.module_resource_directory(&module)? else {
            self.set_last_error(ERROR_RESOURCE_TYPE_NOT_FOUND as u32);
            return Ok(0);
        };
        let Some(type_directory) =
            self.find_resource_subdirectory(resource_root, resource_root, &resource_type)?
        else {
            self.set_last_error(ERROR_RESOURCE_TYPE_NOT_FOUND as u32);
            return Ok(0);
        };
        let Some(name_directory) =
            self.find_resource_subdirectory(resource_root, type_directory, &resource_name)?
        else {
            self.set_last_error(ERROR_RESOURCE_NAME_NOT_FOUND as u32);
            return Ok(0);
        };
        let Some(resource_entry) =
            self.select_resource_data_entry(resource_root, name_directory, language)?
        else {
            self.set_last_error(ERROR_RESOURCE_LANG_NOT_FOUND as u32);
            return Ok(0);
        };
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(resource_entry)
    }

    pub(in crate::runtime::engine) fn load_resource_handle(
        &mut self,
        module_handle: u64,
        resource_handle: u64,
    ) -> Result<u64, VmError> {
        let expected_module_base = if module_handle == 0 {
            self.module_record_for_handle(0).map(|module| module.base)
        } else {
            let Some(module) = self.module_record_for_handle(module_handle) else {
                self.set_last_error(ERROR_INVALID_HANDLE as u32);
                return Ok(0);
            };
            Some(module.base)
        };
        let Some(resource) = self.resource_data_descriptor(resource_handle)? else {
            self.set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND as u32);
            return Ok(0);
        };
        if expected_module_base.is_some_and(|base| base != resource.module_base) {
            self.set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND as u32);
            return Ok(0);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(resource_handle)
    }

    pub(in crate::runtime::engine) fn lock_resource_data(
        &mut self,
        resource_handle: u64,
    ) -> Result<u64, VmError> {
        let Some(resource) = self.resource_data_descriptor(resource_handle)? else {
            self.set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND as u32);
            return Ok(0);
        };
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(resource.data_address)
    }

    pub(in crate::runtime::engine) fn sizeof_resource_data(
        &mut self,
        module_handle: u64,
        resource_handle: u64,
    ) -> Result<u64, VmError> {
        let expected_module_base = if module_handle == 0 {
            self.module_record_for_handle(0).map(|module| module.base)
        } else {
            let Some(module) = self.module_record_for_handle(module_handle) else {
                self.set_last_error(ERROR_INVALID_HANDLE as u32);
                return Ok(0);
            };
            Some(module.base)
        };
        let Some(resource) = self.resource_data_descriptor(resource_handle)? else {
            self.set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND as u32);
            return Ok(0);
        };
        if expected_module_base.is_some_and(|base| base != resource.module_base) {
            self.set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND as u32);
            return Ok(0);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(resource.size as u64)
    }

    fn read_resource_identifier(
        &self,
        value: u64,
        wide: bool,
    ) -> Result<Option<ResourceIdentifier>, VmError> {
        if value == 0 {
            return Ok(None);
        }
        if value <= u16::MAX as u64 {
            return Ok(Some(ResourceIdentifier::Id(value as u16)));
        }
        let text = if wide {
            self.read_wide_string_from_memory(value)?
        } else {
            self.read_c_string_from_memory(value)?
        };
        if let Some(raw_id) = text.strip_prefix('#') {
            if let Ok(id) = raw_id.parse::<u16>() {
                return Ok(Some(ResourceIdentifier::Id(id)));
            }
        }
        Ok(Some(ResourceIdentifier::Text(text)))
    }

    fn module_resource_directory(
        &self,
        module: &ModuleRecord,
    ) -> Result<Option<(u64, u32)>, VmError> {
        self.image_data_directory(module, IMAGE_DIRECTORY_ENTRY_RESOURCE)
    }

    fn image_data_directory(
        &self,
        module: &ModuleRecord,
        index: u32,
    ) -> Result<Option<(u64, u32)>, VmError> {
        if module.synthetic || module.base == 0 {
            return Ok(None);
        }
        let e_lfanew = self.read_u32(module.base + 0x3C)? as u64;
        let optional_header = module.base + e_lfanew + 4 + 20;
        let magic = self.read_u16(optional_header)?;
        let (number_of_rva_and_sizes_offset, data_directory_offset) = match magic {
            0x10B => (0x5C, 0x60),
            0x20B => (0x6C, 0x70),
            _ => return Ok(None),
        };
        let number_of_rva_and_sizes =
            self.read_u32(optional_header + number_of_rva_and_sizes_offset)?;
        if number_of_rva_and_sizes <= index {
            return Ok(None);
        }
        let directory = optional_header + data_directory_offset + index as u64 * 8;
        let rva = self.read_u32(directory)?;
        let size = self.read_u32(directory + 4)?;
        if rva == 0 || size < 16 {
            return Ok(None);
        }
        Ok(Some((module.base + rva as u64, size)))
    }

    fn find_resource_subdirectory(
        &self,
        resource_root: u64,
        directory: u64,
        identifier: &ResourceIdentifier,
    ) -> Result<Option<u64>, VmError> {
        let Some((target, is_directory)) =
            self.find_resource_entry(resource_root, directory, identifier)?
        else {
            return Ok(None);
        };
        Ok(is_directory.then_some(target))
    }

    fn find_resource_entry(
        &self,
        resource_root: u64,
        directory: u64,
        identifier: &ResourceIdentifier,
    ) -> Result<Option<(u64, bool)>, VmError> {
        let entry_count = self.resource_directory_entry_count(directory)?;
        let mut case_insensitive_match = None;
        for index in 0..entry_count {
            let entry = directory + 16 + index as u64 * 8;
            let name_raw = self.read_u32(entry)?;
            let Some(match_rank) =
                self.resource_identifier_match_rank(resource_root, name_raw, identifier)?
            else {
                continue;
            };
            let data_raw = self.read_u32(entry + 4)?;
            let target = resource_root + (data_raw & !IMAGE_RESOURCE_DATA_IS_DIRECTORY) as u64;
            let is_directory = data_raw & IMAGE_RESOURCE_DATA_IS_DIRECTORY != 0;
            if match_rank == 0 {
                return Ok(Some((target, is_directory)));
            }
            if case_insensitive_match.is_none() {
                case_insensitive_match = Some((target, is_directory));
            }
        }
        Ok(case_insensitive_match)
    }

    fn resource_identifier_match_rank(
        &self,
        resource_root: u64,
        name_raw: u32,
        identifier: &ResourceIdentifier,
    ) -> Result<Option<u8>, VmError> {
        match identifier {
            ResourceIdentifier::Id(id) => Ok((name_raw & IMAGE_RESOURCE_NAME_IS_STRING == 0
                && (name_raw & 0xFFFF) == *id as u32)
                .then_some(0)),
            ResourceIdentifier::Text(text) => {
                if name_raw & IMAGE_RESOURCE_NAME_IS_STRING == 0 {
                    return Ok(None);
                }
                let entry_name = self.read_resource_directory_string(
                    resource_root + (name_raw & !IMAGE_RESOURCE_NAME_IS_STRING) as u64,
                )?;
                if entry_name == *text {
                    Ok(Some(0))
                } else if entry_name.is_ascii()
                    && text.is_ascii()
                    && entry_name.eq_ignore_ascii_case(text)
                {
                    Ok(Some(1))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn read_resource_directory_string(&self, address: u64) -> Result<String, VmError> {
        let length = self.read_u16(address)? as usize;
        let bytes = self.read_bytes_from_memory(address + 2, length * 2)?;
        let words = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        Ok(String::from_utf16_lossy(&words))
    }

    fn select_resource_data_entry(
        &self,
        resource_root: u64,
        directory: u64,
        requested_language: Option<u16>,
    ) -> Result<Option<u64>, VmError> {
        let entry_count = self.resource_directory_entry_count(directory)?;
        let mut entries = Vec::new();
        for index in 0..entry_count {
            let entry = directory + 16 + index as u64 * 8;
            let name_raw = self.read_u32(entry)?;
            let data_raw = self.read_u32(entry + 4)?;
            if data_raw & IMAGE_RESOURCE_DATA_IS_DIRECTORY != 0 {
                continue;
            }
            let language = (name_raw & IMAGE_RESOURCE_NAME_IS_STRING == 0)
                .then_some((name_raw & 0xFFFF) as u16);
            entries.push((
                language,
                resource_root + (data_raw & !IMAGE_RESOURCE_DATA_IS_DIRECTORY) as u64,
            ));
        }
        if entries.is_empty() {
            return Ok(None);
        }
        if let Some(language) = requested_language.filter(|value| *value != 0) {
            if let Some((_, entry)) = entries
                .iter()
                .find(|(candidate, _)| *candidate == Some(language))
            {
                return Ok(Some(*entry));
            }
            let primary_language = language & 0x03FF;
            if let Some((_, entry)) = entries.iter().find(|(candidate, _)| {
                candidate
                    .map(|value| value & 0x03FF == primary_language)
                    .unwrap_or(false)
            }) {
                return Ok(Some(*entry));
            }
            if let Some((_, entry)) = entries
                .iter()
                .find(|(candidate, _)| matches!(candidate, Some(0) | Some(0x0400)))
            {
                return Ok(Some(*entry));
            }
        }
        Ok(Some(entries[0].1))
    }

    fn resource_directory_entry_count(&self, directory: u64) -> Result<usize, VmError> {
        Ok((self.read_u16(directory + 12)? as usize) + (self.read_u16(directory + 14)? as usize))
    }

    fn resource_data_descriptor(
        &self,
        resource_handle: u64,
    ) -> Result<Option<ResourceDataDescriptor>, VmError> {
        if resource_handle == 0 {
            return Ok(None);
        }
        let Some(module) = self.core.modules.get_by_address(resource_handle).cloned() else {
            return Ok(None);
        };
        let Some((resource_root, resource_size)) = self.module_resource_directory(&module)? else {
            return Ok(None);
        };
        let Some(resource_entry_end) = resource_handle.checked_add(16) else {
            return Ok(None);
        };
        let resource_root_end = resource_root.saturating_add(resource_size as u64);
        if resource_handle < resource_root || resource_entry_end > resource_root_end {
            return Ok(None);
        }
        let data_rva = self.read_u32(resource_handle)?;
        let size = self.read_u32(resource_handle + 4)?;
        if data_rva == 0 || size == 0 {
            return Ok(None);
        }
        let data_address = module.base + data_rva as u64;
        let Some(data_end) = data_address.checked_add(size as u64) else {
            return Ok(None);
        };
        if data_address < module.base || data_end > module.base + module.size {
            return Ok(None);
        }
        Ok(Some(ResourceDataDescriptor {
            module_base: module.base,
            entry_address: resource_handle,
            data_address,
            size,
        }))
    }
}
