use super::*;
use crate::error::MemoryError;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn base_page_protect(protect: u32) -> u32 {
        protect & !PAGE_GUARD
    }

    pub(in crate::runtime::engine) fn page_protect_has_guard(protect: u32) -> bool {
        protect & PAGE_GUARD != 0
    }

    pub(in crate::runtime::engine) fn page_protect_allows_read(protect: u32) -> bool {
        matches!(
            Self::base_page_protect(protect),
            PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        )
    }

    pub(in crate::runtime::engine) fn page_protect_allows_write(protect: u32) -> bool {
        matches!(
            Self::base_page_protect(protect),
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    pub(in crate::runtime::engine) fn perms_from_page_protect(protect: u32) -> Option<u32> {
        match Self::base_page_protect(protect) {
            PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE => {
                Some(PROT_READ | PROT_WRITE | PROT_EXEC)
            }
            PAGE_EXECUTE_READ => Some(PROT_READ | PROT_EXEC),
            PAGE_EXECUTE => Some(PROT_EXEC),
            PAGE_WRITECOPY | PAGE_READWRITE => Some(PROT_READ | PROT_WRITE),
            PAGE_READONLY => Some(PROT_READ),
            PAGE_NOACCESS => Some(0),
            _ => None,
        }
    }

    pub(in crate::runtime::engine) fn aligned_virtual_range(address: u64, size: u64) -> (u64, u64) {
        let aligned_base = address & !(PAGE_SIZE - 1);
        let aligned_end = address
            .saturating_add(size.max(1))
            .saturating_add(PAGE_SIZE - 1)
            & !(PAGE_SIZE - 1);
        let aligned_size = aligned_end.saturating_sub(aligned_base).max(PAGE_SIZE);
        (aligned_base, aligned_size)
    }

    pub(in crate::runtime::engine) fn consume_guard_pages_on_access(
        &mut self,
        process_handle: u64,
        address: u64,
        size: usize,
    ) -> Vec<(u64, u64, u32)> {
        let Some(record) = self
            .virtual_allocation_record_for_process(process_handle, address)
            .cloned()
        else {
            return Vec::new();
        };
        let end = address.saturating_add(size.max(1) as u64);
        if end > record.end() {
            return Vec::new();
        }
        let guarded_segments = record
            .segments
            .iter()
            .filter(|segment| {
                address < segment.end()
                    && segment.base < end
                    && Self::page_protect_has_guard(segment.protect)
            })
            .map(|segment| (segment.base, segment.size, segment.protect & !PAGE_GUARD))
            .collect::<Vec<_>>();
        if guarded_segments.is_empty() {
            return Vec::new();
        }
        let Some(record) = self.virtual_allocation_record_mut_for_process(process_handle, address)
        else {
            return Vec::new();
        };
        for &(base, size, protect) in &guarded_segments {
            if !record.replace_range(base, size, MEM_COMMIT, protect) {
                return Vec::new();
            }
        }
        guarded_segments
    }

    pub(in crate::runtime::engine) fn insert_virtual_allocation_record(
        &mut self,
        process_handle: u64,
        record: VirtualAllocationRecord,
    ) -> Result<(), VmError> {
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return Ok(());
        };
        if process_key != self.current_process_space_key()
            && !self.process_spaces.contains_key(&process_key)
        {
            let _ = self.ensure_process_space_initialized(process_handle)?;
        }
        if let Some(allocations) = self.process_virtual_allocations_mut(process_key) {
            allocations.insert(record.allocation_base, record);
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn remove_virtual_allocation_record(
        &mut self,
        process_handle: u64,
        allocation_base: u64,
    ) -> Option<VirtualAllocationRecord> {
        let process_key = self.process_space_key_for_handle(process_handle)?;
        self.process_virtual_allocations_mut(process_key)
            .and_then(|allocations| allocations.remove(&allocation_base))
    }

    fn zero_process_memory_range(
        &mut self,
        process_handle: u64,
        base: u64,
        size: u64,
    ) -> Result<(), VmError> {
        let zero_page = vec![0u8; PAGE_SIZE as usize];
        let mut cursor = base;
        let mut remaining = size;
        while remaining != 0 {
            let chunk_len = remaining.min(PAGE_SIZE) as usize;
            let wrote = self.with_process_memory_mut(process_handle, |memory| {
                memory
                    .write(cursor, &zero_page[..chunk_len])
                    .map_err(VmError::from)
            })?;
            if wrote.is_none() {
                break;
            }
            cursor += chunk_len as u64;
            remaining -= chunk_len as u64;
        }
        Ok(())
    }

    fn apply_virtual_allocation_state(
        &mut self,
        process_handle: u64,
        address: u64,
        size: u64,
        state: u32,
        protect: u32,
    ) -> Result<Option<(u64, u64)>, VmError> {
        let (aligned_base, aligned_size) = Self::aligned_virtual_range(address, size);
        let Some(record) =
            self.virtual_allocation_record_mut_for_process(process_handle, aligned_base)
        else {
            return Ok(None);
        };
        if aligned_base < record.allocation_base
            || aligned_base.saturating_add(aligned_size) > record.end()
        {
            return Ok(None);
        }
        if !record.replace_range(aligned_base, aligned_size, state, protect) {
            return Ok(None);
        }
        Ok(Some((aligned_base, aligned_size)))
    }

    fn apply_virtual_protection(
        &mut self,
        process_handle: u64,
        address: u64,
        size: u64,
        new_protect: u32,
        source: &str,
    ) -> Result<Option<(u64, u64, u32)>, VmError> {
        let Some(new_perms) = Self::perms_from_page_protect(new_protect) else {
            return Ok(None);
        };
        if size == 0 {
            return Ok(None);
        }
        if !self.is_current_process_handle(process_handle) {
            self.ensure_process_space_initialized(process_handle)?;
        }
        let (aligned_base, aligned_size) = Self::aligned_virtual_range(address, size);

        let old_protect = if let Some(record) =
            self.virtual_allocation_record_for_process(process_handle, aligned_base)
        {
            let end = aligned_base.saturating_add(aligned_size);
            let Some(first) = record.segment_for_address(aligned_base) else {
                return Ok(None);
            };
            let old_protect = first.protect;
            if first.state != MEM_COMMIT
                || record
                    .segments
                    .iter()
                    .filter(|segment| aligned_base < segment.end() && segment.base < end)
                    .any(|segment| segment.state != MEM_COMMIT)
            {
                return Ok(None);
            }
            let protected = self.with_process_memory_mut(process_handle, |memory| match memory
                .protect(aligned_base, aligned_size, new_perms)
            {
                Ok(()) => Ok(true),
                Err(MemoryError::MissingRegion { .. }) => Ok(false),
                Err(error) => Err(VmError::from(error)),
            })?;
            if protected != Some(true) {
                return Ok(None);
            }
            let Some(record) =
                self.virtual_allocation_record_mut_for_process(process_handle, aligned_base)
            else {
                return Ok(None);
            };
            if !record.replace_range(aligned_base, aligned_size, MEM_COMMIT, new_protect) {
                return Ok(None);
            }
            old_protect
        } else {
            let old_protect = self
                .with_process_memory(process_handle, |memory| {
                    memory
                        .find_region(aligned_base, 1)
                        .map(|region| Self::page_protect_from_perms(region.perms))
                })
                .flatten();
            let Some(old_protect) = old_protect else {
                return Ok(None);
            };
            let protected = self.with_process_memory_mut(process_handle, |memory| match memory
                .protect(aligned_base, aligned_size, new_perms)
            {
                Ok(()) => Ok(true),
                Err(MemoryError::MissingRegion { .. }) => Ok(false),
                Err(error) => Err(VmError::from(error)),
            })?;
            if protected != Some(true) {
                return Ok(None);
            }
            old_protect
        };
        if self.is_current_process_handle(process_handle) {
            self.sync_current_process_native_page_protection(aligned_base, aligned_size)?;
        }

        let mut fields = Map::new();
        fields.insert("source".to_string(), json!(source));
        fields.insert("process_handle".to_string(), json!(process_handle));
        fields.insert("address".to_string(), json!(address));
        fields.insert("base".to_string(), json!(aligned_base));
        fields.insert("size".to_string(), json!(aligned_size));
        fields.insert("old_protect".to_string(), json!(old_protect));
        fields.insert("new_protect".to_string(), json!(new_protect));
        self.log_runtime_event("MEM_PROTECT", fields)?;
        let remote = !self.is_current_process_handle(process_handle);
        self.log_memory_protection_dump(
            process_handle,
            aligned_base,
            aligned_size,
            old_protect,
            new_protect,
            source,
            remote,
        )?;
        Ok(Some((aligned_base, aligned_size, old_protect)))
    }

    pub(in crate::runtime::engine) fn virtual_protect(
        &mut self,
        process_handle: u64,
        address: u64,
        size: u64,
        new_protect: u32,
        old_protect_ptr: u64,
        source: &str,
    ) -> Result<u64, VmError> {
        if !self.is_known_process_target(process_handle) {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }
        if old_protect_ptr == 0 || size == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        if Self::perms_from_page_protect(new_protect).is_none() {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let Some((_, _, old_protect)) =
            self.apply_virtual_protection(process_handle, address, size, new_protect, source)?
        else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        };
        self.write_u32(old_protect_ptr, old_protect)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn nt_protect_virtual_memory(
        &mut self,
        process_handle: u64,
        base_address_ptr: u64,
        region_size_ptr: u64,
        new_protect: u32,
        old_protect_ptr: u64,
        source: &str,
    ) -> Result<u64, VmError> {
        if !self.is_known_process_target(process_handle) {
            return Ok(STATUS_INVALID_HANDLE as u64);
        }
        if base_address_ptr == 0 || region_size_ptr == 0 || old_protect_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        if Self::perms_from_page_protect(new_protect).is_none() {
            return Ok(STATUS_INVALID_PAGE_PROTECTION as u64);
        }
        let address = self.read_pointer_value(base_address_ptr)?;
        let size = self.read_pointer_value(region_size_ptr)?;
        if size == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let Some((aligned_base, aligned_size, old_protect)) =
            self.apply_virtual_protection(process_handle, address, size, new_protect, source)?
        else {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        };
        self.write_pointer_value(base_address_ptr, aligned_base)?;
        self.write_pointer_value(region_size_ptr, aligned_size)?;
        self.write_u32(old_protect_ptr, old_protect)?;
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn nt_allocate_virtual_memory(
        &mut self,
        process_handle: u64,
        base_address_ptr: u64,
        region_size_ptr: u64,
        allocation_type: u32,
        protect: u32,
        source: &str,
    ) -> Result<u64, VmError> {
        if !self.is_known_process_target(process_handle) {
            return Ok(STATUS_INVALID_HANDLE as u64);
        }
        if base_address_ptr == 0 || region_size_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let requested = self.read_pointer_value(base_address_ptr)?;
        let size = self.read_pointer_value(region_size_ptr)?;
        if size == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let address = self.allocate_virtual_region(
            process_handle,
            requested,
            size,
            allocation_type,
            protect,
            source,
            !self.is_current_process_handle(process_handle),
        )?;
        if address == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let (_, allocation_size) = Self::aligned_virtual_range(address, size);
        self.write_pointer_value(base_address_ptr, address)?;
        self.write_pointer_value(region_size_ptr, allocation_size)?;
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn nt_free_virtual_memory(
        &mut self,
        process_handle: u64,
        base_address_ptr: u64,
        region_size_ptr: u64,
        free_type: u64,
        source: &str,
    ) -> Result<u64, VmError> {
        if !self.is_known_process_target(process_handle) {
            return Ok(STATUS_INVALID_HANDLE as u64);
        }
        if base_address_ptr == 0 || region_size_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let address = self.read_pointer_value(base_address_ptr)?;
        let size = self.read_pointer_value(region_size_ptr)?;
        let (aligned_base, aligned_size) = Self::aligned_virtual_range(address, size.max(1));
        if self.free_virtual_region(process_handle, address, size, free_type, source)? == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        if free_type & MEM_RELEASE != 0 {
            self.write_pointer_value(base_address_ptr, 0)?;
            self.write_pointer_value(region_size_ptr, 0)?;
        } else if free_type & MEM_DECOMMIT != 0 {
            self.write_pointer_value(base_address_ptr, aligned_base)?;
            self.write_pointer_value(region_size_ptr, aligned_size)?;
        }
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn allocate_virtual_region(
        &mut self,
        process_handle: u64,
        requested: u64,
        size: u64,
        allocation_type: u32,
        protect: u32,
        source: &str,
        remote: bool,
    ) -> Result<u64, VmError> {
        let allocation_size = size.max(1);
        let reserve = allocation_type & MEM_RESERVE != 0;
        let commit = allocation_type & MEM_COMMIT != 0;
        if !reserve && !commit {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let Some(perms) = Self::perms_from_page_protect(protect) else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        };
        let address = if reserve {
            let Some(address) = self.with_process_memory_mut(process_handle, |memory| {
                let address = memory
                    .reserve(
                        allocation_size,
                        if requested == 0 {
                            None
                        } else {
                            Some(requested)
                        },
                        source,
                        true,
                    )
                    .map_err(VmError::from)?;
                memory
                    .protect(address, allocation_size, if commit { perms } else { 0 })
                    .map_err(VmError::from)?;
                Ok(address)
            })?
            else {
                return Ok(0);
            };
            let (_, aligned_size) = Self::aligned_virtual_range(address, allocation_size);
            self.insert_virtual_allocation_record(
                process_handle,
                VirtualAllocationRecord {
                    allocation_base: address,
                    allocation_size: aligned_size,
                    allocation_protect: protect,
                    allocation_type,
                    region_type: MEM_PRIVATE,
                    segments: vec![VirtualAllocationSegment {
                        base: address,
                        size: aligned_size,
                        state: if commit { MEM_COMMIT } else { MEM_RESERVE },
                        protect: if commit { protect } else { 0 },
                    }],
                },
            )?;
            address
        } else {
            if requested == 0 {
                self.set_last_error(ERROR_INVALID_ADDRESS as u32);
                return Ok(0);
            }
            let (aligned_base, aligned_size) =
                Self::aligned_virtual_range(requested, allocation_size);
            let Some(record) =
                self.virtual_allocation_record_for_process(process_handle, aligned_base)
            else {
                self.set_last_error(ERROR_INVALID_ADDRESS as u32);
                return Ok(0);
            };
            let end = aligned_base.saturating_add(aligned_size);
            if aligned_base < record.allocation_base
                || end > record.end()
                || record
                    .segments
                    .iter()
                    .filter(|segment| aligned_base < segment.end() && segment.base < end)
                    .any(|segment| segment.state != MEM_RESERVE)
            {
                self.set_last_error(ERROR_INVALID_ADDRESS as u32);
                return Ok(0);
            }
            let committed = self.with_process_memory_mut(process_handle, |memory| match memory
                .protect(aligned_base, aligned_size, perms)
            {
                Ok(()) => Ok(true),
                Err(MemoryError::MissingRegion { .. }) => Ok(false),
                Err(error) => Err(VmError::from(error)),
            })?;
            if committed != Some(true)
                || self
                    .apply_virtual_allocation_state(
                        process_handle,
                        aligned_base,
                        aligned_size,
                        MEM_COMMIT,
                        protect,
                    )?
                    .is_none()
            {
                self.set_last_error(ERROR_INVALID_ADDRESS as u32);
                return Ok(0);
            }
            self.zero_process_memory_range(process_handle, aligned_base, aligned_size)?;
            aligned_base
        };
        let mut fields = Map::new();
        fields.insert("source".to_string(), json!(source));
        fields.insert("process_handle".to_string(), json!(process_handle));
        fields.insert("requested".to_string(), json!(requested));
        fields.insert("address".to_string(), json!(address));
        fields.insert("size".to_string(), json!(allocation_size));
        fields.insert("allocation_type".to_string(), json!(allocation_type));
        fields.insert("protect".to_string(), json!(protect));
        fields.insert("remote".to_string(), json!(remote));
        self.log_runtime_event("MEM_ALLOC", fields)?;
        Ok(address)
    }

    pub(in crate::runtime::engine) fn free_virtual_region(
        &mut self,
        process_handle: u64,
        address: u64,
        size: u64,
        free_type: u64,
        source: &str,
    ) -> Result<u64, VmError> {
        let (base, region_size) = if let Some(record) = self
            .virtual_allocation_record_for_process(process_handle, address)
            .cloned()
        {
            if free_type & MEM_RELEASE != 0 {
                if address != record.allocation_base || size != 0 {
                    return Ok(0);
                }
                let _ =
                    self.remove_virtual_allocation_record(process_handle, record.allocation_base);
                let unmapped = self.with_process_memory_mut(process_handle, |memory| {
                    memory
                        .unmap(record.allocation_base, record.allocation_size)
                        .map_err(VmError::from)
                })?;
                if unmapped.is_none() {
                    return Ok(0);
                }
                (record.allocation_base, record.allocation_size)
            } else if free_type & MEM_DECOMMIT != 0 {
                if size == 0 {
                    return Ok(0);
                }
                let (aligned_base, aligned_size) = Self::aligned_virtual_range(address, size);
                let end = aligned_base.saturating_add(aligned_size);
                if aligned_base < record.allocation_base
                    || end > record.end()
                    || record
                        .segments
                        .iter()
                        .filter(|segment| aligned_base < segment.end() && segment.base < end)
                        .any(|segment| segment.state != MEM_COMMIT)
                {
                    return Ok(0);
                }
                let decommitted = self.with_process_memory_mut(process_handle, |memory| {
                    match memory.protect(aligned_base, aligned_size, 0) {
                        Ok(()) => Ok(true),
                        Err(MemoryError::MissingRegion { .. }) => Ok(false),
                        Err(error) => Err(VmError::from(error)),
                    }
                })?;
                if decommitted != Some(true)
                    || self
                        .apply_virtual_allocation_state(
                            process_handle,
                            aligned_base,
                            aligned_size,
                            MEM_RESERVE,
                            0,
                        )?
                        .is_none()
                {
                    return Ok(0);
                }
                self.zero_process_memory_range(process_handle, aligned_base, aligned_size)?;
                (aligned_base, aligned_size)
            } else {
                return Ok(0);
            }
        } else {
            let region = self.with_process_memory(process_handle, |memory| {
                memory
                    .find_region(address, 1)
                    .map(|region| (region.base, region.size))
            });
            let Some(Some((base, region_size))) = region else {
                return Ok(0);
            };
            if free_type & MEM_RELEASE != 0 || size == 0 {
                let _ = self.with_process_memory_mut(process_handle, |memory| {
                    memory.unmap(base, region_size).map_err(VmError::from)
                })?;
            } else {
                return Ok(0);
            }
            (base, region_size)
        };
        let mut fields = Map::new();
        fields.insert("source".to_string(), json!(source));
        fields.insert("process_handle".to_string(), json!(process_handle));
        fields.insert("address".to_string(), json!(address));
        fields.insert("base".to_string(), json!(base));
        fields.insert("size".to_string(), json!(region_size));
        fields.insert("free_type".to_string(), json!(free_type));
        self.log_runtime_event("MEM_FREE", fields)?;
        Ok(1)
    }

    pub(in crate::runtime::engine) fn read_process_memory(
        &mut self,
        process_handle: u64,
        base_address: u64,
        buffer: u64,
        size: usize,
        bytes_read_ptr: u64,
    ) -> Result<u64, VmError> {
        if !self.is_known_process_target(process_handle) {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }
        let guard_cleared = self.consume_guard_pages_on_access(process_handle, base_address, size);
        if !guard_cleared.is_empty() {
            if self.is_current_process_handle(process_handle) {
                for (base, size, _) in &guard_cleared {
                    self.sync_current_process_native_page_protection(*base, *size)?;
                }
            }
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            if bytes_read_ptr != 0 {
                self.write_pointer_value(bytes_read_ptr, 0)?;
            }
            return Ok(0);
        }
        if matches!(
            self.virtual_allocation_range_is_accessible(process_handle, base_address, size, false),
            Some(false)
        ) {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            if bytes_read_ptr != 0 {
                self.write_pointer_value(bytes_read_ptr, 0)?;
            }
            return Ok(0);
        }
        let Some(bytes) = self.with_process_memory(process_handle, |memory| {
            memory.read(base_address, size).ok()
        }) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let Some(bytes) = bytes else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            if bytes_read_ptr != 0 {
                self.write_pointer_value(bytes_read_ptr, 0)?;
            }
            return Ok(0);
        };
        if buffer == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            if bytes_read_ptr != 0 {
                self.write_pointer_value(bytes_read_ptr, 0)?;
            }
            return Ok(0);
        }
        self.modules.memory_mut().write(buffer, &bytes)?;
        if bytes_read_ptr != 0 {
            self.write_pointer_value(bytes_read_ptr, bytes.len() as u64)?;
        }
        let mut fields = Map::new();
        fields.insert("process_handle".to_string(), json!(process_handle));
        fields.insert("base_address".to_string(), json!(base_address));
        fields.insert("size".to_string(), json!(bytes.len()));
        self.log_runtime_event("MEM_READ", fields)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn write_process_memory(
        &mut self,
        process_handle: u64,
        base_address: u64,
        buffer: u64,
        size: usize,
        bytes_written_ptr: u64,
    ) -> Result<u64, VmError> {
        if !self.is_known_process_target(process_handle) {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }
        let data = self.read_bytes_from_memory(buffer, size)?;
        let guard_cleared =
            self.consume_guard_pages_on_access(process_handle, base_address, data.len());
        if !guard_cleared.is_empty() {
            if self.is_current_process_handle(process_handle) {
                for (base, size, _) in &guard_cleared {
                    self.sync_current_process_native_page_protection(*base, *size)?;
                }
            }
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            if bytes_written_ptr != 0 {
                self.write_pointer_value(bytes_written_ptr, 0)?;
            }
            return Ok(0);
        }
        if matches!(
            self.virtual_allocation_range_is_accessible(
                process_handle,
                base_address,
                data.len(),
                true,
            ),
            Some(false)
        ) {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            if bytes_written_ptr != 0 {
                self.write_pointer_value(bytes_written_ptr, 0)?;
            }
            return Ok(0);
        }
        let wrote = self
            .with_process_memory_mut(process_handle, |memory| {
                if !memory.is_range_mapped(base_address, data.len() as u64) {
                    return Ok(false);
                }
                memory.write(base_address, &data).map_err(VmError::from)?;
                Ok(true)
            })?
            .unwrap_or(false);
        if !wrote {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            if bytes_written_ptr != 0 {
                self.write_pointer_value(bytes_written_ptr, 0)?;
            }
            return Ok(0);
        }
        self.propagate_file_mapping_write(process_handle, base_address, &data)?;
        if bytes_written_ptr != 0 {
            self.write_pointer_value(bytes_written_ptr, data.len() as u64)?;
        }
        let mut fields = Map::new();
        fields.insert("process_handle".to_string(), json!(process_handle));
        fields.insert("base_address".to_string(), json!(base_address));
        fields.insert("size".to_string(), json!(data.len()));
        Self::add_payload_preview_field(&mut fields, &data);
        self.log_runtime_event("MEM_WRITE", fields)?;
        self.log_memory_write_dump(
            process_handle,
            base_address,
            buffer,
            &data,
            "WriteProcessMemory",
            !self.is_current_process_handle(process_handle),
        )?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn nt_read_virtual_memory(
        &mut self,
        process_handle: u64,
        base_address: u64,
        buffer: u64,
        size: usize,
        bytes_read_ptr: u64,
    ) -> Result<u64, VmError> {
        if !self.is_known_process_target(process_handle) {
            if bytes_read_ptr != 0 {
                self.write_pointer_value(bytes_read_ptr, 0)?;
            }
            return Ok(STATUS_INVALID_HANDLE as u64);
        }
        if buffer == 0 {
            if bytes_read_ptr != 0 {
                self.write_pointer_value(bytes_read_ptr, 0)?;
            }
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let guard_cleared = self.consume_guard_pages_on_access(process_handle, base_address, size);
        if !guard_cleared.is_empty() {
            if self.is_current_process_handle(process_handle) {
                for (base, size, _) in &guard_cleared {
                    self.sync_current_process_native_page_protection(*base, *size)?;
                }
            }
            if bytes_read_ptr != 0 {
                self.write_pointer_value(bytes_read_ptr, 0)?;
            }
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        if matches!(
            self.virtual_allocation_range_is_accessible(process_handle, base_address, size, false),
            Some(false)
        ) {
            if bytes_read_ptr != 0 {
                self.write_pointer_value(bytes_read_ptr, 0)?;
            }
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let Some(bytes) = self.with_process_memory(process_handle, |memory| {
            memory.read(base_address, size).ok()
        }) else {
            if bytes_read_ptr != 0 {
                self.write_pointer_value(bytes_read_ptr, 0)?;
            }
            return Ok(STATUS_INVALID_HANDLE as u64);
        };
        let Some(bytes) = bytes else {
            if bytes_read_ptr != 0 {
                self.write_pointer_value(bytes_read_ptr, 0)?;
            }
            return Ok(STATUS_INVALID_PARAMETER as u64);
        };

        self.modules.memory_mut().write(buffer, &bytes)?;
        if bytes_read_ptr != 0 {
            self.write_pointer_value(bytes_read_ptr, bytes.len() as u64)?;
        }
        let mut fields = Map::new();
        fields.insert("process_handle".to_string(), json!(process_handle));
        fields.insert("base_address".to_string(), json!(base_address));
        fields.insert("size".to_string(), json!(bytes.len()));
        self.log_runtime_event("MEM_READ", fields)?;
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn nt_write_virtual_memory(
        &mut self,
        process_handle: u64,
        base_address: u64,
        buffer: u64,
        size: usize,
        bytes_written_ptr: u64,
    ) -> Result<u64, VmError> {
        if !self.is_known_process_target(process_handle) {
            if bytes_written_ptr != 0 {
                self.write_pointer_value(bytes_written_ptr, 0)?;
            }
            return Ok(STATUS_INVALID_HANDLE as u64);
        }
        let data = self.read_bytes_from_memory(buffer, size)?;
        let guard_cleared =
            self.consume_guard_pages_on_access(process_handle, base_address, data.len());
        if !guard_cleared.is_empty() {
            if self.is_current_process_handle(process_handle) {
                for (base, size, _) in &guard_cleared {
                    self.sync_current_process_native_page_protection(*base, *size)?;
                }
            }
            if bytes_written_ptr != 0 {
                self.write_pointer_value(bytes_written_ptr, 0)?;
            }
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        if matches!(
            self.virtual_allocation_range_is_accessible(
                process_handle,
                base_address,
                data.len(),
                true,
            ),
            Some(false)
        ) {
            if bytes_written_ptr != 0 {
                self.write_pointer_value(bytes_written_ptr, 0)?;
            }
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let wrote = self
            .with_process_memory_mut(process_handle, |memory| {
                if !memory.is_range_mapped(base_address, data.len() as u64) {
                    return Ok(false);
                }
                memory.write(base_address, &data).map_err(VmError::from)?;
                Ok(true)
            })?
            .unwrap_or(false);
        if !wrote {
            if bytes_written_ptr != 0 {
                self.write_pointer_value(bytes_written_ptr, 0)?;
            }
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        self.propagate_file_mapping_write(process_handle, base_address, &data)?;
        if bytes_written_ptr != 0 {
            self.write_pointer_value(bytes_written_ptr, data.len() as u64)?;
        }
        let mut fields = Map::new();
        fields.insert("process_handle".to_string(), json!(process_handle));
        fields.insert("base_address".to_string(), json!(base_address));
        fields.insert("size".to_string(), json!(data.len()));
        Self::add_payload_preview_field(&mut fields, &data);
        self.log_runtime_event("MEM_WRITE", fields)?;
        self.log_memory_write_dump(
            process_handle,
            base_address,
            buffer,
            &data,
            "NtWriteVirtualMemory",
            !self.is_current_process_handle(process_handle),
        )?;
        Ok(STATUS_SUCCESS as u64)
    }
}
