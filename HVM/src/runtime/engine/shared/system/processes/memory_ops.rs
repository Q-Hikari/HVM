use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn sync_current_process_native_page_protection(
        &mut self,
        address: u64,
        size: u64,
    ) -> Result<(), VmError> {
        let (Some(unicorn), Some(handle)) = (
            self.unicorn_state.unicorn.as_deref(),
            self.unicorn_state.unicorn_handle,
        ) else {
            return Ok(());
        };
        let (aligned_base, aligned_size) = Self::aligned_virtual_range(address, size.max(1));
        let end = aligned_base.saturating_add(aligned_size);
        let mut cursor = aligned_base;
        while cursor < end {
            if let Some(info) = self
                .virtual_allocation_snapshot_for_process(self.current_process_space_key(), cursor)
            {
                let perms = if info.state == MEM_COMMIT {
                    if Self::page_protect_has_guard(info.protect) {
                        0
                    } else {
                        Self::perms_from_page_protect(info.protect).unwrap_or(0)
                    }
                } else {
                    0
                };
                unsafe {
                    unicorn.mem_protect_raw(
                        handle,
                        info.base_address,
                        info.region_size,
                        unicorn_prot(perms),
                    )
                }
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_mem_protect",
                    detail,
                })?;
                cursor = info.base_address.saturating_add(info.region_size);
                continue;
            }
            if let Some(region) = self.core.modules.memory().find_region(cursor, 1) {
                unsafe {
                    unicorn.mem_protect_raw(
                        handle,
                        region.base,
                        region.size,
                        unicorn_prot(region.perms),
                    )
                }
                .map_err(|detail| VmError::NativeExecution {
                    op: "uc_mem_protect",
                    detail,
                })?;
                cursor = region.base.saturating_add(region.size);
            } else {
                cursor = (cursor + PAGE_SIZE) & !(PAGE_SIZE - 1);
            }
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn open_process_handle_by_pid(
        &mut self,
        pid: u32,
    ) -> Option<u64> {
        // If the PID is unknown, create a synthetic process identity so that
        // VirtualAllocEx / WriteProcessMemory / CreateRemoteThread can still
        // target it.  Many malware samples OpenProcess on a PID discovered via
        // process enumeration and inject into it.
        if self.process_identity_by_pid(pid).is_none() {
            // Avoid duplicate entries for the same PID.
            if !self
                .process_memory
                .synthetic_process_identities
                .iter()
                .any(|p| p.pid == pid)
            {
                self.process_memory
                    .synthetic_process_identities
                    .push(SyntheticProcessIdentity {
                        pid,
                        parent_pid: self.current_process_id(),
                        image_path: format!("C:\\\\Windows\\\\System32\\\\svchost.exe"),
                        command_line: format!(
                            "C:\\\\Windows\\\\System32\\\\svchost.exe -k netsvcs"
                        ),
                        current_directory: "C:\\\\Windows\\\\System32".to_string(),
                    });
            }
        }
        let handle = self.handles.next_object_handle;
        self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
        self.process_memory.process_handles.insert(handle, pid);
        self.core
            .scheduler
            .register_external_object(handle, "process", true, true);
        Some(handle as u64)
    }

    pub(in crate::runtime::engine) fn duplicate_runtime_handle(
        &mut self,
        source_process_handle: u64,
        source_handle: u32,
        target_process_handle: u64,
        target_handle_ptr: u64,
        options: u64,
    ) -> Result<u64, VmError> {
        const DUPLICATE_CLOSE_SOURCE: u64 = 0x1;

        if target_handle_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        // Cross-process handle duplication is not supported; fail explicitly
        // to avoid writing invalid handle values.
        if !self.is_current_process_handle(source_process_handle)
            || !self.is_current_process_handle(target_process_handle)
        {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }

        let duplicated = if self
            .core
            .scheduler
            .thread_tid_for_handle(source_handle)
            .is_some()
        {
            // Reuse the existing thread handle value — enough for samples that save
            // the current thread handle for later Get/SetThreadContext calls.
            source_handle
        } else if self
            .process_identity_for_handle(source_handle as u64)
            .is_some()
        {
            source_handle
        } else if let Some(&canonical) = self.sync.mutex_handle_targets.get(&source_handle) {
            let alias = self.handles.next_object_handle;
            self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
            self.sync.mutex_handles.insert(alias);
            self.sync.mutex_handle_targets.insert(alias, canonical);
            alias
        } else if let Some(&canonical) = self.sync.semaphore_handle_targets.get(&source_handle) {
            let alias = self.handles.next_object_handle;
            self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
            self.sync.semaphore_handles.insert(alias);
            self.sync.semaphore_handle_targets.insert(alias, canonical);
            alias
        } else if self.handles.file_handles.contains_key(&source_handle)
            || self.handles.device_handles.contains_key(&source_handle)
            || self
                .process_memory
                .process_snapshots
                .contains_key(&source_handle)
            || self.handles.token_handles.contains(&source_handle)
            || self
                .process_memory
                .file_mappings
                .resolve_mapping(source_handle)
                .is_some()
        {
            source_handle
        } else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };

        self.write_pointer_value(target_handle_ptr, duplicated as u64)?;

        if (options & DUPLICATE_CLOSE_SOURCE) != 0 {
            let _ = self.close_object_handle(source_handle);
        }

        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn close_object_handle(&mut self, handle: u32) -> bool {
        let mut closed = false;
        closed |= self.handles.file_handles.remove(&handle).is_some();
        closed |= self.handles.find_handles.remove(&handle).is_some();
        closed |= self.handles.volume_find_handles.remove(&handle).is_some();
        closed |= self.handles.device_handles.remove(&handle).is_some();
        closed |= self
            .process_memory
            .process_handles
            .remove(&handle)
            .is_some();
        closed |= self
            .process_memory
            .process_snapshots
            .remove(&handle)
            .is_some();
        closed |= self.handles.token_handles.remove(&handle);
        closed |= self.handles.etw_trace_handles.remove(&handle);
        closed |= self.handles.io_completion_ports.remove(&handle).is_some();
        closed |= self.process_memory.file_mappings.close_handle(handle);
        closed |= self.sync.mutex_handles.remove(&handle);
        closed |= self.sync.mutex_handle_targets.remove(&handle).is_some();
        closed |= self.sync.semaphore_handles.remove(&handle);
        closed |= self.sync.semaphore_handle_targets.remove(&handle).is_some();
        closed |= self.handles.setup_device_sets.remove(&handle).is_some();
        closed |= self.objects.wts_server_handles.remove(&handle);
        closed |= self.user32_close_object_handle(handle);
        closed
    }

    pub(in crate::runtime::engine) fn current_process_thread_count(&self) -> u32 {
        self.core
            .scheduler
            .thread_snapshots()
            .into_iter()
            .filter(|thread| thread.state != "terminated")
            .count()
            .min(u32::MAX as usize) as u32
    }

    pub(in crate::runtime::engine) fn build_toolhelp_process_entries(
        &self,
    ) -> Vec<ToolhelpProcessEntry> {
        let current_thread_count = self.current_process_thread_count();
        self.known_process_identities()
            .into_iter()
            .map(|process| ToolhelpProcessEntry {
                pid: process.pid,
                parent_pid: process.parent_pid,
                thread_count: if process.pid == self.current_process_id() {
                    current_thread_count
                } else {
                    0
                },
                image_name: process.image_name(),
            })
            .collect()
    }

    pub(in crate::runtime::engine) fn create_toolhelp_snapshot(
        &mut self,
        flags: u64,
        _process_id: u64,
    ) -> Result<u64, VmError> {
        if flags & TH32CS_SNAPPROCESS == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(self.invalid_handle_value_for_arch());
        }

        let handle = self.handles.next_object_handle;
        self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
        self.process_memory.process_snapshots.insert(
            handle,
            ToolhelpProcessSnapshot {
                entries: self.build_toolhelp_process_entries(),
                next_index: 0,
            },
        );
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(handle as u64)
    }

    pub(in crate::runtime::engine) fn process32_first_next(
        &mut self,
        snapshot_handle: u64,
        entry_ptr: u64,
        wide: bool,
        first: bool,
    ) -> Result<u64, VmError> {
        if entry_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let expected_size = if wide { 556usize } else { 296usize };
        let declared_size = self.read_u32(entry_ptr)? as usize;
        if declared_size < expected_size {
            self.set_last_error(ERROR_BAD_LENGTH as u32);
            return Ok(0);
        }

        let handle = snapshot_handle as u32;
        let Some(snapshot) = self.process_memory.process_snapshots.get_mut(&handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        if first {
            snapshot.next_index = 0;
        }
        let Some(entry) = snapshot.entries.get(snapshot.next_index).cloned() else {
            self.set_last_error(ERROR_NO_MORE_FILES as u32);
            return Ok(0);
        };
        snapshot.next_index = snapshot.next_index.saturating_add(1);
        self.write_process_entry32(entry_ptr, declared_size, &entry, wide)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn write_process_entry32(
        &mut self,
        entry_ptr: u64,
        declared_size: usize,
        entry: &ToolhelpProcessEntry,
        wide: bool,
    ) -> Result<(), VmError> {
        let expected_size = if wide { 556usize } else { 296usize };
        let mut bytes = vec![0u8; expected_size];
        bytes[0..4].copy_from_slice(&(declared_size as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&entry.pid.to_le_bytes());
        bytes[20..24].copy_from_slice(&entry.thread_count.to_le_bytes());
        bytes[24..28].copy_from_slice(&entry.parent_pid.to_le_bytes());
        bytes[28..32].copy_from_slice(&(8i32).to_le_bytes());

        if wide {
            let mut encoded = entry.image_name.encode_utf16().collect::<Vec<_>>();
            encoded.truncate(259);
            let image_bytes = encoded
                .into_iter()
                .chain(std::iter::once(0))
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>();
            let writable = image_bytes.len().min(bytes.len().saturating_sub(36));
            bytes[36..36 + writable].copy_from_slice(&image_bytes[..writable]);
        } else {
            let mut image_bytes = entry.image_name.as_bytes().to_vec();
            image_bytes.truncate(259);
            image_bytes.push(0);
            let writable = image_bytes.len().min(bytes.len().saturating_sub(36));
            bytes[36..36 + writable].copy_from_slice(&image_bytes[..writable]);
        }

        self.core.modules.memory_mut().write(entry_ptr, &bytes)?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn module_path_for_handle(
        &self,
        module_handle: u64,
    ) -> Option<String> {
        let module = self.module_record_for_handle(module_handle)?;

        // For the main module, prefer the environment profile's configured image_path
        // so that GetModuleFileNameA/W returns a Windows-style path (e.g.
        // "C:\Users\liming\Downloads\sample.exe") instead of the Linux host path
        // (e.g. "/home/dev/…/d2727b626d299d4839fbaf2034949948").
        if self
            .core
            .main_module
            .as_ref()
            .map_or(false, |m| m.base == module.base)
        {
            let configured = &self.core.environment_profile.machine.image_path;
            if !configured.is_empty() {
                return Some(configured.clone());
            }
        }

        // For non-main modules, try to return a Windows-style path when the module
        // was loaded from a snapshot directory (system DLLs).
        if let Some(ref host_path) = module.path {
            if let Some(windows_path) = self.host_path_to_windows_module_path(host_path) {
                return Some(windows_path);
            }
            return Some(host_path.to_string_lossy().to_string());
        }

        Some(module.name.clone())
    }

    /// Attempts to map a host filesystem path back to a guest Windows module path.
    /// Returns `None` for non-system directories where no mapping exists.
    fn host_path_to_windows_module_path(&self, host_path: &std::path::Path) -> Option<String> {
        let file_name = host_path.file_name()?.to_string_lossy();
        let parent_name = host_path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();

        let win_root = self
            .windows_directory_path()
            .trim_end_matches('\\')
            .rsplit('\\')
            .next()
            .unwrap_or("Windows")
            .to_string();

        // Direct match: the DLL sits inside a directory named System32 or SysWOW64.
        if parent_name == "system32" || parent_name == "syswow64" {
            return Some(format!(r"C:\{}\{}\{}", win_root, parent_name, file_name));
        }

        // If the module was loaded from a `dlls` hierarchy, try to infer its
        // virtual Windows location from the relative directory structure.
        if parent_name == "dlls" || host_path.to_string_lossy().contains("/dlls/") {
            let host_str = host_path.to_string_lossy();
            for subdir in &["System32", "SysWOW64"] {
                if host_str.contains(&format!("/{}/", subdir.to_ascii_lowercase())) {
                    return Some(format!(r"C:\{}\{}\{}", win_root, subdir, file_name));
                }
            }
            // Fallback: just place it in System32.
            return Some(format!(r"C:\{}\System32\{}", win_root, file_name));
        }

        // If the module lives under a system_dll top-level directory.
        if parent_name == "system_dll" || host_path.to_string_lossy().contains("/system_dll/") {
            return Some(format!(r"C:\{}\System32\{}", win_root, file_name));
        }

        None
    }

    pub(in crate::runtime::engine) fn process_modules_for_handle(
        &mut self,
        process_handle: u64,
    ) -> Result<Option<Vec<ModuleRecord>>, VmError> {
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return Ok(None);
        };
        if process_key == self.current_process_space_key() {
            return Ok(Some(self.current_process_modules()));
        }
        self.ensure_process_space_initialized(process_handle)?;
        Ok(self
            .process_memory
            .process_spaces
            .get(&process_key)
            .map(|space| space.modules.clone()))
    }

    pub(in crate::runtime::engine) fn process_module_for_handle(
        &mut self,
        process_handle: u64,
        module_handle: u64,
    ) -> Result<Option<ModuleRecord>, VmError> {
        let Some(modules) = self.process_modules_for_handle(process_handle)? else {
            return Ok(None);
        };
        if module_handle == 0 {
            return Ok(modules.first().cloned());
        }
        Ok(modules
            .into_iter()
            .find(|module| module.base == module_handle))
    }

    pub(in crate::runtime::engine) fn process_module_by_address(
        &mut self,
        process_handle: u64,
        address: u64,
    ) -> Result<Option<ModuleRecord>, VmError> {
        let Some(modules) = self.process_modules_for_handle(process_handle)? else {
            return Ok(None);
        };
        Ok(modules
            .into_iter()
            .find(|module| module.base <= address && address < module.base + module.size))
    }

    pub(in crate::runtime::engine) fn process_peb_base_for_handle(
        &mut self,
        process_handle: u64,
    ) -> Result<Option<u64>, VmError> {
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return Ok(None);
        };
        if process_key == self.current_process_space_key() {
            return Ok(Some(self.core.process_env.current_peb()));
        }
        self.ensure_process_space_initialized(process_handle)?;
        Ok(self
            .process_memory
            .process_spaces
            .get(&process_key)
            .map(|space| space.process_env.current_peb()))
    }

    pub(in crate::runtime::engine) fn enum_processes(
        &mut self,
        process_ids: u64,
        byte_capacity: usize,
        needed_ptr: u64,
    ) -> Result<u64, VmError> {
        let pids = self
            .known_process_identities()
            .into_iter()
            .map(|process| process.pid)
            .collect::<Vec<_>>();
        let required = pids.len() * std::mem::size_of::<u32>();
        if needed_ptr != 0 {
            self.write_u32(needed_ptr, required as u32)?;
        }
        if process_ids != 0 && byte_capacity != 0 {
            let writable = required.min(byte_capacity) / 4;
            let mut bytes = Vec::with_capacity(writable * 4);
            for pid in pids.iter().take(writable) {
                bytes.extend_from_slice(&pid.to_le_bytes());
            }
            if !bytes.is_empty() {
                self.core.modules.memory_mut().write(process_ids, &bytes)?;
            }
        }
        Ok(1)
    }

    pub(in crate::runtime::engine) fn enum_process_modules(
        &mut self,
        process_handle: u64,
        module_array: u64,
        byte_capacity: usize,
        needed_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(modules) = self.process_modules_for_handle(process_handle)? else {
            return Ok(0);
        };
        let pointer_size = self.core.arch.pointer_size;
        let required = modules.len() * pointer_size;
        if needed_ptr != 0 {
            self.write_u32(needed_ptr, required as u32)?;
        }
        if module_array != 0 && byte_capacity != 0 {
            let writable = required.min(byte_capacity) / pointer_size;
            let mut bytes = Vec::with_capacity(writable * pointer_size);
            for module in modules.iter().take(writable) {
                if self.core.arch.is_x86() {
                    bytes.extend_from_slice(&(module.base as u32).to_le_bytes());
                } else {
                    bytes.extend_from_slice(&module.base.to_le_bytes());
                }
            }
            if !bytes.is_empty() {
                self.core.modules.memory_mut().write(module_array, &bytes)?;
            }
        }
        Ok(1)
    }

    pub(in crate::runtime::engine) fn get_module_base_name_result(
        &mut self,
        process_handle: u64,
        module_handle: u64,
        buffer: u64,
        capacity: usize,
        wide: bool,
    ) -> Result<u64, VmError> {
        let Some(module) = self.process_module_for_handle(process_handle, module_handle)? else {
            return Ok(0);
        };
        let name = module
            .path
            .as_ref()
            .and_then(|path| path.file_name())
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| module.name.clone());
        if wide {
            self.write_wide_string_to_memory(buffer, capacity, &name)
        } else {
            self.write_c_string_to_memory(buffer, capacity, &name)
        }
    }

    pub(in crate::runtime::engine) fn get_module_file_name_ex_result(
        &mut self,
        process_handle: u64,
        module_handle: u64,
        buffer: u64,
        capacity: usize,
        wide: bool,
    ) -> Result<u64, VmError> {
        let Some(module) = self.process_module_for_handle(process_handle, module_handle)? else {
            return Ok(0);
        };
        let path = module
            .path
            .as_ref()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|| module.name.clone());
        if wide {
            self.write_wide_string_to_memory(buffer, capacity, &path)
        } else {
            self.write_c_string_to_memory(buffer, capacity, &path)
        }
    }

    pub(in crate::runtime::engine) fn write_module_information(
        &mut self,
        process_handle: u64,
        module_handle: u64,
        info_ptr: u64,
        info_len: usize,
    ) -> Result<u64, VmError> {
        if info_ptr == 0 {
            return Ok(0);
        }
        let Some(module) = self.process_module_for_handle(process_handle, module_handle)? else {
            return Ok(0);
        };
        if self.core.arch.is_x86() {
            if info_len < 12 {
                return Ok(0);
            }
            let mut bytes = [0u8; 12];
            bytes[0..4].copy_from_slice(&(module.base as u32).to_le_bytes());
            bytes[4..8].copy_from_slice(&(module.size as u32).to_le_bytes());
            bytes[8..12].copy_from_slice(&(module.entrypoint as u32).to_le_bytes());
            self.core.modules.memory_mut().write(info_ptr, &bytes)?;
        } else {
            if info_len < 24 {
                return Ok(0);
            }
            let mut bytes = [0u8; 24];
            bytes[0..8].copy_from_slice(&module.base.to_le_bytes());
            bytes[8..12].copy_from_slice(&(module.size as u32).to_le_bytes());
            bytes[16..24].copy_from_slice(&module.entrypoint.to_le_bytes());
            self.core.modules.memory_mut().write(info_ptr, &bytes)?;
        }
        Ok(1)
    }

    pub(in crate::runtime::engine) fn get_process_image_file_name_result(
        &mut self,
        process_handle: u64,
        buffer: u64,
        capacity: usize,
        wide: bool,
    ) -> Result<u64, VmError> {
        let Some(process) = self.process_identity_for_handle(process_handle) else {
            return Ok(0);
        };
        let path = process.display_path();
        if wide {
            self.write_wide_string_to_memory(buffer, capacity, &path)
        } else {
            self.write_c_string_to_memory(buffer, capacity, &path)
        }
    }

    pub(in crate::runtime::engine) fn get_mapped_file_name_result(
        &mut self,
        process_handle: u64,
        address: u64,
        buffer: u64,
        capacity: usize,
        wide: bool,
    ) -> Result<u64, VmError> {
        if !self.is_known_process_target(process_handle) {
            return Ok(0);
        }
        let path = self
            .mapped_file_path_for_process(process_handle, address)
            .unwrap_or_default();
        if wide {
            self.write_wide_string_to_memory(buffer, capacity, &path)
        } else {
            self.write_c_string_to_memory(buffer, capacity, &path)
        }
    }

    pub(in crate::runtime::engine) fn write_process_memory_info(
        &mut self,
        process_handle: u64,
        counters_ptr: u64,
        counters_len: usize,
    ) -> Result<u64, VmError> {
        if self.process_identity_for_handle(process_handle).is_none()
            || counters_ptr == 0
            || counters_len == 0
        {
            return Ok(0);
        }
        let mut bytes = vec![0u8; counters_len];
        let cb = counters_len.min(u32::MAX as usize) as u32;
        let prefix_len = 4.min(bytes.len());
        bytes[0..prefix_len].copy_from_slice(&cb.to_le_bytes()[..prefix_len]);
        self.core.modules.memory_mut().write(counters_ptr, &bytes)?;
        Ok(1)
    }

    pub(in crate::runtime::engine) fn query_full_process_image_name_result(
        &mut self,
        process_handle: u64,
        buffer: u64,
        size_ptr: u64,
        wide: bool,
    ) -> Result<u64, VmError> {
        let Some(process) = self.process_identity_for_handle(process_handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        if buffer == 0 || size_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let capacity = self.read_u32(size_ptr)? as usize;
        let path = process.display_path();
        let required = if wide {
            path.encode_utf16().count()
        } else {
            path.len()
        };
        if capacity <= required {
            self.write_u32(size_ptr, required as u32)?;
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }

        let written = if wide {
            self.write_wide_string_to_memory(buffer, capacity, &path)?
        } else {
            self.write_c_string_to_memory(buffer, capacity, &path)?
        };
        self.write_u32(size_ptr, written as u32)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn nt_open_process(
        &mut self,
        out_handle_ptr: u64,
        client_id_ptr: u64,
    ) -> Result<u64, VmError> {
        if out_handle_ptr == 0 || client_id_ptr == 0 {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        }
        let pid = self.read_u32(client_id_ptr)?;
        let Some(handle) = self.open_process_handle_by_pid(pid) else {
            return Ok(STATUS_INVALID_PARAMETER as u64);
        };
        self.write_u32(out_handle_ptr, handle as u32)?;
        Ok(STATUS_SUCCESS as u64)
    }

    pub(in crate::runtime::engine) fn nt_query_information_process(
        &mut self,
        process_handle: u64,
        info_class: u64,
        info_ptr: u64,
        info_len: usize,
        return_len_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(process) = self.process_identity_for_handle(process_handle) else {
            return Ok(STATUS_INVALID_HANDLE as u64);
        };
        match info_class {
            PROCESS_BASIC_INFORMATION_CLASS => {
                let required = if self.core.arch.is_x64() {
                    48u32
                } else {
                    24u32
                };
                if return_len_ptr != 0 {
                    self.write_u32(return_len_ptr, required)?;
                }
                if info_ptr == 0 || info_len < required as usize {
                    return Ok(STATUS_INFO_LENGTH_MISMATCH as u64);
                }
                let Some(peb_base) = self.process_peb_base_for_handle(process_handle)? else {
                    return Ok(STATUS_INVALID_HANDLE as u64);
                };
                let mut bytes = vec![0u8; required as usize];
                if self.core.arch.is_x64() {
                    bytes[8..16].copy_from_slice(&peb_base.to_le_bytes());
                    bytes[32..40].copy_from_slice(&(process.pid as u64).to_le_bytes());
                    bytes[40..48].copy_from_slice(&(process.parent_pid as u64).to_le_bytes());
                } else {
                    bytes[4..8].copy_from_slice(&(peb_base as u32).to_le_bytes());
                    bytes[16..20].copy_from_slice(&process.pid.to_le_bytes());
                    bytes[20..24].copy_from_slice(&process.parent_pid.to_le_bytes());
                }
                self.core.modules.memory_mut().write(info_ptr, &bytes)?;
                Ok(STATUS_SUCCESS as u64)
            }
            PROCESS_IMAGE_FILE_NAME_CLASS => {
                let path = process.display_path();
                let encoded = path
                    .encode_utf16()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>();
                let header_size = if self.core.arch.is_x64() { 16 } else { 8 };
                let required = header_size + encoded.len() + 2;
                if return_len_ptr != 0 {
                    self.write_u32(return_len_ptr, required as u32)?;
                }
                if info_ptr == 0 || info_len < required {
                    return Ok(STATUS_INFO_LENGTH_MISMATCH as u64);
                }
                let buffer_ptr = info_ptr + header_size as u64;
                self.write_u16(info_ptr, encoded.len().min(u16::MAX as usize) as u16)?;
                self.write_u16(
                    info_ptr + 2,
                    (encoded.len() + 2).min(u16::MAX as usize) as u16,
                )?;
                if self.core.arch.is_x64() {
                    self.core
                        .modules
                        .memory_mut()
                        .write(info_ptr + 8, &buffer_ptr.to_le_bytes())?;
                } else {
                    self.write_u32(info_ptr + 4, buffer_ptr as u32)?;
                }
                self.core.modules.memory_mut().write(buffer_ptr, &encoded)?;
                self.core
                    .modules
                    .memory_mut()
                    .write(buffer_ptr + encoded.len() as u64, &[0, 0])?;
                Ok(STATUS_SUCCESS as u64)
            }
            PROCESS_DEBUG_PORT_CLASS => {
                // ProcessDebugObjectHandle (0x1E=30): when not being debugged,
                // must return STATUS_PORT_NOT_SET (0xC0000353).
                // Returning STATUS_SUCCESS would indicate a debug object exists.
                Ok(STATUS_PORT_NOT_SET)
            }
            _ => Ok(STATUS_INVALID_PARAMETER as u64),
        }
    }

    pub(in crate::runtime::engine) fn nt_query_system_information(
        &mut self,
        info_class: u64,
        info_ptr: u64,
        info_len: usize,
        return_len_ptr: u64,
    ) -> Result<u64, VmError> {
        let (status, size) = match info_class {
            SYSTEM_BASIC_INFORMATION_CLASS => {
                let size = if info_ptr == 0 {
                    0
                } else {
                    self.write_system_basic_information(info_ptr)?
                };
                let status = if info_len < size {
                    STATUS_INFO_LENGTH_MISMATCH
                } else {
                    STATUS_SUCCESS
                };
                (status, size)
            }
            SYSTEM_PROCESS_INFORMATION_CLASS => {
                self.write_system_process_information(info_ptr, info_len)?
            }
            _ => {
                if info_ptr != 0 && info_len != 0 {
                    self.core
                        .modules
                        .memory_mut()
                        .write(info_ptr, &vec![0u8; info_len])?;
                }
                (STATUS_SUCCESS, info_len)
            }
        };
        if return_len_ptr != 0 {
            self.write_u32(return_len_ptr, size.min(u32::MAX as usize) as u32)?;
        }
        Ok(status as u64)
    }

    pub(in crate::runtime::engine) fn write_system_basic_information(
        &mut self,
        info_ptr: u64,
    ) -> Result<usize, VmError> {
        let page_size = 0x1000u32;
        let allocation_granularity = 0x10000u32;
        let mut payload = Vec::with_capacity(44);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&156_250u32.to_le_bytes());
        payload.extend_from_slice(&page_size.to_le_bytes());
        payload.extend_from_slice(&0x10000u32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&0x10000u32.to_le_bytes());
        payload.extend_from_slice(&allocation_granularity.to_le_bytes());
        payload.extend_from_slice(&0x10000u32.to_le_bytes());
        payload.extend_from_slice(&0x7FFE_FFFFu32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.push(1);
        payload.extend_from_slice(&[0u8; 3]);
        self.core.modules.memory_mut().write(info_ptr, &payload)?;
        Ok(payload.len())
    }

    pub(in crate::runtime::engine) fn write_system_process_information(
        &mut self,
        info_ptr: u64,
        info_len: usize,
    ) -> Result<(u32, usize), VmError> {
        let base_size = 0xB8usize;
        let image_name_offset = 0x38u64;
        let base_priority_offset = 0x40u64;
        let pid_offset = 0x44u64;
        let ppid_offset = 0x48u64;
        let thread_size = 0x40usize;
        let thread_start_offset = 0x1Cu64;
        let thread_client_id_offset = 0x20u64;
        let thread_priority_offset = 0x28u64;
        let thread_base_priority_offset = 0x2Cu64;
        let current_threads = self
            .core
            .scheduler
            .thread_snapshots()
            .into_iter()
            .filter(|thread| thread.state != "terminated")
            .map(|thread| (thread.tid, thread.start_address))
            .collect::<Vec<_>>();
        let entries = self
            .known_process_identities()
            .into_iter()
            .map(|process| {
                let name_data = {
                    let mut bytes = process.image_name().encode_utf16().collect::<Vec<_>>();
                    bytes.push(0);
                    bytes
                        .into_iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<_>>()
                };
                let threads = if process.pid == self.current_process_id() {
                    current_threads.clone()
                } else {
                    Vec::new()
                };
                let entry_size =
                    (base_size + threads.len() * thread_size + name_data.len() + 7) & !7usize;
                (process, threads, name_data, entry_size)
            })
            .collect::<Vec<_>>();
        let total = entries.iter().map(|(_, _, _, size)| *size).sum::<usize>();
        if info_len < total {
            return Ok((STATUS_INFO_LENGTH_MISMATCH, total));
        }
        if info_ptr == 0 {
            return Ok((STATUS_SUCCESS, total));
        }

        let mut cursor = 0usize;
        for (index, (process, threads, name_data, entry_size)) in entries.iter().enumerate() {
            let base = info_ptr + cursor as u64;
            let next_offset = if index + 1 == entries.len() {
                0
            } else {
                *entry_size as u32
            };
            let thread_count = threads.len() as u32;
            let name_buffer = base + (base_size + threads.len() * thread_size) as u64;
            self.core
                .modules
                .memory_mut()
                .write(base, &vec![0u8; *entry_size])?;
            self.write_u32(base, next_offset)?;
            self.write_u32(base + 4, thread_count)?;
            self.write_u16(
                base + image_name_offset,
                name_data.len().saturating_sub(2).min(u16::MAX as usize) as u16,
            )?;
            self.write_u16(
                base + image_name_offset + 2,
                name_data.len().min(u16::MAX as usize) as u16,
            )?;
            self.write_u32(base + image_name_offset + 4, name_buffer as u32)?;
            self.write_u32(base + base_priority_offset, 8)?;
            self.write_u32(base + pid_offset, process.pid)?;
            self.write_u32(base + ppid_offset, process.parent_pid)?;
            self.core
                .modules
                .memory_mut()
                .write(name_buffer, name_data)?;
            let thread_base = base + base_size as u64;
            for (thread_index, (tid, start_address)) in threads.iter().enumerate() {
                let entry_base = thread_base + (thread_index * thread_size) as u64;
                self.write_u32(entry_base + thread_start_offset, *start_address as u32)?;
                self.write_u32(entry_base + thread_client_id_offset, process.pid)?;
                self.write_u32(entry_base + thread_client_id_offset + 4, *tid)?;
                self.write_u32(entry_base + thread_priority_offset, 8)?;
                self.write_u32(entry_base + thread_base_priority_offset, 8)?;
            }
            cursor += *entry_size;
        }
        Ok((STATUS_SUCCESS, total))
    }
}
