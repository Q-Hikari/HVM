use super::*;

const STATUS_ACCESS_VIOLATION_EXIT: u32 = 0xC000_0005;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::runtime::engine) struct RemoteShellcodeStagedRegion {
    pub(in crate::runtime::engine) source_base: u64,
    pub(in crate::runtime::engine) source_size: u64,
    pub(in crate::runtime::engine) staged_base: u64,
    pub(in crate::runtime::engine) exact_base: bool,
}

impl RemoteShellcodeStagedRegion {
    fn contains_source_address(&self, address: u64) -> bool {
        self.source_base <= address && address < self.source_base.saturating_add(self.source_size)
    }

    fn translate_source_address(&self, address: u64) -> Option<u64> {
        self.contains_source_address(address).then_some(
            self.staged_base
                .saturating_add(address.saturating_sub(self.source_base)),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::runtime::engine) enum RemoteThreadEntrySource {
    PrivateAllocation {
        source_allocation_base: u64,
        source_allocation_size: u64,
    },
    ModuleRvaTranslation {
        source_module_name: String,
        source_module_base: u64,
        source_rva: u64,
        translated_module_name: String,
        translated_module_base: u64,
        translated_start_address: u64,
        translation_source: String,
    },
    BoundHookTranslation {
        translated_module_name: String,
        translated_function_name: String,
        translated_start_address: u64,
        translation_source: String,
    },
}

impl RemoteThreadEntrySource {
    fn entry_mode(&self) -> &'static str {
        match self {
            Self::PrivateAllocation { .. } => "private_shellcode",
            Self::ModuleRvaTranslation { .. } | Self::BoundHookTranslation { .. } => {
                "api_translation"
            }
        }
    }

    fn extend_log_fields(&self, fields: &mut Map<String, serde_json::Value>) {
        fields.insert("entry_mode".to_string(), json!(self.entry_mode()));
        match self {
            Self::PrivateAllocation {
                source_allocation_base,
                source_allocation_size,
            } => {
                fields.insert(
                    "source_allocation_base".to_string(),
                    json!(source_allocation_base),
                );
                fields.insert(
                    "source_allocation_size".to_string(),
                    json!(source_allocation_size),
                );
            }
            Self::ModuleRvaTranslation {
                source_module_name,
                source_module_base,
                source_rva,
                translated_module_name,
                translated_module_base,
                translated_start_address,
                translation_source,
            } => {
                fields.insert("source_module_name".to_string(), json!(source_module_name));
                fields.insert("source_module_base".to_string(), json!(source_module_base));
                fields.insert("source_module_rva".to_string(), json!(source_rva));
                fields.insert(
                    "translated_module_name".to_string(),
                    json!(translated_module_name),
                );
                fields.insert(
                    "translated_module_base".to_string(),
                    json!(translated_module_base),
                );
                fields.insert(
                    "translated_start_address".to_string(),
                    json!(translated_start_address),
                );
                fields.insert("translation_source".to_string(), json!(translation_source));
            }
            Self::BoundHookTranslation {
                translated_module_name,
                translated_function_name,
                translated_start_address,
                translation_source,
            } => {
                fields.insert(
                    "translated_module_name".to_string(),
                    json!(translated_module_name),
                );
                fields.insert(
                    "translated_function_name".to_string(),
                    json!(translated_function_name),
                );
                fields.insert(
                    "translated_start_address".to_string(),
                    json!(translated_start_address),
                );
                fields.insert("translation_source".to_string(), json!(translation_source));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::runtime::engine) struct RemoteShellcodeThread {
    pub(in crate::runtime::engine) thread_tid: u32,
    pub(in crate::runtime::engine) thread_handle: u32,
    pub(in crate::runtime::engine) source_process_handle: u64,
    pub(in crate::runtime::engine) source_process_key: u64,
    pub(in crate::runtime::engine) source_start_address: u64,
    pub(in crate::runtime::engine) source_parameter: u64,
    pub(in crate::runtime::engine) entry_source: RemoteThreadEntrySource,
    pub(in crate::runtime::engine) creation_source: String,
    pub(in crate::runtime::engine) staged_start_address: Option<u64>,
    pub(in crate::runtime::engine) staged_parameter: Option<u64>,
    pub(in crate::runtime::engine) staged_regions: Vec<RemoteShellcodeStagedRegion>,
}

impl RemoteShellcodeThread {
    fn translate_source_address(&self, address: u64) -> Option<u64> {
        self.staged_regions
            .iter()
            .find_map(|region| region.translate_source_address(address))
    }
}

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn create_remote_shellcode_thread(
        &mut self,
        process_handle: u64,
        start_address: u64,
        parameter: u64,
        suspended: bool,
        tid_ptr: u64,
        source: &str,
    ) -> Result<Option<u64>, VmError> {
        let Some((process_key, entry_source)) =
            self.resolve_remote_thread_entry(process_handle, start_address)?
        else {
            return Ok(None);
        };

        let thread = self
            .scheduler
            .create_virtual_thread(start_address, parameter, suspended)
            .ok_or(VmError::RuntimeInvariant(
                "failed to register remote execution thread",
            ))?;
        self.initialize_virtual_thread(thread.tid, parameter)?;
        if tid_ptr != 0 {
            self.write_u32(tid_ptr, thread.tid)?;
        }

        let state = if suspended { "suspended" } else { "ready" };
        let metadata = RemoteShellcodeThread {
            thread_tid: thread.tid,
            thread_handle: thread.handle,
            source_process_handle: process_handle,
            source_process_key: process_key,
            source_start_address: start_address,
            source_parameter: parameter,
            entry_source,
            creation_source: source.to_string(),
            staged_start_address: None,
            staged_parameter: None,
            staged_regions: Vec::new(),
        };
        self.log_remote_thread_record_event(&metadata, state)?;
        self.remote_shellcode_threads.insert(thread.tid, metadata);

        self.set_last_error(ERROR_SUCCESS as u32);
        self.log_thread_event(
            "THREAD_CREATE",
            thread.tid,
            thread.handle,
            start_address,
            parameter,
            state,
        )?;
        Ok(Some(thread.handle as u64))
    }

    pub(in crate::runtime::engine) fn prepare_remote_shellcode_thread_if_needed(
        &mut self,
        tid: u32,
    ) -> Result<(), VmError> {
        let Some(metadata) = self.remote_shellcode_threads.get(&tid).cloned() else {
            return Ok(());
        };
        if metadata.staged_start_address.is_some() {
            return Ok(());
        }

        match self.stage_remote_shellcode_thread(metadata.clone()) {
            Ok(updated) => {
                self.remote_shellcode_threads.insert(tid, updated);
                Ok(())
            }
            Err(error) => {
                self.log_remote_thread_stage_failure(&metadata, &error.to_string())?;
                let _ = self.terminate_current_thread(STATUS_ACCESS_VIOLATION_EXIT);
                Ok(())
            }
        }
    }

    fn resolve_remote_thread_entry(
        &mut self,
        process_handle: u64,
        start_address: u64,
    ) -> Result<Option<(u64, RemoteThreadEntrySource)>, VmError> {
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return Ok(None);
        };
        if process_key == self.current_process_space_key() {
            return Ok(None);
        }
        let _ = self.ensure_process_space_initialized(process_handle)?;

        if let Some(record) = self
            .virtual_allocation_record_for_process(process_handle, start_address)
            .cloned()
        {
            if record.region_type == MEM_PRIVATE
                && record
                    .segment_for_address(start_address)
                    .map(|segment| segment.state == MEM_COMMIT)
                    .unwrap_or(false)
            {
                return Ok(Some((
                    process_key,
                    RemoteThreadEntrySource::PrivateAllocation {
                        source_allocation_base: record.allocation_base,
                        source_allocation_size: record.allocation_size,
                    },
                )));
            }
        }

        if let Some(entry) = self.resolve_remote_api_thread_entry(process_handle, start_address)? {
            return Ok(Some((process_key, entry)));
        }

        Ok(None)
    }

    fn resolve_remote_api_thread_entry(
        &mut self,
        process_handle: u64,
        start_address: u64,
    ) -> Result<Option<RemoteThreadEntrySource>, VmError> {
        if let Some(remote_module) =
            self.process_module_by_address(process_handle, start_address)?
        {
            if let Some(local_module) =
                self.ensure_local_module_for_remote_address(&remote_module)?
            {
                let source_rva = start_address.saturating_sub(remote_module.base);
                if source_rva < local_module.size {
                    return Ok(Some(RemoteThreadEntrySource::ModuleRvaTranslation {
                        source_module_name: remote_module.name.clone(),
                        source_module_base: remote_module.base,
                        source_rva,
                        translated_module_name: local_module.name.clone(),
                        translated_module_base: local_module.base,
                        translated_start_address: local_module.base + source_rva,
                        translation_source: "remote_module_rva".to_string(),
                    }));
                }
            }
        }

        if let Some(local_module) = self.modules.get_by_address(start_address).cloned() {
            return Ok(Some(RemoteThreadEntrySource::ModuleRvaTranslation {
                source_module_name: local_module.name.clone(),
                source_module_base: local_module.base,
                source_rva: start_address.saturating_sub(local_module.base),
                translated_module_name: local_module.name.clone(),
                translated_module_base: local_module.base,
                translated_start_address: start_address,
                translation_source: "current_module_address".to_string(),
            }));
        }

        if let Some((module, function)) = self.hooks.binding_for_address(start_address) {
            return Ok(Some(RemoteThreadEntrySource::BoundHookTranslation {
                translated_module_name: module.to_string(),
                translated_function_name: function.to_string(),
                translated_start_address: start_address,
                translation_source: "bound_hook_address".to_string(),
            }));
        }

        Ok(None)
    }

    fn ensure_local_module_for_remote_address(
        &mut self,
        remote_module: &ModuleRecord,
    ) -> Result<Option<ModuleRecord>, VmError> {
        if let Some(local) = self.modules.get_loaded(&remote_module.name).cloned() {
            return Ok(Some(local));
        }
        let Some(path) = remote_module.path.as_ref() else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }

        let module = self.modules.load_runtime_dependency(
            &path.to_string_lossy(),
            &self.config,
            &mut self.hooks,
        )?;
        self.register_module_image_allocation(self.current_process_space_key(), &module)?;
        self.sync_process_environment_modules()?;
        Ok(Some(module))
    }

    fn stage_remote_shellcode_thread(
        &mut self,
        mut metadata: RemoteShellcodeThread,
    ) -> Result<RemoteShellcodeThread, VmError> {
        let mut staged_records = BTreeMap::<u64, VirtualAllocationRecord>::new();

        if let RemoteThreadEntrySource::PrivateAllocation {
            source_allocation_base,
            ..
        } = metadata.entry_source
        {
            let primary = self
                .virtual_allocation_record_for_process(
                    metadata.source_process_handle,
                    source_allocation_base,
                )
                .cloned()
                .ok_or(VmError::RuntimeInvariant(
                    "remote private allocation disappeared before staging",
                ))?;
            staged_records.insert(primary.allocation_base, primary);
        }

        if metadata.source_parameter != 0 {
            if let Some(record) = self
                .virtual_allocation_record_for_process(
                    metadata.source_process_handle,
                    metadata.source_parameter,
                )
                .cloned()
            {
                if record
                    .segment_for_address(metadata.source_parameter)
                    .map(|segment| segment.state == MEM_COMMIT)
                    .unwrap_or(false)
                    && record.region_type != MEM_IMAGE
                {
                    staged_records
                        .entry(record.allocation_base)
                        .or_insert(record);
                }
            }
        }

        let mut regions = Vec::with_capacity(staged_records.len());
        for record in staged_records.into_values() {
            regions.push(self.stage_remote_allocation_into_current(record, &metadata)?);
        }

        metadata.staged_regions = regions;
        let staged_start = match &metadata.entry_source {
            RemoteThreadEntrySource::PrivateAllocation { .. } => metadata
                .translate_source_address(metadata.source_start_address)
                .ok_or(VmError::RuntimeInvariant(
                    "failed to translate staged private thread start address",
                ))?,
            RemoteThreadEntrySource::ModuleRvaTranslation {
                translated_start_address,
                ..
            }
            | RemoteThreadEntrySource::BoundHookTranslation {
                translated_start_address,
                ..
            } => *translated_start_address,
        };
        let staged_parameter = if metadata.source_parameter == 0 {
            0
        } else {
            metadata
                .translate_source_address(metadata.source_parameter)
                .unwrap_or(metadata.source_parameter)
        };

        self.retarget_thread_to_staged_shellcode(
            metadata.thread_tid,
            staged_start,
            staged_parameter,
        )?;
        metadata.staged_start_address = Some(staged_start);
        metadata.staged_parameter = Some(staged_parameter);

        self.log_remote_thread_stage_event(&metadata)?;
        self.log_thread_entry_dump_if_dynamic(
            "THREAD_START_DUMP",
            "REMOTE_THREAD_STAGE",
            metadata.thread_tid,
            metadata.thread_handle,
            staged_start,
            staged_parameter,
            "running",
        )?;
        Ok(metadata)
    }

    fn stage_remote_allocation_into_current(
        &mut self,
        record: VirtualAllocationRecord,
        metadata: &RemoteShellcodeThread,
    ) -> Result<RemoteShellcodeStagedRegion, VmError> {
        let preferred = record.allocation_base;
        let exact_base = self
            .modules
            .memory()
            .is_free(preferred, record.allocation_size, false);
        let tag = format!(
            "remote_thread:pk-0x{:X}:0x{:X}",
            metadata.source_process_key, record.allocation_base
        );
        let staged_base = self
            .modules
            .memory_mut()
            .reserve(record.allocation_size, Some(preferred), &tag, true)
            .map_err(VmError::from)?;

        for segment in &record.segments {
            if segment.state != MEM_COMMIT || segment.size == 0 {
                continue;
            }
            let Some(bytes) = self.with_process_memory(metadata.source_process_handle, |memory| {
                memory.read(
                    segment.base,
                    usize::try_from(segment.size).unwrap_or(usize::MAX),
                )
            }) else {
                return Err(VmError::RuntimeInvariant(
                    "remote process memory missing while staging thread data",
                ));
            };
            let bytes = bytes.map_err(VmError::from)?;
            let staged_segment_base =
                staged_base.saturating_add(segment.base.saturating_sub(record.allocation_base));
            self.modules
                .memory_mut()
                .write(staged_segment_base, &bytes)
                .map_err(VmError::from)?;
        }

        for segment in &record.segments {
            if segment.size == 0 {
                continue;
            }
            let staged_segment_base =
                staged_base.saturating_add(segment.base.saturating_sub(record.allocation_base));
            let perms = if segment.state == MEM_COMMIT {
                Self::perms_from_page_protect(segment.protect).unwrap_or(0)
            } else {
                0
            };
            self.modules
                .memory_mut()
                .protect(staged_segment_base, segment.size, perms)
                .map_err(VmError::from)?;
        }

        let staged_record = VirtualAllocationRecord {
            allocation_base: staged_base,
            allocation_size: record.allocation_size,
            allocation_protect: record.allocation_protect,
            allocation_type: record.allocation_type,
            region_type: record.region_type,
            segments: record
                .segments
                .iter()
                .map(|segment| VirtualAllocationSegment {
                    base: staged_base
                        .saturating_add(segment.base.saturating_sub(record.allocation_base)),
                    size: segment.size,
                    state: segment.state,
                    protect: segment.protect,
                })
                .collect(),
        };
        self.insert_virtual_allocation_record(self.current_process_space_key(), staged_record)?;

        Ok(RemoteShellcodeStagedRegion {
            source_base: record.allocation_base,
            source_size: record.allocation_size,
            staged_base,
            exact_base: exact_base && staged_base == preferred,
        })
    }

    fn retarget_thread_to_staged_shellcode(
        &mut self,
        tid: u32,
        start_address: u64,
        parameter: u64,
    ) -> Result<(), VmError> {
        self.scheduler
            .set_thread_start_address(tid, start_address)
            .ok_or(VmError::RuntimeInvariant(
                "failed to retarget remote thread start address",
            ))?;
        self.scheduler
            .set_thread_parameter(tid, parameter)
            .ok_or(VmError::RuntimeInvariant(
                "failed to retarget remote thread parameter",
            ))?;
        let mut registers = self
            .scheduler
            .thread_snapshot(tid)
            .ok_or(VmError::RuntimeInvariant(
                "missing thread snapshot while staging remote thread",
            ))?
            .registers;
        if self.arch.is_x86() {
            registers.insert("eip".to_string(), start_address);
            let esp = registers
                .get("esp")
                .copied()
                .ok_or(VmError::RuntimeInvariant(
                    "missing ESP while staging x86 remote thread",
                ))?;
            self.write_u32(esp.saturating_add(4), parameter as u32)?;
        } else {
            registers.insert("rip".to_string(), start_address);
            registers.insert("rcx".to_string(), parameter);
        }
        self.scheduler
            .set_thread_registers(tid, registers)
            .ok_or(VmError::RuntimeInvariant(
                "failed to update staged remote thread registers",
            ))?;
        Ok(())
    }

    fn log_remote_thread_record_event(
        &mut self,
        metadata: &RemoteShellcodeThread,
        state: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert(
            "source_process_handle".to_string(),
            json!(metadata.source_process_handle),
        );
        fields.insert(
            "source_process_key".to_string(),
            json!(metadata.source_process_key),
        );
        fields.insert(
            "creation_source".to_string(),
            json!(metadata.creation_source.clone()),
        );
        metadata.entry_source.extend_log_fields(&mut fields);

        let should_dump = matches!(
            metadata.entry_source,
            RemoteThreadEntrySource::PrivateAllocation { .. }
        ) && self
            .query_memory_basic_information_for_process(
                metadata.source_process_handle,
                metadata.source_start_address,
            )
            .map(|info| self.should_dump_memory_region(metadata.source_process_handle, info, true))
            .unwrap_or(false);

        if should_dump {
            self.log_thread_entry_dump_for_process_if_dynamic(
                "REMOTE_THREAD_RECORD",
                &metadata.creation_source,
                metadata.source_process_handle,
                metadata.thread_tid,
                metadata.thread_handle,
                metadata.source_start_address,
                metadata.source_parameter,
                state,
                fields,
            )
        } else {
            fields.insert("thread_tid".to_string(), json!(metadata.thread_tid));
            fields.insert("thread_handle".to_string(), json!(metadata.thread_handle));
            fields.insert(
                "start_address".to_string(),
                json!(metadata.source_start_address),
            );
            fields.insert("parameter".to_string(), json!(metadata.source_parameter));
            fields.insert("state".to_string(), json!(state));
            self.log_runtime_event("REMOTE_THREAD_RECORD", fields)
        }
    }

    fn log_remote_thread_stage_event(
        &mut self,
        metadata: &RemoteShellcodeThread,
    ) -> Result<(), VmError> {
        let staged_start = metadata.staged_start_address.unwrap_or(0);
        let staged_parameter = metadata
            .staged_parameter
            .unwrap_or(metadata.source_parameter);
        let mut fields = Map::new();
        fields.insert("thread_tid".to_string(), json!(metadata.thread_tid));
        fields.insert("thread_handle".to_string(), json!(metadata.thread_handle));
        fields.insert(
            "source_process_handle".to_string(),
            json!(metadata.source_process_handle),
        );
        fields.insert(
            "source_process_key".to_string(),
            json!(metadata.source_process_key),
        );
        fields.insert(
            "source_start_address".to_string(),
            json!(metadata.source_start_address),
        );
        fields.insert(
            "source_parameter".to_string(),
            json!(metadata.source_parameter),
        );
        fields.insert(
            "creation_source".to_string(),
            json!(metadata.creation_source),
        );
        fields.insert("staged_start_address".to_string(), json!(staged_start));
        fields.insert("staged_parameter".to_string(), json!(staged_parameter));
        fields.insert(
            "staged_regions".to_string(),
            json!(metadata
                .staged_regions
                .iter()
                .map(|region| {
                    json!({
                        "source_base": region.source_base,
                        "source_size": region.source_size,
                        "staged_base": region.staged_base,
                        "exact_base": region.exact_base,
                    })
                })
                .collect::<Vec<_>>()),
        );
        metadata.entry_source.extend_log_fields(&mut fields);
        self.add_address_ref_fields(&mut fields, "staged_start_address", staged_start);
        if staged_parameter != 0 {
            self.add_address_ref_fields(&mut fields, "staged_parameter", staged_parameter);
        }
        self.log_runtime_event("REMOTE_THREAD_STAGE", fields)
    }

    fn log_remote_thread_stage_failure(
        &mut self,
        metadata: &RemoteShellcodeThread,
        reason: &str,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("thread_tid".to_string(), json!(metadata.thread_tid));
        fields.insert("thread_handle".to_string(), json!(metadata.thread_handle));
        fields.insert(
            "source_process_handle".to_string(),
            json!(metadata.source_process_handle),
        );
        fields.insert(
            "source_process_key".to_string(),
            json!(metadata.source_process_key),
        );
        fields.insert(
            "source_start_address".to_string(),
            json!(metadata.source_start_address),
        );
        fields.insert(
            "source_parameter".to_string(),
            json!(metadata.source_parameter),
        );
        fields.insert(
            "creation_source".to_string(),
            json!(metadata.creation_source.clone()),
        );
        fields.insert("reason".to_string(), json!(reason));
        metadata.entry_source.extend_log_fields(&mut fields);
        self.log_runtime_event("REMOTE_THREAD_STAGE_FAIL", fields)
    }
}
