use std::path::{Path, PathBuf};

use super::*;
use crate::runtime::engine::shared::MemoryBasicInfoSnapshot;

const MEMORY_DUMP_PREVIEW_BYTES: usize = 64;

impl VirtualExecutionEngine {
    pub(super) fn stable_runtime_hash(bytes: &[u8]) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

        let mut hash = FNV_OFFSET;
        for &byte in bytes {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }

    pub(super) fn process_handle_for_process_key(&self, process_key: u64) -> u64 {
        if process_key == self.current_process_space_key() {
            return self.current_process_space_key();
        }
        if process_key & SHELL_PROCESS_SPACE_KEY_BASE != 0 {
            return process_key & u32::MAX as u64;
        }
        self.process_handles
            .iter()
            .find_map(|(handle, pid)| (*pid as u64 == process_key).then_some(*handle as u64))
            .unwrap_or(process_key)
    }

    pub(super) fn read_process_memory_by_key(
        &self,
        process_key: u64,
        address: u64,
        size: usize,
    ) -> Option<Result<Vec<u8>, crate::error::MemoryError>> {
        if process_key == self.current_process_space_key() {
            Some(self.modules.memory().read(address, size))
        } else {
            self.process_spaces
                .get(&process_key)
                .map(|space| space.memory.read(address, size))
        }
    }

    pub(super) fn collect_executable_virtual_allocation_segments(
        &self,
    ) -> Vec<(u64, VirtualAllocationRecord, VirtualAllocationSegment)> {
        let mut candidates = Vec::new();
        let current_process_key = self.current_process_space_key();
        for record in self.virtual_allocations.values() {
            if record.region_type == MEM_IMAGE {
                continue;
            }
            for segment in &record.segments {
                if segment.state == MEM_COMMIT && Self::page_protect_is_executable(segment.protect)
                {
                    candidates.push((current_process_key, record.clone(), *segment));
                }
            }
        }
        for (&process_key, space) in &self.process_spaces {
            for record in space.virtual_allocations.values() {
                if record.region_type == MEM_IMAGE {
                    continue;
                }
                for segment in &record.segments {
                    if segment.state == MEM_COMMIT
                        && Self::page_protect_is_executable(segment.protect)
                    {
                        candidates.push((process_key, record.clone(), *segment));
                    }
                }
            }
        }
        candidates
    }

    pub(super) fn sample_dump_size_limit_bytes(&self) -> u64 {
        self.main_module
            .as_ref()
            .and_then(|module| module.path.as_ref())
            .and_then(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .or_else(|| {
                fs::metadata(&self.config.main_module)
                    .ok()
                    .map(|metadata| metadata.len())
            })
            .or_else(|| self.main_module.as_ref().map(|module| module.size))
            .unwrap_or(u64::MAX)
            .max(1)
    }

    pub(super) fn bounded_dump_capture_size(
        &self,
        requested_size: u64,
        available_size: u64,
    ) -> u64 {
        requested_size
            .max(1)
            .min(available_size.max(1))
            .min(self.sample_dump_size_limit_bytes())
    }

    fn module_image_capture_size(module: &ModuleRecord) -> u64 {
        module
            .path
            .as_ref()
            .and_then(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .unwrap_or(module.size)
            .max(1)
    }

    pub(super) fn current_process_image_dump_info(
        &mut self,
        module: &ModuleRecord,
        capture_size: u64,
    ) -> Option<MemoryBasicInfoSnapshot> {
        let mut info = self.query_memory_basic_information_for_process(
            self.current_process_space_key(),
            module.base,
        )?;
        info.base_address = module.base;
        info.region_size = capture_size;
        Some(info)
    }

    pub(super) fn capture_current_process_image_hash_baseline(
        &mut self,
        module: &ModuleRecord,
    ) -> Result<(), VmError> {
        if module.synthetic {
            return Ok(());
        }
        let capture_size = Self::module_image_capture_size(module);
        let Some(bytes) = self.read_process_memory_by_key(
            self.current_process_space_key(),
            module.base,
            usize::try_from(capture_size).unwrap_or(usize::MAX),
        ) else {
            return Ok(());
        };
        let bytes = bytes.map_err(VmError::from)?;
        self.image_hash_baselines.insert(
            (self.current_process_space_key(), module.base),
            ImageHashBaseline {
                capture_size,
                hash: Self::stable_runtime_hash(&bytes),
            },
        );
        Ok(())
    }

    pub(super) fn capture_current_process_image_hash_baselines(&mut self) -> Result<(), VmError> {
        let modules = self
            .current_process_modules()
            .into_iter()
            .filter(|module| !module.synthetic)
            .collect::<Vec<_>>();
        for module in modules {
            self.capture_current_process_image_hash_baseline(&module)?;
        }
        Ok(())
    }
}

impl VirtualExecutionEngine {
    pub(super) fn write_memory_dump_artifact(
        &mut self,
        marker: &str,
        base: u64,
        bytes: &[u8],
    ) -> Result<PathBuf, VmError> {
        self.memory_dump_sequence = self.memory_dump_sequence.saturating_add(1);
        let path = self
            .config
            .sandbox_output_dir
            .join("memory_dumps")
            .join(format!(
                "{}-pid{:05}-tid{:05}-{:06}-0x{:X}.bin",
                marker.to_ascii_lowercase(),
                self.current_process_id(),
                self.current_log_tid(),
                self.memory_dump_sequence,
                base,
            ));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| VmError::OutputIo {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        fs::write(&path, bytes).map_err(|source| VmError::OutputIo {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }

    pub(super) fn memory_region_type_name(region_type: u32) -> &'static str {
        match region_type {
            MEM_IMAGE => "image",
            MEM_MAPPED => "mapped",
            MEM_PRIVATE => "private",
            _ => "unknown",
        }
    }

    fn memory_state_name(state: u32) -> &'static str {
        match state {
            MEM_COMMIT => "commit",
            MEM_RESERVE => "reserve",
            MEM_FREE => "free",
            _ => "unknown",
        }
    }

    pub(super) fn should_dump_memory_region(
        &self,
        process_handle: u64,
        info: MemoryBasicInfoSnapshot,
        non_image_only: bool,
    ) -> bool {
        if info.state != MEM_COMMIT {
            return false;
        }
        if !non_image_only {
            return true;
        }
        info.region_type != MEM_IMAGE || !self.is_current_process_handle(process_handle)
    }

    fn enrich_memory_dump_fields(
        &mut self,
        fields: &mut Map<String, serde_json::Value>,
        process_handle: u64,
        address: u64,
        dump_base: u64,
        requested_size: u64,
        info: MemoryBasicInfoSnapshot,
        bytes: &[u8],
        dump_path: &Path,
    ) {
        fields.insert("process_handle".to_string(), json!(process_handle));
        fields.insert("address".to_string(), json!(address));
        fields.insert("dump_base".to_string(), json!(dump_base));
        fields.insert("requested_size".to_string(), json!(requested_size.max(1)));
        fields.insert("captured_size".to_string(), json!(bytes.len()));
        fields.insert("allocation_base".to_string(), json!(info.allocation_base));
        fields.insert("region_base".to_string(), json!(info.base_address));
        fields.insert("region_size".to_string(), json!(info.region_size));
        fields.insert("state".to_string(), json!(info.state));
        fields.insert(
            "state_name".to_string(),
            json!(Self::memory_state_name(info.state)),
        );
        fields.insert("protect".to_string(), json!(info.protect));
        fields.insert(
            "allocation_protect".to_string(),
            json!(info.allocation_protect),
        );
        fields.insert("region_type".to_string(), json!(info.region_type));
        fields.insert(
            "region_type_name".to_string(),
            json!(Self::memory_region_type_name(info.region_type)),
        );
        fields.insert(
            "dump_path".to_string(),
            json!(dump_path.to_string_lossy().to_string()),
        );
        fields.insert(
            "bytes_preview".to_string(),
            json!(Self::format_runtime_bytes(
                &bytes[..bytes.len().min(MEMORY_DUMP_PREVIEW_BYTES)],
            )),
        );
        if process_handle == self.current_process_space_key()
            || self.is_current_process_handle(process_handle)
        {
            self.add_address_ref_fields(fields, "address", address);
            self.add_address_ref_fields(fields, "dump_base", dump_base);
        }
    }

    pub(super) fn log_process_memory_dump_with_bytes(
        &mut self,
        marker: &str,
        process_handle: u64,
        address: u64,
        dump_base: u64,
        requested_size: u64,
        bytes: &[u8],
        info: MemoryBasicInfoSnapshot,
        mut fields: Map<String, serde_json::Value>,
    ) -> Result<Option<PathBuf>, VmError> {
        if !self.api_logger.writes_marker(marker) {
            return Ok(None);
        }
        let dump_path = self.write_memory_dump_artifact(marker, dump_base, bytes)?;
        self.enrich_memory_dump_fields(
            &mut fields,
            process_handle,
            address,
            dump_base,
            requested_size,
            info,
            bytes,
            &dump_path,
        );
        self.log_runtime_event(marker, fields)?;
        Ok(Some(dump_path))
    }

    pub(super) fn log_process_memory_dump(
        &mut self,
        marker: &str,
        process_handle: u64,
        address: u64,
        dump_base: u64,
        requested_size: u64,
        non_image_only: bool,
        fields: Map<String, serde_json::Value>,
    ) -> Result<Option<PathBuf>, VmError> {
        if !self.api_logger.writes_marker(marker) {
            return Ok(None);
        }
        let Some(info) = self.query_memory_basic_information_for_process(process_handle, address)
        else {
            return Ok(None);
        };
        if !self.should_dump_memory_region(process_handle, info, non_image_only)
            || dump_base < info.base_address
        {
            return Ok(None);
        }
        let region_end = info.base_address.saturating_add(info.region_size);
        if dump_base >= region_end {
            return Ok(None);
        }
        let capture_size =
            self.bounded_dump_capture_size(requested_size, region_end.saturating_sub(dump_base));
        let Some(bytes) = self.with_process_memory(process_handle, |memory| {
            memory.read(dump_base, capture_size as usize)
        }) else {
            return Ok(None);
        };
        let bytes = bytes.map_err(VmError::from)?;
        self.log_process_memory_dump_with_bytes(
            marker,
            process_handle,
            address,
            dump_base,
            requested_size,
            &bytes,
            info,
            fields,
        )
    }
}

impl VirtualExecutionEngine {
    fn dynamic_code_activity_key(
        &self,
        process_handle: u64,
        info: MemoryBasicInfoSnapshot,
    ) -> Option<(u64, u64)> {
        if info.state != MEM_COMMIT || info.region_type == MEM_IMAGE {
            return None;
        }
        let process_key = self.process_space_key_for_handle(process_handle)?;
        let allocation_base = if info.allocation_base != 0 {
            info.allocation_base
        } else {
            info.base_address
        };
        Some((process_key, allocation_base))
    }

    pub(super) fn dynamic_code_chain_id(process_key: u64, allocation_base: u64) -> String {
        format!("pk-0x{process_key:X}-ab-0x{allocation_base:X}")
    }

    pub(super) fn page_protect_is_executable(protect: u32) -> bool {
        matches!(
            protect & !PAGE_GUARD,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    fn log_dynamic_code_chain_snapshot(
        &mut self,
        activity: DynamicCodeRegionActivity,
    ) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("MEM_EXEC_CHAIN") {
            return Ok(());
        }

        let current_process_key = self.current_process_space_key();
        let mut fields = Map::new();
        fields.insert("stage".to_string(), json!(activity.last_stage));
        fields.insert(
            "chain_id".to_string(),
            json!(Self::dynamic_code_chain_id(
                activity.process_key,
                activity.allocation_base,
            )),
        );
        fields.insert("process_key".to_string(), json!(activity.process_key));
        fields.insert(
            "allocation_base".to_string(),
            json!(activity.allocation_base),
        );
        fields.insert("region_base".to_string(), json!(activity.region_base));
        fields.insert("region_size".to_string(), json!(activity.region_size));
        fields.insert("region_type".to_string(), json!(activity.region_type));
        fields.insert(
            "region_type_name".to_string(),
            json!(Self::memory_region_type_name(activity.region_type)),
        );
        fields.insert("has_write".to_string(), json!(activity.write.is_some()));
        fields.insert("has_protect".to_string(), json!(activity.protect.is_some()));
        fields.insert("has_thread".to_string(), json!(activity.thread.is_some()));

        if activity.process_key == current_process_key {
            self.add_address_ref_fields(&mut fields, "allocation_base", activity.allocation_base);
            self.add_address_ref_fields(&mut fields, "region_base", activity.region_base);
        }

        if let Some(write) = activity.write.as_ref() {
            fields.insert("write_source".to_string(), json!(write.source));
            fields.insert("write_remote".to_string(), json!(write.remote));
            fields.insert(
                "write_source_buffer".to_string(),
                json!(write.source_buffer),
            );
            fields.insert(
                "write_target_address".to_string(),
                json!(write.target_address),
            );
            fields.insert("write_size".to_string(), json!(write.size));
            fields.insert("write_dump_path".to_string(), json!(write.dump_path));
            fields.insert(
                "write_target_offset".to_string(),
                json!(write
                    .target_address
                    .saturating_sub(activity.allocation_base)),
            );
            if write.source_buffer != 0 {
                self.add_address_ref_fields(
                    &mut fields,
                    "write_source_buffer",
                    write.source_buffer,
                );
            }
            if activity.process_key == current_process_key {
                self.add_address_ref_fields(
                    &mut fields,
                    "write_target_address",
                    write.target_address,
                );
            }
        }

        if let Some(protect) = activity.protect.as_ref() {
            fields.insert("protect_source".to_string(), json!(protect.source));
            fields.insert("protect_remote".to_string(), json!(protect.remote));
            fields.insert("protect_address".to_string(), json!(protect.address));
            fields.insert("protect_size".to_string(), json!(protect.size));
            fields.insert("protect_old".to_string(), json!(protect.old_protect));
            fields.insert("protect_new".to_string(), json!(protect.new_protect));
            fields.insert(
                "became_executable".to_string(),
                json!(protect.became_executable),
            );
            fields.insert("protect_dump_path".to_string(), json!(protect.dump_path));
            fields.insert(
                "protect_offset".to_string(),
                json!(protect.address.saturating_sub(activity.allocation_base)),
            );
            if activity.process_key == current_process_key {
                self.add_address_ref_fields(&mut fields, "protect_address", protect.address);
            }
        }

        if let Some(thread) = activity.thread.as_ref() {
            fields.insert("thread_trigger".to_string(), json!(thread.trigger));
            fields.insert("thread_tid".to_string(), json!(thread.tid));
            fields.insert("thread_handle".to_string(), json!(thread.handle));
            fields.insert(
                "thread_start_address".to_string(),
                json!(thread.start_address),
            );
            fields.insert("thread_parameter".to_string(), json!(thread.parameter));
            fields.insert("thread_state".to_string(), json!(thread.state));
            fields.insert("thread_dump_path".to_string(), json!(thread.dump_path));
            fields.insert(
                "thread_start_offset".to_string(),
                json!(thread
                    .start_address
                    .saturating_sub(activity.allocation_base)),
            );
            if activity.process_key == current_process_key {
                self.add_address_ref_fields(
                    &mut fields,
                    "thread_start_address",
                    thread.start_address,
                );
            }
        }

        self.log_runtime_event("MEM_EXEC_CHAIN", fields)
    }

    pub(super) fn track_dynamic_code_write(
        &mut self,
        process_handle: u64,
        info: MemoryBasicInfoSnapshot,
        source: &str,
        remote: bool,
        source_buffer: u64,
        target_address: u64,
        size: u64,
        dump_path: &Path,
    ) -> Result<(), VmError> {
        let Some((process_key, allocation_base)) =
            self.dynamic_code_activity_key(process_handle, info)
        else {
            return Ok(());
        };
        let entry = self
            .dynamic_code_activities
            .entry((process_key, allocation_base))
            .or_insert_with(|| DynamicCodeRegionActivity {
                process_key,
                allocation_base,
                region_base: info.base_address,
                region_size: info.region_size,
                region_type: info.region_type,
                last_stage: String::new(),
                write: None,
                protect: None,
                thread: None,
            });
        entry.region_base = info.base_address;
        entry.region_size = info.region_size;
        entry.region_type = info.region_type;
        entry.last_stage = "write".to_string();
        entry.write = Some(DynamicCodeWriteObservation {
            source: source.to_string(),
            remote,
            source_buffer,
            target_address,
            size,
            dump_path: dump_path.to_string_lossy().to_string(),
        });
        let snapshot = entry.clone();
        self.log_dynamic_code_chain_snapshot(snapshot)
    }

    pub(super) fn track_dynamic_code_protect(
        &mut self,
        process_handle: u64,
        info: MemoryBasicInfoSnapshot,
        source: &str,
        remote: bool,
        address: u64,
        size: u64,
        old_protect: u32,
        new_protect: u32,
        dump_path: &Path,
    ) -> Result<(), VmError> {
        let Some((process_key, allocation_base)) =
            self.dynamic_code_activity_key(process_handle, info)
        else {
            return Ok(());
        };
        let became_executable = Self::page_protect_is_executable(new_protect)
            && !Self::page_protect_is_executable(old_protect);
        let entry = self
            .dynamic_code_activities
            .entry((process_key, allocation_base))
            .or_insert_with(|| DynamicCodeRegionActivity {
                process_key,
                allocation_base,
                region_base: info.base_address,
                region_size: info.region_size,
                region_type: info.region_type,
                last_stage: String::new(),
                write: None,
                protect: None,
                thread: None,
            });
        entry.region_base = info.base_address;
        entry.region_size = info.region_size;
        entry.region_type = info.region_type;
        entry.last_stage = "protect".to_string();
        entry.protect = Some(DynamicCodeProtectObservation {
            source: source.to_string(),
            remote,
            address,
            size,
            old_protect,
            new_protect,
            became_executable,
            dump_path: dump_path.to_string_lossy().to_string(),
        });
        let snapshot = entry.clone();
        self.log_dynamic_code_chain_snapshot(snapshot)
    }

    pub(super) fn track_dynamic_code_thread(
        &mut self,
        process_handle: u64,
        info: MemoryBasicInfoSnapshot,
        trigger: &str,
        tid: u32,
        handle: u32,
        start_address: u64,
        parameter: u64,
        state: &str,
        dump_path: &Path,
    ) -> Result<(), VmError> {
        let Some((process_key, allocation_base)) =
            self.dynamic_code_activity_key(process_handle, info)
        else {
            return Ok(());
        };
        let entry = self
            .dynamic_code_activities
            .entry((process_key, allocation_base))
            .or_insert_with(|| DynamicCodeRegionActivity {
                process_key,
                allocation_base,
                region_base: info.base_address,
                region_size: info.region_size,
                region_type: info.region_type,
                last_stage: String::new(),
                write: None,
                protect: None,
                thread: None,
            });
        entry.region_base = info.base_address;
        entry.region_size = info.region_size;
        entry.region_type = info.region_type;
        entry.last_stage = "thread".to_string();
        entry.thread = Some(DynamicCodeThreadObservation {
            trigger: trigger.to_string(),
            tid,
            handle,
            start_address,
            parameter,
            state: state.to_string(),
            dump_path: dump_path.to_string_lossy().to_string(),
        });
        let snapshot = entry.clone();
        self.log_dynamic_code_chain_snapshot(snapshot)
    }
}

impl VirtualExecutionEngine {
    pub(super) fn log_modified_image_dumps(&mut self, reason: &str) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("IMAGE_MODIFIED_DUMP") {
            return Ok(());
        }

        let process_key = self.current_process_space_key();
        let modules = self
            .current_process_modules()
            .into_iter()
            .filter(|module| !module.synthetic)
            .collect::<Vec<_>>();
        for module in modules {
            let Some(baseline) = self
                .image_hash_baselines
                .get(&(process_key, module.base))
                .cloned()
            else {
                continue;
            };
            let capture_size = baseline.capture_size.max(1);
            let Some(bytes) = self.read_process_memory_by_key(
                process_key,
                module.base,
                usize::try_from(capture_size).unwrap_or(usize::MAX),
            ) else {
                continue;
            };
            let bytes = bytes.map_err(VmError::from)?;
            let current_hash = Self::stable_runtime_hash(&bytes);
            if current_hash == baseline.hash {
                continue;
            }
            let Some(info) = self.current_process_image_dump_info(&module, capture_size) else {
                continue;
            };

            let mut fields = Map::new();
            fields.insert("trigger".to_string(), json!("RUN_STOP"));
            fields.insert("reason".to_string(), json!(reason));
            fields.insert("module_name".to_string(), json!(module.name.clone()));
            fields.insert("module_base".to_string(), json!(module.base));
            fields.insert("module_size".to_string(), json!(module.size));
            fields.insert(
                "capture_size".to_string(),
                json!(capture_size.min(bytes.len() as u64)),
            );
            fields.insert(
                "baseline_hash".to_string(),
                json!(format!("{:016x}", baseline.hash)),
            );
            fields.insert(
                "current_hash".to_string(),
                json!(format!("{:016x}", current_hash)),
            );
            if let Some(path) = module.path.as_ref() {
                fields.insert(
                    "module_path".to_string(),
                    json!(path.to_string_lossy().to_string()),
                );
            }
            self.add_address_ref_fields(&mut fields, "module_base", module.base);
            let _ = self.log_process_memory_dump_with_bytes(
                "IMAGE_MODIFIED_DUMP",
                self.current_process_space_key(),
                module.base,
                module.base,
                capture_size,
                &bytes,
                info,
                fields,
            )?;
        }
        Ok(())
    }

    pub(super) fn log_exit_executable_allocation_dumps(
        &mut self,
        reason: &str,
    ) -> Result<(), VmError> {
        if !self.api_logger.writes_marker("MEM_EXEC_EXIT_DUMP") {
            return Ok(());
        }

        let current_process_key = self.current_process_space_key();
        let candidates = self.collect_executable_virtual_allocation_segments();
        for (process_key, record, segment) in candidates {
            let capture_size = self.bounded_dump_capture_size(segment.size, segment.size);
            let Some(bytes) =
                self.read_process_memory_by_key(process_key, segment.base, capture_size as usize)
            else {
                continue;
            };
            let bytes = bytes.map_err(VmError::from)?;
            let mut fields = Map::new();
            fields.insert("trigger".to_string(), json!("RUN_STOP"));
            fields.insert("reason".to_string(), json!(reason));
            fields.insert("process_key".to_string(), json!(process_key));
            fields.insert(
                "is_current_process".to_string(),
                json!(process_key == current_process_key),
            );
            fields.insert("allocation_size".to_string(), json!(record.allocation_size));
            fields.insert("allocation_type".to_string(), json!(record.allocation_type));
            fields.insert("segment_base".to_string(), json!(segment.base));
            fields.insert("segment_size".to_string(), json!(segment.size));
            fields.insert(
                "segment_offset".to_string(),
                json!(segment.base.saturating_sub(record.allocation_base)),
            );
            fields.insert("segment_protect".to_string(), json!(segment.protect));
            if let Some(activity) = self
                .dynamic_code_activities
                .get(&(process_key, record.allocation_base))
            {
                fields.insert(
                    "chain_id".to_string(),
                    json!(Self::dynamic_code_chain_id(
                        process_key,
                        record.allocation_base
                    )),
                );
                fields.insert("has_write".to_string(), json!(activity.write.is_some()));
                fields.insert("has_protect".to_string(), json!(activity.protect.is_some()));
                fields.insert("has_thread".to_string(), json!(activity.thread.is_some()));
                fields.insert("last_stage".to_string(), json!(activity.last_stage));
            }
            let process_handle = self.process_handle_for_process_key(process_key);
            let info = MemoryBasicInfoSnapshot {
                base_address: segment.base,
                allocation_base: record.allocation_base,
                allocation_protect: record.allocation_protect,
                region_size: segment.size,
                state: segment.state,
                protect: segment.protect,
                region_type: record.region_type,
            };
            let _ = self.log_process_memory_dump_with_bytes(
                "MEM_EXEC_EXIT_DUMP",
                process_handle,
                segment.base,
                segment.base,
                segment.size,
                &bytes,
                info,
                fields,
            )?;
        }
        Ok(())
    }
}

impl VirtualExecutionEngine {
    pub(super) fn log_memory_protection_dump(
        &mut self,
        process_handle: u64,
        aligned_base: u64,
        aligned_size: u64,
        old_protect: u32,
        new_protect: u32,
        source: &str,
        remote: bool,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("trigger".to_string(), json!("MEM_PROTECT"));
        fields.insert("source".to_string(), json!(source));
        fields.insert("old_protect".to_string(), json!(old_protect));
        fields.insert("new_protect".to_string(), json!(new_protect));
        fields.insert(
            "became_executable".to_string(),
            json!(
                Self::page_protect_is_executable(new_protect)
                    && !Self::page_protect_is_executable(old_protect)
            ),
        );
        fields.insert("remote".to_string(), json!(remote));
        let Some(info) =
            self.query_memory_basic_information_for_process(process_handle, aligned_base)
        else {
            return Ok(());
        };
        let dump_path = self.log_process_memory_dump(
            "MEM_PROTECT_DUMP",
            process_handle,
            aligned_base,
            aligned_base,
            info.region_size.max(aligned_size),
            false,
            fields,
        )?;
        if let Some(dump_path) = dump_path {
            self.track_dynamic_code_protect(
                process_handle,
                info,
                source,
                remote,
                aligned_base,
                aligned_size,
                old_protect,
                new_protect,
                &dump_path,
            )?;
        }
        Ok(())
    }

    pub(super) fn log_memory_write_dump(
        &mut self,
        process_handle: u64,
        base_address: u64,
        source_buffer: u64,
        data: &[u8],
        source: &str,
        remote: bool,
    ) -> Result<(), VmError> {
        let Some(info) =
            self.query_memory_basic_information_for_process(process_handle, base_address)
        else {
            return Ok(());
        };
        if !self.should_dump_memory_region(process_handle, info, true) {
            return Ok(());
        }
        let capture_len = data
            .len()
            .min(usize::try_from(self.sample_dump_size_limit_bytes()).unwrap_or(usize::MAX));
        let mut fields = Map::new();
        fields.insert("trigger".to_string(), json!("MEM_WRITE"));
        fields.insert("source".to_string(), json!(source));
        fields.insert("source_buffer".to_string(), json!(source_buffer));
        fields.insert("remote".to_string(), json!(remote));
        if source_buffer != 0 {
            self.add_address_ref_fields(&mut fields, "source_buffer", source_buffer);
        }
        let dump_path = self.log_process_memory_dump_with_bytes(
            "MEM_WRITE_DUMP",
            process_handle,
            base_address,
            base_address,
            data.len() as u64,
            &data[..capture_len],
            info,
            fields,
        )?;
        if let Some(dump_path) = dump_path {
            self.track_dynamic_code_write(
                process_handle,
                info,
                source,
                remote,
                source_buffer,
                base_address,
                data.len() as u64,
                &dump_path,
            )?;
        }
        Ok(())
    }

    pub(super) fn log_thread_entry_dump_for_process_if_dynamic(
        &mut self,
        marker: &str,
        trigger: &str,
        process_handle: u64,
        tid: u32,
        handle: u32,
        start_address: u64,
        parameter: u64,
        state: &str,
        mut fields: Map<String, serde_json::Value>,
    ) -> Result<(), VmError> {
        let Some(info) =
            self.query_memory_basic_information_for_process(process_handle, start_address)
        else {
            return Ok(());
        };
        if !self.should_dump_memory_region(process_handle, info, true) {
            return Ok(());
        }
        fields.insert("trigger".to_string(), json!(trigger));
        fields.insert("thread_tid".to_string(), json!(tid));
        fields.insert("thread_handle".to_string(), json!(handle));
        fields.insert("start_address".to_string(), json!(start_address));
        fields.insert("parameter".to_string(), json!(parameter));
        fields.insert("state".to_string(), json!(state));
        fields.insert(
            "start_offset".to_string(),
            json!(start_address.saturating_sub(info.base_address)),
        );
        let dump_path = self.log_process_memory_dump(
            marker,
            process_handle,
            start_address,
            start_address,
            info.region_size,
            true,
            fields,
        )?;
        if let Some(dump_path) = dump_path {
            self.track_dynamic_code_thread(
                process_handle,
                info,
                trigger,
                tid,
                handle,
                start_address,
                parameter,
                state,
                &dump_path,
            )?;
        }
        Ok(())
    }

    pub(super) fn log_thread_entry_dump_if_dynamic(
        &mut self,
        marker: &str,
        trigger: &str,
        tid: u32,
        handle: u32,
        start_address: u64,
        parameter: u64,
        state: &str,
    ) -> Result<(), VmError> {
        self.log_thread_entry_dump_for_process_if_dynamic(
            marker,
            trigger,
            self.current_process_space_key(),
            tid,
            handle,
            start_address,
            parameter,
            state,
            Map::new(),
        )
    }
}
