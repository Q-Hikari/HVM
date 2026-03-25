use super::*;

#[derive(Debug, Clone)]
struct ProcessRuntimeProfile {
    identity: SyntheticProcessIdentity,
    current_directory: String,
}

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn is_current_process_handle(&self, handle: u64) -> bool {
        handle == 0
            || handle == self.current_process_id() as u64
            || (handle & 0xFFFF_FFFF) == PROCESS_HANDLE_PSEUDO
    }

    pub(in crate::runtime::engine) fn module_record_for_handle(
        &self,
        module_handle: u64,
    ) -> Option<&ModuleRecord> {
        if module_handle == 0 {
            self.main_module.as_ref()
        } else {
            self.modules.get_by_base(module_handle)
        }
    }

    pub(in crate::runtime::engine) fn current_process_modules(&self) -> Vec<ModuleRecord> {
        let mut modules = self.modules.loaded_modules();
        if modules.is_empty() {
            return modules;
        }
        let process_image_base = self
            .main_module
            .as_ref()
            .map(|module| module.base)
            .or_else(|| modules.first().map(|module| module.base))
            .unwrap_or(0);
        let original_order = modules
            .iter()
            .enumerate()
            .map(|(index, module)| (module.base, index))
            .collect::<BTreeMap<_, _>>();
        modules.sort_by_key(|module| {
            (
                module.base != process_image_base,
                Self::startup_module_order_rank(&module.name),
                original_order
                    .get(&module.base)
                    .copied()
                    .unwrap_or(usize::MAX),
                module.base,
            )
        });
        modules
    }

    pub(in crate::runtime::engine) fn sync_process_environment_modules(
        &mut self,
    ) -> Result<(), VmError> {
        let modules = self.current_process_modules();
        self.process_env.sync_modules(&modules)?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn module_process_attach_completed(
        &self,
        module: &ModuleRecord,
    ) -> bool {
        self.attached_process_modules.contains(&module.base)
            || (!module.synthetic && module.initialized)
    }

    pub(in crate::runtime::engine) fn startup_module_order_rank(module_name: &str) -> usize {
        STARTUP_BASELINE_MODULES
            .iter()
            .position(|candidate| compare_ci(candidate, module_name) == 0)
            .unwrap_or(usize::MAX)
    }

    pub(in crate::runtime::engine) fn strict_unknown_api_policy(&self) -> bool {
        matches!(
            self.config.unknown_api_policy.to_ascii_lowercase().as_str(),
            "strict" | "error" | "fail"
        )
    }

    pub(in crate::runtime::engine) fn current_process_image_path(&self) -> String {
        if !self.environment_profile.machine.image_path.is_empty() {
            return self.environment_profile.machine.image_path.clone();
        }
        self.module_path_for_handle(0).unwrap_or_else(|| {
            self.config
                .process_image_path()
                .to_string_lossy()
                .to_string()
        })
    }

    pub(in crate::runtime::engine) fn build_parent_process_identity(
        &self,
    ) -> Option<SyntheticProcessIdentity> {
        let has_parent_override = self.config.parent_process_image.is_some()
            || self.config.parent_process_pid.is_some()
            || self.config.parent_process_command_line.is_some();
        let has_profile_parent = self.environment_profile.has_parent_process();
        if !has_parent_override && !has_profile_parent {
            return None;
        }

        let image_path = self
            .config
            .parent_process_image
            .as_ref()
            .map(|path| path.to_string_lossy().to_string())
            .filter(|path| !path.is_empty())
            .or_else(|| {
                (!self
                    .environment_profile
                    .machine
                    .parent_image_path
                    .is_empty())
                .then_some(self.environment_profile.machine.parent_image_path.clone())
            })
            .unwrap_or_default();
        let command_line = self
            .config
            .parent_process_command_line
            .clone()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                (!self
                    .environment_profile
                    .machine
                    .parent_command_line
                    .is_empty())
                .then_some(self.environment_profile.machine.parent_command_line.clone())
            })
            .unwrap_or_else(|| image_path.clone());

        Some(SyntheticProcessIdentity {
            pid: self
                .config
                .parent_process_pid
                .unwrap_or_else(|| self.environment_profile.machine.parent_process_id.max(1)),
            parent_pid: 0,
            image_path,
            command_line,
            current_directory: self.environment_profile.machine.current_directory.clone(),
        })
    }

    pub(in crate::runtime::engine) fn current_process_parent_id(&self) -> u32 {
        self.parent_process
            .as_ref()
            .map(|process| process.pid)
            .unwrap_or(0)
    }

    pub(in crate::runtime::engine) fn current_process_identity(&self) -> SyntheticProcessIdentity {
        SyntheticProcessIdentity {
            pid: self.current_process_id(),
            parent_pid: self.current_process_parent_id(),
            image_path: self.current_process_image_path(),
            command_line: self.command_line.clone(),
            current_directory: self.current_directory_display_text(),
        }
    }

    pub(in crate::runtime::engine) fn known_process_identities(
        &self,
    ) -> Vec<SyntheticProcessIdentity> {
        let mut processes = BTreeMap::new();
        for profile in &self.environment_profile.processes {
            if profile.pid == 0 {
                continue;
            }
            processes.insert(
                profile.pid,
                SyntheticProcessIdentity {
                    pid: profile.pid,
                    parent_pid: profile.parent_pid,
                    image_path: profile.image_path.clone(),
                    command_line: if profile.command_line.is_empty() {
                        profile.image_path.clone()
                    } else {
                        profile.command_line.clone()
                    },
                    current_directory: profile.current_directory.clone(),
                },
            );
        }
        if let Some(parent) = self.parent_process.clone() {
            processes.insert(parent.pid, parent);
        }
        let current = self.current_process_identity();
        processes.insert(current.pid, current);
        processes.into_values().collect()
    }

    pub(in crate::runtime::engine) fn process_identity_by_pid(
        &self,
        pid: u32,
    ) -> Option<SyntheticProcessIdentity> {
        self.known_process_identities()
            .into_iter()
            .find(|process| process.pid == pid)
    }

    pub(in crate::runtime::engine) fn process_identity_for_handle(
        &self,
        handle: u64,
    ) -> Option<SyntheticProcessIdentity> {
        if self.is_current_process_handle(handle) {
            return Some(self.current_process_identity());
        }
        if let Some(&pid) = self.process_handles.get(&(handle as u32)) {
            return self.process_identity_by_pid(pid);
        }
        let record = self.processes.find_process_by_handle(handle as u32)?;
        Some(SyntheticProcessIdentity {
            pid: handle as u32,
            parent_pid: self.current_process_id(),
            image_path: record.image_path.clone(),
            command_line: record.command_line.clone(),
            current_directory: record.current_directory.clone(),
        })
    }

    fn process_runtime_profile_for_handle(&self, handle: u64) -> Option<ProcessRuntimeProfile> {
        if self.is_current_process_handle(handle) {
            return Some(ProcessRuntimeProfile {
                identity: self.current_process_identity(),
                current_directory: self.current_directory_display_text(),
            });
        }
        if let Some(&pid) = self.process_handles.get(&(handle as u32)) {
            let identity = self.process_identity_by_pid(pid)?;
            let current_directory = if identity.current_directory.is_empty() {
                std::path::Path::new(&identity.image_path)
                    .parent()
                    .map(|path| path.to_string_lossy().to_string())
                    .filter(|path| !path.is_empty())
                    .unwrap_or_else(|| self.current_directory_display_text())
            } else {
                identity.current_directory.clone()
            };
            return Some(ProcessRuntimeProfile {
                identity,
                current_directory,
            });
        }
        let record = self.processes.find_process_by_handle(handle as u32)?;
        Some(ProcessRuntimeProfile {
            identity: SyntheticProcessIdentity {
                pid: handle as u32,
                parent_pid: self.current_process_id(),
                image_path: record.image_path.clone(),
                command_line: record.command_line.clone(),
                current_directory: record.current_directory.clone(),
            },
            current_directory: record.current_directory.clone(),
        })
    }

    fn build_fallback_process_module(&self, profile: &ProcessRuntimeProfile) -> ModuleRecord {
        let path = std::path::PathBuf::from(&profile.identity.image_path);
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| profile.identity.image_name());
        let base = if self.arch.is_x86() {
            0x0040_0000
        } else {
            0x0000_0140_0000_0000
        };
        ModuleRecord {
            name,
            path: (!profile.identity.image_path.is_empty()).then_some(path),
            arch: self.arch.name.to_string(),
            is_dll: false,
            base,
            size: 0x100000,
            entrypoint: base + 0x1000,
            image_base: base,
            synthetic: true,
            tls_callbacks: Vec::new(),
            initialized: true,
            exports_by_name: Default::default(),
            export_name_text_by_key: Default::default(),
            exports_by_ordinal: Default::default(),
            forwarded_exports_by_name: Default::default(),
            forwarded_exports_by_ordinal: Default::default(),
            stub_cursor: 0,
        }
    }

    pub(in crate::runtime::engine) fn ensure_process_space_initialized(
        &mut self,
        process_handle: u64,
    ) -> Result<Option<u64>, VmError> {
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return Ok(None);
        };
        if process_key == self.current_process_space_key() {
            return Ok(Some(process_key));
        }
        if self
            .process_spaces
            .get(&process_key)
            .map(|space| !space.modules.is_empty())
            .unwrap_or(false)
        {
            return Ok(Some(process_key));
        }

        let Some(profile) = self.process_runtime_profile_for_handle(process_handle) else {
            return Ok(None);
        };
        let mut space = self
            .process_spaces
            .remove(&process_key)
            .unwrap_or_else(|| SyntheticProcessSpace::new(self.arch));

        let module = if !profile.identity.image_path.is_empty() {
            let path = std::path::PathBuf::from(&profile.identity.image_path);
            if path.exists() {
                map_image(&path, &mut space.memory)
                    .unwrap_or_else(|_| self.build_fallback_process_module(&profile))
            } else {
                self.build_fallback_process_module(&profile)
            }
        } else {
            self.build_fallback_process_module(&profile)
        };
        let modules = vec![module.clone()];

        space.process_env = WindowsProcessEnvironment::for_tests(self.arch);
        let image_path = if profile.identity.image_path.is_empty() {
            profile.identity.command_line.clone()
        } else {
            profile.identity.image_path.clone()
        };
        let current_directory = if profile.current_directory.is_empty() {
            if profile.identity.current_directory.is_empty() {
                self.current_directory_display_text()
            } else {
                profile.identity.current_directory.clone()
            }
        } else {
            profile.current_directory.clone()
        };
        let dll_path = self.system_directory_path();
        let environment = self.runtime_environment_entries();
        space
            .process_env
            .configure_process_parameters_with_runtime_details_and_environment(
                &image_path,
                &profile.identity.command_line,
                &current_directory,
                &dll_path,
                &environment,
            )
            .map_err(VmError::from)?;
        space
            .process_env
            .sync_modules(&modules)
            .map_err(VmError::from)?;
        space.process_env.sync_image_base(module.base);
        space.process_env.sync_teb_client_id(
            space.process_env.current_teb(),
            profile.identity.pid,
            1,
        );
        space.process_env.sync_last_error(0);
        space
            .process_env
            .materialize_into(&mut space.memory)
            .map_err(VmError::from)?;
        if let Some(record) = Self::module_image_allocation_record(&space.memory, &module) {
            space
                .virtual_allocations
                .insert(record.allocation_base, record);
        }
        space.modules = modules;
        self.process_spaces.insert(process_key, space);
        Ok(Some(process_key))
    }

    pub(in crate::runtime::engine) fn module_image_allocation_record(
        memory: &MemoryManager,
        module: &ModuleRecord,
    ) -> Option<VirtualAllocationRecord> {
        if module.synthetic || module.size == 0 {
            return None;
        }

        let allocation_base = module.base;
        let allocation_size = module.size;
        let allocation_end = allocation_base.saturating_add(allocation_size);
        let mut cursor = allocation_base;
        let mut segments = Vec::new();

        for region in memory
            .regions
            .iter()
            .filter(|region| allocation_base < region.end() && region.base < allocation_end)
        {
            let segment_base = region.base.max(allocation_base);
            if segment_base > cursor {
                segments.push(VirtualAllocationSegment {
                    base: cursor,
                    size: segment_base - cursor,
                    state: MEM_RESERVE,
                    protect: 0,
                });
            }

            let segment_end = region.end().min(allocation_end);
            if segment_end > segment_base {
                segments.push(VirtualAllocationSegment {
                    base: segment_base,
                    size: segment_end - segment_base,
                    state: MEM_COMMIT,
                    protect: Self::page_protect_from_perms(region.perms),
                });
                cursor = segment_end;
            }
        }

        if segments.is_empty() {
            return None;
        }
        if cursor < allocation_end {
            segments.push(VirtualAllocationSegment {
                base: cursor,
                size: allocation_end - cursor,
                state: MEM_RESERVE,
                protect: 0,
            });
        }

        let segments = VirtualAllocationRecord::merge_segments(segments);
        let allocation_protect = segments
            .iter()
            .find(|segment| segment.state == MEM_COMMIT)
            .map(|segment| segment.protect)
            .unwrap_or(PAGE_NOACCESS);
        Some(VirtualAllocationRecord {
            allocation_base,
            allocation_size,
            allocation_protect,
            allocation_type: MEM_COMMIT,
            region_type: MEM_IMAGE,
            segments,
        })
    }

    pub(in crate::runtime::engine) fn register_module_image_allocation(
        &mut self,
        process_handle: u64,
        module: &ModuleRecord,
    ) -> Result<(), VmError> {
        let record = self
            .with_process_memory(process_handle, |memory| {
                Self::module_image_allocation_record(memory, module)
            })
            .flatten();
        if let Some(record) = record {
            self.insert_virtual_allocation_record(process_handle, record)?;
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn register_mapped_view_allocation(
        &mut self,
        process_handle: u64,
        view: &MappingViewRecord,
    ) -> Result<(), VmError> {
        self.insert_virtual_allocation_record(
            process_handle,
            VirtualAllocationRecord {
                allocation_base: view.base,
                allocation_size: view.alloc_size,
                allocation_protect: view.protect,
                allocation_type: MEM_COMMIT,
                region_type: if view.image { MEM_IMAGE } else { MEM_MAPPED },
                segments: vec![VirtualAllocationSegment {
                    base: view.base,
                    size: view.alloc_size,
                    state: MEM_COMMIT,
                    protect: view.protect,
                }],
            },
        )
    }

    pub(in crate::runtime::engine) fn register_initial_thread_stack_allocation(
        &mut self,
        process_handle: u64,
        allocation_base: u64,
        stack_base: u64,
        stack_top: u64,
    ) -> Result<u64, VmError> {
        if !self.arch.is_x86() {
            return Ok(allocation_base);
        }

        let commit_base = stack_top.saturating_sub(PAGE_SIZE);
        let guard_base = commit_base.saturating_sub(PAGE_SIZE);
        if guard_base <= allocation_base || commit_base >= stack_base {
            return Ok(allocation_base);
        }

        self.modules
            .memory_mut()
            .protect(
                allocation_base,
                commit_base.saturating_sub(allocation_base),
                0,
            )
            .map_err(VmError::from)?;

        let mut segments = Vec::with_capacity(3);
        if guard_base > allocation_base {
            segments.push(VirtualAllocationSegment {
                base: allocation_base,
                size: guard_base - allocation_base,
                state: MEM_RESERVE,
                protect: 0,
            });
        }
        segments.push(VirtualAllocationSegment {
            base: guard_base,
            size: PAGE_SIZE,
            state: MEM_COMMIT,
            protect: PAGE_READWRITE | PAGE_GUARD,
        });
        segments.push(VirtualAllocationSegment {
            base: commit_base,
            size: stack_base.saturating_sub(commit_base),
            state: MEM_COMMIT,
            protect: PAGE_READWRITE,
        });

        self.insert_virtual_allocation_record(
            process_handle,
            VirtualAllocationRecord {
                allocation_base,
                allocation_size: stack_base.saturating_sub(allocation_base),
                allocation_protect: PAGE_READWRITE,
                allocation_type: MEM_COMMIT | MEM_RESERVE,
                region_type: MEM_PRIVATE,
                segments: VirtualAllocationRecord::merge_segments(segments),
            },
        )?;

        if self.is_current_process_handle(process_handle) {
            self.sync_current_process_native_page_protection(
                allocation_base,
                stack_base.saturating_sub(allocation_base),
            )?;
        }

        Ok(commit_base)
    }

    pub(in crate::runtime::engine) fn unregister_process_virtual_allocation(
        &mut self,
        process_handle: u64,
        allocation_base: u64,
    ) {
        let _ = self.remove_virtual_allocation_record(process_handle, allocation_base);
    }

    pub(in crate::runtime::engine) fn current_process_space_key(&self) -> u64 {
        self.current_process_id() as u64
    }

    pub(in crate::runtime::engine) fn process_space_key_for_handle(
        &self,
        handle: u64,
    ) -> Option<u64> {
        if self.is_current_process_handle(handle) {
            Some(self.current_process_space_key())
        } else if let Some(&pid) = self.process_handles.get(&(handle as u32)) {
            Some(pid as u64)
        } else if self
            .processes
            .find_process_by_handle(handle as u32)
            .is_some()
        {
            Some(SHELL_PROCESS_SPACE_KEY_BASE | handle)
        } else {
            None
        }
    }

    pub(in crate::runtime::engine) fn is_known_process_target(&self, handle: u64) -> bool {
        self.process_space_key_for_handle(handle).is_some()
    }

    pub(in crate::runtime::engine) fn process_virtual_allocations(
        &self,
        process_key: u64,
    ) -> Option<&BTreeMap<u64, VirtualAllocationRecord>> {
        if process_key == self.current_process_space_key() {
            Some(&self.virtual_allocations)
        } else {
            self.process_spaces
                .get(&process_key)
                .map(|space| &space.virtual_allocations)
        }
    }

    pub(in crate::runtime::engine) fn process_virtual_allocations_mut(
        &mut self,
        process_key: u64,
    ) -> Option<&mut BTreeMap<u64, VirtualAllocationRecord>> {
        if process_key == self.current_process_space_key() {
            Some(&mut self.virtual_allocations)
        } else {
            self.process_spaces
                .get_mut(&process_key)
                .map(|space| &mut space.virtual_allocations)
        }
    }

    pub(in crate::runtime::engine) fn virtual_allocation_record_for_process(
        &self,
        process_handle: u64,
        address: u64,
    ) -> Option<&VirtualAllocationRecord> {
        let process_key = self.process_space_key_for_handle(process_handle)?;
        let allocations = self.process_virtual_allocations(process_key)?;
        let (_, record) = allocations.range(..=address).next_back()?;
        record.contains(address).then_some(record)
    }

    pub(in crate::runtime::engine) fn virtual_allocation_record_mut_for_process(
        &mut self,
        process_handle: u64,
        address: u64,
    ) -> Option<&mut VirtualAllocationRecord> {
        let process_key = self.process_space_key_for_handle(process_handle)?;
        let allocations = self.process_virtual_allocations_mut(process_key)?;
        let (_, record) = allocations.range_mut(..=address).next_back()?;
        record.contains(address).then_some(record)
    }

    pub(in crate::runtime::engine) fn virtual_allocation_snapshot_for_process(
        &self,
        process_handle: u64,
        address: u64,
    ) -> Option<MemoryBasicInfoSnapshot> {
        let record = self.virtual_allocation_record_for_process(process_handle, address)?;
        let segment = record.segment_for_address(address)?;
        Some(MemoryBasicInfoSnapshot {
            base_address: segment.base,
            allocation_base: record.allocation_base,
            allocation_protect: record.allocation_protect,
            region_size: segment.size,
            state: segment.state,
            protect: if segment.state == MEM_COMMIT {
                segment.protect
            } else {
                0
            },
            region_type: if segment.state == MEM_COMMIT {
                record.region_type
            } else {
                0
            },
        })
    }

    pub(in crate::runtime::engine) fn virtual_allocation_range_is_accessible(
        &self,
        process_handle: u64,
        address: u64,
        size: usize,
        write: bool,
    ) -> Option<bool> {
        let record = self.virtual_allocation_record_for_process(process_handle, address)?;
        let end = address.saturating_add(size.max(1) as u64);
        if end > record.end() {
            return Some(false);
        }
        Some(
            record
                .segments
                .iter()
                .filter(|segment| address < segment.end() && segment.base < end)
                .all(|segment| {
                    segment.state == MEM_COMMIT
                        && !Self::page_protect_has_guard(segment.protect)
                        && if write {
                            Self::page_protect_allows_write(segment.protect)
                        } else {
                            Self::page_protect_allows_read(segment.protect)
                        }
                }),
        )
    }

    pub(in crate::runtime::engine) fn with_process_memory_mut<T, F>(
        &mut self,
        process_handle: u64,
        f: F,
    ) -> Result<Option<T>, VmError>
    where
        F: FnOnce(&mut MemoryManager) -> Result<T, VmError>,
    {
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return Ok(None);
        };
        if process_key == self.current_process_space_key() {
            return f(self.modules.memory_mut()).map(Some);
        }
        let arch = self.arch;
        let space = self
            .process_spaces
            .entry(process_key)
            .or_insert_with(|| SyntheticProcessSpace::new(arch));
        f(&mut space.memory).map(Some)
    }

    pub(in crate::runtime::engine) fn with_process_key_memory_mut<T, F>(
        &mut self,
        process_key: u64,
        f: F,
    ) -> Result<Option<T>, VmError>
    where
        F: FnOnce(&mut MemoryManager) -> Result<T, VmError>,
    {
        if process_key == self.current_process_space_key() {
            return f(self.modules.memory_mut()).map(Some);
        }
        self.process_spaces
            .get_mut(&process_key)
            .map(|space| f(&mut space.memory))
            .transpose()
    }

    pub(in crate::runtime::engine) fn with_process_memory<T, F>(
        &self,
        process_handle: u64,
        f: F,
    ) -> Option<T>
    where
        F: FnOnce(&MemoryManager) -> T,
    {
        let process_key = self.process_space_key_for_handle(process_handle)?;
        if process_key == self.current_process_space_key() {
            Some(f(self.modules.memory()))
        } else if let Some(space) = self.process_spaces.get(&process_key) {
            Some(f(&space.memory))
        } else {
            let empty = MemoryManager::for_arch(self.arch);
            Some(f(&empty))
        }
    }

    pub(in crate::runtime::engine) fn propagate_file_mapping_write(
        &mut self,
        process_handle: u64,
        address: u64,
        data: &[u8],
    ) -> Result<(), VmError> {
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return Ok(());
        };
        let targets = self
            .file_mappings
            .record_view_write(process_key, address, data)
            .unwrap_or_default();
        for MappingWriteTarget {
            process_key,
            address,
            source_offset,
            length,
        } in targets
        {
            let slice = &data[source_offset..source_offset + length];
            let _ = self.with_process_key_memory_mut(process_key, |memory| {
                memory.write(address, slice).map_err(VmError::from)
            })?;
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn sync_current_process_native_page_protection(
        &mut self,
        address: u64,
        size: u64,
    ) -> Result<(), VmError> {
        let (Some(unicorn), Some(handle)) = (self.unicorn.as_deref(), self.unicorn_handle) else {
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
            if let Some(region) = self.modules.memory().find_region(cursor, 1) {
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
        self.process_identity_by_pid(pid)?;
        let handle = self.next_object_handle;
        self.next_object_handle = self.next_object_handle.saturating_add(4);
        self.process_handles.insert(handle, pid);
        self.scheduler
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

        // 当前 runtime 只支持同进程内复制句柄；跨进程复制先明确失败，
        // 避免把目标句柄写成无效值后继续执行。
        if !self.is_current_process_handle(source_process_handle)
            || !self.is_current_process_handle(target_process_handle)
        {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }

        let duplicated = if self
            .scheduler
            .thread_tid_for_handle(source_handle)
            .is_some()
        {
            // 线程句柄目前直接复用已有 handle 值即可，能够满足样本里
            // “保存当前线程句柄供后续 Get/SetThreadContext 使用”的路径。
            source_handle
        } else if self
            .process_identity_for_handle(source_handle as u64)
            .is_some()
        {
            source_handle
        } else if let Some(&canonical) = self.mutex_handle_targets.get(&source_handle) {
            let alias = self.next_object_handle;
            self.next_object_handle = self.next_object_handle.saturating_add(4);
            self.mutex_handles.insert(alias);
            self.mutex_handle_targets.insert(alias, canonical);
            alias
        } else if self.file_handles.contains_key(&source_handle)
            || self.device_handles.contains_key(&source_handle)
            || self.process_snapshots.contains_key(&source_handle)
            || self.token_handles.contains(&source_handle)
            || self.file_mappings.resolve_mapping(source_handle).is_some()
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
        closed |= self.file_handles.remove(&handle).is_some();
        closed |= self.find_handles.remove(&handle).is_some();
        closed |= self.volume_find_handles.remove(&handle).is_some();
        closed |= self.device_handles.remove(&handle).is_some();
        closed |= self.process_handles.remove(&handle).is_some();
        closed |= self.process_snapshots.remove(&handle).is_some();
        closed |= self.token_handles.remove(&handle);
        closed |= self.file_mappings.close_handle(handle);
        closed |= self.mutex_handles.remove(&handle);
        closed |= self.mutex_handle_targets.remove(&handle).is_some();
        closed |= self.setup_device_sets.remove(&handle).is_some();
        closed |= self.wts_server_handles.remove(&handle);
        closed |= self.user32_close_object_handle(handle);
        closed
    }

    pub(in crate::runtime::engine) fn current_process_thread_count(&self) -> u32 {
        self.scheduler
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

        let handle = self.next_object_handle;
        self.next_object_handle = self.next_object_handle.saturating_add(4);
        self.process_snapshots.insert(
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
        let Some(snapshot) = self.process_snapshots.get_mut(&handle) else {
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

        self.modules.memory_mut().write(entry_ptr, &bytes)?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn module_path_for_handle(
        &self,
        module_handle: u64,
    ) -> Option<String> {
        let module = self.module_record_for_handle(module_handle)?;
        Some(
            module
                .path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_else(|| module.name.clone()),
        )
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
            return Ok(Some(self.process_env.current_peb()));
        }
        self.ensure_process_space_initialized(process_handle)?;
        Ok(self
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
                self.modules.memory_mut().write(process_ids, &bytes)?;
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
        let pointer_size = self.arch.pointer_size;
        let required = modules.len() * pointer_size;
        if needed_ptr != 0 {
            self.write_u32(needed_ptr, required as u32)?;
        }
        if module_array != 0 && byte_capacity != 0 {
            let writable = required.min(byte_capacity) / pointer_size;
            let mut bytes = Vec::with_capacity(writable * pointer_size);
            for module in modules.iter().take(writable) {
                if self.arch.is_x86() {
                    bytes.extend_from_slice(&(module.base as u32).to_le_bytes());
                } else {
                    bytes.extend_from_slice(&module.base.to_le_bytes());
                }
            }
            if !bytes.is_empty() {
                self.modules.memory_mut().write(module_array, &bytes)?;
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
        if self.arch.is_x86() {
            if info_len < 12 {
                return Ok(0);
            }
            let mut bytes = [0u8; 12];
            bytes[0..4].copy_from_slice(&(module.base as u32).to_le_bytes());
            bytes[4..8].copy_from_slice(&(module.size as u32).to_le_bytes());
            bytes[8..12].copy_from_slice(&(module.entrypoint as u32).to_le_bytes());
            self.modules.memory_mut().write(info_ptr, &bytes)?;
        } else {
            if info_len < 24 {
                return Ok(0);
            }
            let mut bytes = [0u8; 24];
            bytes[0..8].copy_from_slice(&module.base.to_le_bytes());
            bytes[8..12].copy_from_slice(&(module.size as u32).to_le_bytes());
            bytes[16..24].copy_from_slice(&module.entrypoint.to_le_bytes());
            self.modules.memory_mut().write(info_ptr, &bytes)?;
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
        self.modules.memory_mut().write(counters_ptr, &bytes)?;
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
                let required = if self.arch.is_x64() { 48u32 } else { 24u32 };
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
                if self.arch.is_x64() {
                    bytes[8..16].copy_from_slice(&peb_base.to_le_bytes());
                    bytes[32..40].copy_from_slice(&(process.pid as u64).to_le_bytes());
                    bytes[40..48].copy_from_slice(&(process.parent_pid as u64).to_le_bytes());
                } else {
                    bytes[4..8].copy_from_slice(&(peb_base as u32).to_le_bytes());
                    bytes[16..20].copy_from_slice(&process.pid.to_le_bytes());
                    bytes[20..24].copy_from_slice(&process.parent_pid.to_le_bytes());
                }
                self.modules.memory_mut().write(info_ptr, &bytes)?;
                Ok(STATUS_SUCCESS as u64)
            }
            PROCESS_IMAGE_FILE_NAME_CLASS => {
                let path = process.display_path();
                let encoded = path
                    .encode_utf16()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>();
                let header_size = if self.arch.is_x64() { 16 } else { 8 };
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
                if self.arch.is_x64() {
                    self.modules
                        .memory_mut()
                        .write(info_ptr + 8, &buffer_ptr.to_le_bytes())?;
                } else {
                    self.write_u32(info_ptr + 4, buffer_ptr as u32)?;
                }
                self.modules.memory_mut().write(buffer_ptr, &encoded)?;
                self.modules
                    .memory_mut()
                    .write(buffer_ptr + encoded.len() as u64, &[0, 0])?;
                Ok(STATUS_SUCCESS as u64)
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
                    self.modules
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
        self.modules.memory_mut().write(info_ptr, &payload)?;
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
            self.modules
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
            self.modules.memory_mut().write(name_buffer, name_data)?;
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
