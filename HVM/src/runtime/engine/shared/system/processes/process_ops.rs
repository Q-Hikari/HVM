use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn is_current_process_handle(&self, handle: u64) -> bool {
        handle == 0
            || handle == self.current_process_id() as u64
            || (handle & 0xFFFF_FFFF) == PROCESS_HANDLE_PSEUDO
    }

    /// Returns `true` when `handle` refers to a synthetic process created
    /// on-the-fly by `OpenProcess` for a PID that is not in the environment
    /// profile process list.  Memory allocations and writes targeting such
    /// handles must be mirrored into the current process space so the
    /// remote thread can execute.
    pub(in crate::runtime::engine) fn is_synthetic_process_handle(&self, handle: u64) -> bool {
        if let Some(&pid) = self.process_memory.process_handles.get(&(handle as u32)) {
            self.process_memory
                .synthetic_process_identities
                .iter()
                .any(|p| p.pid == pid)
        } else {
            false
        }
    }

    pub(in crate::runtime::engine) fn module_record_for_handle(
        &self,
        module_handle: u64,
    ) -> Option<&ModuleRecord> {
        if module_handle == 0 {
            self.core.main_module.as_ref()
        } else {
            self.core.modules.get_by_base(module_handle)
        }
    }

    pub(in crate::runtime::engine) fn current_process_modules(&self) -> Vec<ModuleRecord> {
        let mut modules = self.core.modules.loaded_modules();
        if modules.is_empty() {
            return modules;
        }
        let process_image_base = self
            .core
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
        self.core.process_env.sync_modules(&modules)?;
        self.core
            .process_env
            .sync_current_thread_from_memory(self.core.modules.memory())?;
        self.core
            .process_env
            .materialize_into(self.core.modules.memory_mut())?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn module_process_attach_completed(
        &self,
        module: &ModuleRecord,
    ) -> bool {
        self.objects.attached_process_modules.contains(&module.base)
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
            self.core
                .config
                .unknown_api_policy
                .to_ascii_lowercase()
                .as_str(),
            "strict" | "error" | "fail"
        )
    }

    pub(in crate::runtime::engine) fn current_process_image_path(&self) -> String {
        if !self.core.environment_profile.machine.image_path.is_empty() {
            return self.core.environment_profile.machine.image_path.clone();
        }
        self.module_path_for_handle(0).unwrap_or_else(|| {
            self.core
                .config
                .process_image_path()
                .to_string_lossy()
                .to_string()
        })
    }

    pub(in crate::runtime::engine) fn build_parent_process_identity(
        &self,
    ) -> Option<SyntheticProcessIdentity> {
        let has_parent_override = self.core.config.parent_process_image.is_some()
            || self.core.config.parent_process_pid.is_some()
            || self.core.config.parent_process_command_line.is_some();
        let has_profile_parent = self.core.environment_profile.has_parent_process();
        if !has_parent_override && !has_profile_parent {
            return None;
        }

        let image_path = self
            .core
            .config
            .parent_process_image
            .as_ref()
            .map(|path| path.to_string_lossy().to_string())
            .filter(|path| !path.is_empty())
            .or_else(|| {
                (!self
                    .core
                    .environment_profile
                    .machine
                    .parent_image_path
                    .is_empty())
                .then_some(
                    self.core
                        .environment_profile
                        .machine
                        .parent_image_path
                        .clone(),
                )
            })
            .unwrap_or_default();
        let command_line = self
            .core
            .config
            .parent_process_command_line
            .clone()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                (!self
                    .core
                    .environment_profile
                    .machine
                    .parent_command_line
                    .is_empty())
                .then_some(
                    self.core
                        .environment_profile
                        .machine
                        .parent_command_line
                        .clone(),
                )
            })
            .unwrap_or_else(|| image_path.clone());

        Some(SyntheticProcessIdentity {
            pid: self.core.config.parent_process_pid.unwrap_or_else(|| {
                self.core
                    .environment_profile
                    .machine
                    .parent_process_id
                    .max(1)
            }),
            parent_pid: 0,
            image_path,
            command_line,
            current_directory: self
                .core
                .environment_profile
                .machine
                .current_directory
                .clone(),
        })
    }

    pub(in crate::runtime::engine) fn current_process_parent_id(&self) -> u32 {
        self.core
            .parent_process
            .as_ref()
            .map(|process| process.pid)
            .unwrap_or(0)
    }

    pub(in crate::runtime::engine) fn current_process_identity(&self) -> SyntheticProcessIdentity {
        SyntheticProcessIdentity {
            pid: self.current_process_id(),
            parent_pid: self.current_process_parent_id(),
            image_path: self.current_process_image_path(),
            command_line: self.core.command_line.clone(),
            current_directory: self.current_directory_display_text(),
        }
    }

    pub(in crate::runtime::engine) fn known_process_identities(
        &self,
    ) -> Vec<SyntheticProcessIdentity> {
        let mut processes = BTreeMap::new();
        for profile in &self.core.environment_profile.processes {
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
        if let Some(parent) = self.core.parent_process.clone() {
            processes.insert(parent.pid, parent);
        }
        let current = self.current_process_identity();
        processes.insert(current.pid, current);
        // Include synthetic process identities created by OpenProcess for
        // unknown PIDs so that VirtualAllocEx / WriteProcessMemory /
        // CreateRemoteThread can target them.
        for synthetic in &self.process_memory.synthetic_process_identities {
            processes
                .entry(synthetic.pid)
                .or_insert_with(|| synthetic.clone());
        }
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
        if let Some(&pid) = self.process_memory.process_handles.get(&(handle as u32)) {
            return self.process_identity_by_pid(pid);
        }
        let record = self.core.processes.find_process_by_handle(handle as u32)?;
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
        if let Some(&pid) = self.process_memory.process_handles.get(&(handle as u32)) {
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
        let record = self.core.processes.find_process_by_handle(handle as u32)?;
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
        let base = if self.core.arch.is_x86() {
            0x0040_0000
        } else {
            0x0000_0140_0000_0000
        };
        ModuleRecord {
            name,
            path: (!profile.identity.image_path.is_empty()).then_some(path),
            arch: self.core.arch.name.to_string(),
            is_dll: false,
            allow_execution: true,
            base,
            visible_base: base,
            size: 0x100000,
            entrypoint: base + 0x1000,
            image_base: base,
            time_date_stamp: 0,
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
            .process_memory
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
        let stack_size = self.core.modules.memory().layout().stack_size;
        let mut space = self
            .process_memory
            .process_spaces
            .remove(&process_key)
            .unwrap_or_else(|| {
                let mut space = SyntheticProcessSpace::new(self.core.arch);
                space.memory.set_stack_size(stack_size);
                space
            });

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

        space.process_env = WindowsProcessEnvironment::for_tests(self.core.arch);
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
        self.process_memory
            .process_spaces
            .insert(process_key, space);
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
            .values()
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
        _stack_top: u64,
    ) -> Result<u64, VmError> {
        let allocation_size = stack_base.saturating_sub(allocation_base);
        let register_fully_committed_stack = |engine: &mut Self| -> Result<u64, VmError> {
            engine.insert_virtual_allocation_record(
                process_handle,
                VirtualAllocationRecord {
                    allocation_base,
                    allocation_size,
                    allocation_protect: PAGE_READWRITE,
                    allocation_type: MEM_COMMIT | MEM_RESERVE,
                    region_type: MEM_PRIVATE,
                    segments: vec![VirtualAllocationSegment {
                        base: allocation_base,
                        size: allocation_size,
                        state: MEM_COMMIT,
                        protect: PAGE_READWRITE,
                    }],
                },
            )?;

            if engine.is_current_process_handle(process_handle) {
                engine.sync_current_process_native_page_protection(
                    allocation_base,
                    allocation_size,
                )?;
            }

            Ok(allocation_base)
        };

        // Use fully-committed stacks for all architectures.  The x86 guard-page
        // model (Windows) requires perfect tracking of which pages are actually
        // committed vs merely reserved, and a mismatch between `stack_limit` and
        // Unicorn page permissions causes unhandled read faults when the sample
        // accesses stack variables >0x10000 bytes above ESP (e.g. large local
        // arrays or alloca-style allocation in a deep call chain).
        register_fully_committed_stack(self)
    }

    pub(in crate::runtime::engine) fn expand_current_thread_stack_for_native_access(
        &mut self,
        address: u64,
        size: usize,
    ) -> Result<bool, VmError> {
        let Some(thread) = self.current_thread_snapshot() else {
            return Ok(false);
        };
        if thread.stack_base == 0 || thread.stack_limit == 0 {
            return Ok(false);
        }

        let access_size = size.max(1) as u64;
        let access_base = address & !(PAGE_SIZE - 1);
        let access_end = address.saturating_add(access_size);
        if access_base >= thread.stack_limit || access_end > thread.stack_base {
            return Ok(false);
        }

        let current_process = self.current_process_space_key();
        let Some(record) = self
            .virtual_allocation_record_for_process(current_process, access_base)
            .cloned()
        else {
            return Ok(false);
        };
        if record.end() != thread.stack_base || access_base <= record.allocation_base {
            return Ok(false);
        }

        let Some(region) = self.core.modules.memory().find_region(access_base, 1) else {
            return Ok(false);
        };
        if region.tag != "stack" {
            return Ok(false);
        }

        let current_stack_limit = thread.stack_limit & !(PAGE_SIZE - 1);
        if access_base >= current_stack_limit {
            return Ok(false);
        }

        let new_stack_limit = access_base;
        let Some(new_guard_base) = new_stack_limit.checked_sub(PAGE_SIZE) else {
            return Ok(false);
        };
        if new_guard_base < record.allocation_base {
            return Ok(false);
        }

        let expanded = self.with_process_memory_mut(current_process, |memory| {
            match memory.protect(
                new_stack_limit,
                current_stack_limit.saturating_sub(new_stack_limit),
                PROT_READ | PROT_WRITE,
            ) {
                Ok(()) => Ok(true),
                Err(crate::error::MemoryError::MissingRegion { .. }) => Ok(false),
                Err(error) => Err(VmError::from(error)),
            }
        })?;
        if expanded != Some(true) {
            return Ok(false);
        }

        let Some(record) =
            self.virtual_allocation_record_mut_for_process(current_process, access_base)
        else {
            return Ok(false);
        };
        if !record.replace_range(
            new_stack_limit,
            current_stack_limit.saturating_sub(new_stack_limit),
            MEM_COMMIT,
            PAGE_READWRITE,
        ) {
            return Ok(false);
        }
        if !record.replace_range(
            new_guard_base,
            PAGE_SIZE,
            MEM_COMMIT,
            PAGE_READWRITE | PAGE_GUARD,
        ) {
            return Ok(false);
        }

        let Some(tid) = self
            .core
            .scheduler
            .current_tid()
            .or(self.core.main_thread_tid)
        else {
            return Ok(false);
        };
        if self
            .core
            .scheduler
            .set_thread_stack_limit(tid, new_stack_limit)
            .is_none()
        {
            return Ok(false);
        }
        self.core
            .process_env
            .set_current_thread_stack_limit(new_stack_limit)
            .map_err(VmError::from)?;
        self.sync_current_process_native_page_protection(
            new_guard_base,
            thread.stack_base.saturating_sub(new_guard_base),
        )?;
        Ok(true)
    }

    pub(in crate::runtime::engine) fn unregister_process_virtual_allocation(
        &mut self,
        process_handle: u64,
        allocation_base: u64,
    ) {
        let _ = self.remove_virtual_allocation_record(process_handle, allocation_base);
    }

    pub(in crate::runtime::engine) fn release_terminated_thread_stack(
        &mut self,
        tid: u32,
    ) -> Result<(), VmError> {
        let Some(thread) = self.core.scheduler.thread_snapshot(tid) else {
            return Ok(());
        };
        if thread.stack_base == 0 {
            return Ok(());
        }

        let process_key = self.current_process_space_key();
        let Some((allocation_base, allocation_size)) = self
            .process_virtual_allocations(process_key)
            .and_then(|allocations| {
                allocations.iter().find_map(|(base, record)| {
                    if record.region_type != MEM_PRIVATE || record.end() != thread.stack_base {
                        return None;
                    }
                    let is_stack = self
                        .with_process_memory(process_key, |memory| {
                            memory
                                .find_region(*base, 1)
                                .map(|region| region.tag == "stack")
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);
                    is_stack.then_some((*base, record.allocation_size))
                })
            })
        else {
            return Ok(());
        };

        let _ = self.with_process_key_memory_mut(process_key, |memory| {
            match memory.unmap(allocation_base, allocation_size) {
                Ok(()) => Ok(()),
                Err(crate::error::MemoryError::MissingRegion { .. }) => Ok(()),
                Err(error) => Err(VmError::from(error)),
            }
        })?;
        self.unregister_process_virtual_allocation(process_key, allocation_base);

        if let Some(thread) = self.core.scheduler.thread_ref_mut(tid) {
            thread.stack_base = 0;
            thread.stack_limit = 0;
            thread.stack_top = 0;
        }
        Ok(())
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
        } else if let Some(&pid) = self.process_memory.process_handles.get(&(handle as u32)) {
            // Synthetic processes share the current process space so that
            // VirtualAllocEx/WriteProcessMemory operate directly on the
            // memory that the remote thread will execute in.
            if self
                .process_memory
                .synthetic_process_identities
                .iter()
                .any(|p| p.pid == pid)
            {
                Some(self.current_process_space_key())
            } else {
                Some(pid as u64)
            }
        } else if self
            .core
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
            Some(&self.process_memory.virtual_allocations)
        } else {
            self.process_memory
                .process_spaces
                .get(&process_key)
                .map(|space| &space.virtual_allocations)
        }
    }

    pub(in crate::runtime::engine) fn process_virtual_allocations_mut(
        &mut self,
        process_key: u64,
    ) -> Option<&mut BTreeMap<u64, VirtualAllocationRecord>> {
        if process_key == self.current_process_space_key() {
            Some(&mut self.process_memory.virtual_allocations)
        } else {
            self.process_memory
                .process_spaces
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
            return f(self.core.modules.memory_mut()).map(Some);
        }
        let arch = self.core.arch;
        let stack_size = self.core.modules.memory().layout().stack_size;
        let space = self
            .process_memory
            .process_spaces
            .entry(process_key)
            .or_insert_with(|| {
                let mut space = SyntheticProcessSpace::new(arch);
                space.memory.set_stack_size(stack_size);
                space
            });
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
            return f(self.core.modules.memory_mut()).map(Some);
        }
        self.process_memory
            .process_spaces
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
            Some(f(self.core.modules.memory()))
        } else if let Some(space) = self.process_memory.process_spaces.get(&process_key) {
            Some(f(&space.memory))
        } else {
            let empty = MemoryManager::for_arch(self.core.arch);
            Some(f(&empty))
        }
    }

    pub(in crate::runtime::engine) fn propagate_file_mapping_write(
        &mut self,
        process_handle: u64,
        address: u64,
        data: &[u8],
    ) -> Result<(), VmError> {
        self.core
            .runtime_profiler
            .add_counter("file_mapping.propagate_write.calls", 1);
        self.core
            .runtime_profiler
            .add_counter("file_mapping.propagate_write.bytes", data.len() as u64);
        let Some(process_key) = self.process_space_key_for_handle(process_handle) else {
            return Ok(());
        };
        let targets = {
            let _profile = self
                .core
                .runtime_profiler
                .start_scope("file_mapping.record_view_write");
            self.process_memory
                .file_mappings
                .record_view_write(process_key, address, data)
                .unwrap_or_default()
        };
        self.core
            .runtime_profiler
            .add_counter("file_mapping.propagate_write.targets", targets.len() as u64);
        if targets.is_empty() {
            self.core
                .runtime_profiler
                .add_counter("file_mapping.propagate_write.zero_target_calls", 1);
        }
        for MappingWriteTarget {
            process_key,
            address,
            source_offset,
            length,
        } in targets
        {
            self.core
                .runtime_profiler
                .add_counter("file_mapping.propagate_write.target_bytes", length as u64);
            let slice = &data[source_offset..source_offset + length];
            let _ = self.with_process_key_memory_mut(process_key, |memory| {
                memory.write(address, slice).map_err(VmError::from)
            })?;
        }
        Ok(())
    }
}
