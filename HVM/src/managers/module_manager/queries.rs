use super::*;

impl ModuleManager {
    pub(super) fn guest_visible_address_for_module(module: &ModuleRecord, address: u64) -> u64 {
        if module.visible_base == 0 || module.visible_base == module.base {
            return address;
        }
        if address < module.base || address >= module.base.saturating_add(module.size) {
            return address;
        }
        module.visible_base + (address - module.base)
    }

    pub(super) fn bind_real_export_address_variants(
        hooks: &mut HookRegistry,
        module_name: &str,
        function: &str,
        mapped_address: u64,
        visible_address: u64,
    ) {
        // The canonical guest-facing address is always the visible address.
        // Name-based lookups (binding_address, GetProcAddress) must return this.
        hooks.bind_real_export_canonical(module_name, function, visible_address);
        // The mapped (backing) address serves as an additional dispatch alias
        // so that execution at either mapped or visible address hits the same hook.
        if mapped_address != visible_address {
            hooks.bind_real_export_alias(module_name, function, mapped_address);
        }
    }

    pub(super) fn observe_real_export_address_variants(
        hooks: &mut HookRegistry,
        module_name: &str,
        function: &str,
        mapped_address: u64,
        visible_address: u64,
    ) {
        hooks.observe_real_export(module_name, function, visible_address);
        if mapped_address != visible_address {
            hooks.observe_real_export(module_name, function, mapped_address);
        }
    }

    pub(super) fn visible_alias_tag(module_name: &str, visible_base: u64) -> String {
        format!(
            "visible-image-alias:{}@{:016X}",
            module_name.to_ascii_lowercase(),
            visible_base
        )
    }

    pub(super) fn visible_alias_range(
        module: &ModuleRecord,
        visible_base: u64,
    ) -> Option<(u64, u64)> {
        if visible_base == 0 || visible_base == module.base {
            return None;
        }

        let aligned_base = visible_base & !(PAGE_SIZE - 1);
        let page_prefix = visible_base.saturating_sub(aligned_base);
        let aligned_size = align_up(page_prefix.saturating_add(module.size.max(1)), PAGE_SIZE);
        Some((aligned_base, aligned_size))
    }

    pub(super) fn remove_visible_alias_for_module(&mut self, module: &ModuleRecord) {
        let alias_tag = Self::visible_alias_tag(&module.name, module.visible_base);
        let regions = self
            .memory
            .regions
            .values()
            .filter(|region| region.tag == alias_tag)
            .map(|region| (region.base, region.size))
            .collect::<Vec<_>>();
        if regions.is_empty() {
            return;
        }
        for (base, size) in regions {
            let _ = self.memory.unmap(base, size);
        }
    }

    pub(super) fn install_visible_alias_for_module(
        &mut self,
        module: &ModuleRecord,
        visible_base: u64,
    ) -> bool {
        let Some((alias_base, alias_size)) = Self::visible_alias_range(module, visible_base) else {
            return true;
        };
        if !self.memory.is_free(alias_base, alias_size, false) {
            return false;
        }

        let image_end = module.base.saturating_add(module.size);
        let alias_tag = Self::visible_alias_tag(&module.name, visible_base);
        let mut page_perms = BTreeMap::<u64, u32>::new();
        let segments = self
            .memory
            .regions
            .values()
            .filter(|region| region.base < image_end && region.end() > module.base)
            .map(|region| {
                let region_start = region.base.max(module.base);
                let region_end = region.end().min(image_end);
                if region_start >= region_end {
                    return Some(None);
                }
                let offset = region_start.saturating_sub(module.base);
                let alias_region_base = visible_base.saturating_add(offset);
                let region_size = region_end.saturating_sub(region_start);
                let bytes = self.memory.read(region_start, region_size as usize).ok()?;
                let page_start = alias_region_base & !(PAGE_SIZE - 1);
                let page_end = align_up(alias_region_base.saturating_add(region_size), PAGE_SIZE);
                let mut page = page_start;
                while page < page_end {
                    *page_perms.entry(page).or_insert(0) |= region.perms;
                    page = page.saturating_add(PAGE_SIZE);
                }
                Some(Some((alias_region_base, bytes)))
            })
            .collect::<Option<Vec<_>>>();
        let Some(segments) = segments else {
            return false;
        };
        let segments = segments.into_iter().flatten().collect::<Vec<_>>();
        if segments.is_empty() || page_perms.is_empty() {
            return false;
        }

        let mut page_runs = Vec::new();
        let mut run_start = 0u64;
        let mut run_size = 0u64;
        let mut run_perms = 0u32;
        for (page_base, perms) in page_perms {
            if run_size == 0 {
                run_start = page_base;
                run_size = PAGE_SIZE;
                run_perms = perms;
                continue;
            }
            if page_base == run_start.saturating_add(run_size) && perms == run_perms {
                run_size = run_size.saturating_add(PAGE_SIZE);
                continue;
            }
            page_runs.push((run_start, run_size, run_perms));
            run_start = page_base;
            run_size = PAGE_SIZE;
            run_perms = perms;
        }
        if run_size != 0 {
            page_runs.push((run_start, run_size, run_perms));
        }

        let mut mapped_runs = Vec::new();
        for (run_base, run_size, run_perms) in page_runs {
            if self
                .memory
                .map_region(run_base, run_size, run_perms, &alias_tag)
                .is_err()
            {
                for (mapped_base, mapped_size) in mapped_runs {
                    let _ = self.memory.unmap(mapped_base, mapped_size);
                }
                return false;
            }
            mapped_runs.push((run_base, run_size));
        }

        for (alias_region_base, bytes) in segments {
            if self.memory.write(alias_region_base, &bytes).is_err() {
                for (mapped_base, mapped_size) in mapped_runs {
                    let _ = self.memory.unmap(mapped_base, mapped_size);
                }
                return false;
            }
        }

        // Re-relocate the visible alias so all absolute addresses inside it
        // point to the visible address space instead of the mapped space.
        Self::apply_visible_alias_relocations(module, visible_base, &mut self.memory);

        true
    }

    /// Applies a second round of PE relocations to a visible alias image so
    /// that all absolute addresses (JMP operands, IAT entries, pointers in
    /// .data/.rdata) point into the visible address space rather than the
    /// mapped address space.
    pub(super) fn apply_visible_alias_relocations(
        module: &ModuleRecord,
        visible_base: u64,
        memory: &mut MemoryManager,
    ) {
        if module.synthetic {
            return;
        }
        let Some(path) = module.path.as_ref() else {
            return;
        };
        let delta = visible_base as i128 - module.base as i128;
        if delta == 0 {
            return;
        }
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let Ok(pe) = PE::parse(&bytes) else {
            return;
        };
        let _ = apply_delta_relocations(&pe, visible_base, delta, memory);
    }

    /// Inserts into the sorted base_index, maintaining ascending order by base address.
    pub(super) fn insert_base_index(&mut self, base: u64, name: &str) {
        let idx = self.base_index.partition_point(|(b, _)| *b < base);
        self.base_index.insert(idx, (base, name.to_string()));
    }

    /// Builds a module manager for one target architecture.
    pub fn for_arch(arch: &'static ArchSpec) -> Self {
        Self {
            arch,
            memory: MemoryManager::for_arch(arch),
            loaded_by_name: HashMap::new(),
            alias_by_name: HashMap::new(),
            loaded_by_base: HashMap::new(),
            loaded_by_visible_base: HashMap::new(),
            load_order: Vec::new(),
            base_index: Vec::new(),
        }
    }

    /// Builds a test-only module manager with the default x86 memory layout.
    pub fn for_tests() -> Self {
        Self::for_arch(&X86_ARCH)
    }

    /// Exposes the current memory manager for test assertions.
    pub fn memory(&self) -> &MemoryManager {
        &self.memory
    }

    /// Exposes mutable memory-manager access for runtime stack and frame initialization.
    pub fn memory_mut(&mut self) -> &mut MemoryManager {
        &mut self.memory
    }

    /// Returns the architecture this manager should use for synthetic modules.
    pub fn arch(&self) -> &'static ArchSpec {
        self.arch
    }

    /// Returns one already loaded module by name using case-insensitive normalization rules.
    pub fn get_loaded(&self, name: &str) -> Option<&ModuleRecord> {
        let normalized_name = normalize_module_name(Path::new(name));
        self.loaded_by_name
            .get(&normalized_name)
            .or_else(|| {
                self.alias_by_name
                    .get(&normalized_name)
                    .and_then(|storage_name| self.loaded_by_name.get(storage_name))
            })
            .or_else(|| {
                let canonical_name = canonical_runtime_module_name(&normalized_name);
                (canonical_name != normalized_name)
                    .then_some(canonical_name)
                    .and_then(|canonical_name| {
                        self.loaded_by_name.get(&canonical_name).or_else(|| {
                            self.alias_by_name
                                .get(&canonical_name)
                                .and_then(|storage_name| self.loaded_by_name.get(storage_name))
                        })
                    })
            })
    }

    /// Returns one already loaded module by its mapped image base.
    pub fn get_by_base(&self, base: u64) -> Option<&ModuleRecord> {
        let name = self.loaded_by_base.get(&base)?;
        self.loaded_by_name.get(name)
    }

    /// Returns one loaded module by the base address exposed to the guest.
    pub fn get_by_visible_base(&self, visible_base: u64) -> Option<&ModuleRecord> {
        let name = self.loaded_by_visible_base.get(&visible_base)?;
        self.loaded_by_name.get(name)
    }

    /// Returns one loaded module by either its mapped base or guest-visible base.
    pub fn get_by_any_base(&self, base: u64) -> Option<&ModuleRecord> {
        self.get_by_base(base)
            .or_else(|| self.get_by_visible_base(base))
    }

    /// Returns one already loaded module that owns the requested virtual address.
    pub fn get_by_address(&self, address: u64) -> Option<&ModuleRecord> {
        let idx = self
            .base_index
            .partition_point(|(base, _)| *base <= address);
        if idx == 0 {
            return self.loaded_by_name.values().find(|module| {
                module.visible_base != module.base
                    && address >= module.visible_base
                    && address < module.visible_base.saturating_add(module.size)
            });
        }
        let (_, name) = &self.base_index[idx - 1];
        let module = self.loaded_by_name.get(name)?;
        if address < module.base + module.size {
            Some(module)
        } else {
            self.loaded_by_name.values().find(|module| {
                module.visible_base != module.base
                    && address >= module.visible_base
                    && address < module.visible_base.saturating_add(module.size)
            })
        }
    }

    /// Returns a snapshot of the currently loaded modules in load order.
    pub fn loaded_modules(&self) -> Vec<ModuleRecord> {
        self.load_order
            .iter()
            .filter_map(|name| self.loaded_by_name.get(name).cloned())
            .collect()
    }

    /// Returns the load-order module name list for batch iteration.
    pub fn module_names(&self) -> Vec<String> {
        self.load_order.clone()
    }

    /// Updates the base address exposed to the guest without changing the mapped image base.
    pub fn set_visible_base(&mut self, mapped_base: u64, visible_base: u64) -> bool {
        let Some(name) = self.loaded_by_base.get(&mapped_base).cloned() else {
            return false;
        };
        let Some(existing) = self.loaded_by_name.get(&name).cloned() else {
            return false;
        };
        if let Some(owner) = self.loaded_by_visible_base.get(&visible_base) {
            if owner != &name {
                return false;
            }
        }
        if existing.visible_base == visible_base {
            return true;
        }
        if visible_base != mapped_base
            && !self.install_visible_alias_for_module(&existing, visible_base)
        {
            return false;
        }
        // After the visible alias is created and re-relocated, restore the
        // benign JMP stub prologues that were corrupted by re-relocation.
        if visible_base != mapped_base {
            self.patch_visible_alias_jmp_stubs(&name);
        }
        self.remove_visible_alias_for_module(&existing);
        let Some(module) = self.loaded_by_name.get_mut(&name) else {
            return false;
        };
        if module.visible_base != 0 {
            self.loaded_by_visible_base.remove(&module.visible_base);
        }
        module.visible_base = visible_base;
        self.loaded_by_visible_base.insert(visible_base, name);
        true
    }

    /// Fixes import thunk values in the visible alias for one module.
    ///
    /// Import thunks are filled by the PE loader (not the linker), so they are
    /// not covered by the PE relocation table.  When the thunks were written,
    /// `module.visible_base` was still equal to `module.base`, so the resolved
    /// addresses are mapped-space values.  This function rewrites the visible
    /// alias copies of those thunks with the corresponding visible-space values.
    pub fn fixup_visible_alias_import_thunks(&mut self, module_name: &str, hooks: &HookRegistry) {
        let Some(module) = self.loaded_by_name.get(module_name) else {
            return;
        };
        if module.synthetic || module.visible_base == 0 || module.visible_base == module.base {
            return;
        }
        let mapped_base = module.base;
        let visible_base = module.visible_base;
        let module_end = mapped_base.saturating_add(module.size);
        // Collect thunks to fix (need to borrow hooks immutably while writing)
        let thunks: Vec<(u64, u64)> = hooks
            .import_bindings_by_thunk()
            .iter()
            // Only fix thunks that belong to this module's mapped range
            .filter(|(thunk, _)| **thunk >= mapped_base && **thunk < module_end)
            .map(|(thunk, binding)| {
                let visible_thunk = visible_base + (thunk - mapped_base);
                // Convert resolved address from mapped to visible space.
                // The resolved address may point into any module's mapped range,
                // so use get_by_any_base to find the owning module.
                let visible_resolved = self
                    .get_by_any_base(binding.resolved_address)
                    .map(|owner| {
                        if owner.visible_base != 0 && owner.visible_base != owner.base {
                            owner.visible_base + (binding.resolved_address - owner.base)
                        } else {
                            binding.resolved_address
                        }
                    })
                    .unwrap_or(binding.resolved_address);
                (visible_thunk, visible_resolved)
            })
            .collect();
        for (visible_thunk, visible_resolved) in thunks {
            let bytes = (visible_resolved as u32).to_le_bytes();
            let _ = self.memory.write(visible_thunk, &bytes);
        }
    }

    /// Mirrors one mapped-image write into the guest-visible alias when the
    /// module exposes a different base address to the guest.
    pub fn mirror_write_into_visible_alias(
        &mut self,
        mapped_address: u64,
        data: &[u8],
    ) -> Result<(), MemoryError> {
        if data.is_empty() {
            return Ok(());
        }
        let Some(module) = self.get_by_address(mapped_address).cloned() else {
            return Ok(());
        };
        if module.visible_base == 0 || module.visible_base == module.base {
            return Ok(());
        }
        if mapped_address < module.base || mapped_address >= module.base.saturating_add(module.size)
        {
            return Ok(());
        }
        let available = module
            .base
            .saturating_add(module.size)
            .saturating_sub(mapped_address);
        let len = data.len().min(available as usize);
        if len == 0 {
            return Ok(());
        }
        let visible_address = Self::guest_visible_address_for_module(&module, mapped_address);
        if visible_address == mapped_address
            || !self.memory.is_range_mapped(visible_address, len as u64)
        {
            return Ok(());
        }
        self.memory.write(visible_address, &data[..len])
    }

    pub fn mapped_base_for_any_base(&self, base: u64) -> Option<u64> {
        self.get_by_any_base(base).map(|module| module.base)
    }

    /// Inserts or replaces one module record to support integration tests for export resolution.
    pub fn insert_module_record_for_test(&mut self, mut module: ModuleRecord) {
        let normalized_name = normalize_module_name(Path::new(&module.name));
        module.name = normalized_name.clone();

        if let Some(existing) = self
            .loaded_by_name
            .insert(normalized_name.clone(), module.clone())
        {
            self.loaded_by_base.remove(&existing.base);
            self.loaded_by_visible_base.remove(&existing.visible_base);
            self.base_index.retain(|(base, _)| *base != existing.base);
        }
        self.insert_base_index(module.base, &normalized_name);
        self.loaded_by_base
            .insert(module.base, normalized_name.clone());
        self.loaded_by_visible_base
            .insert(module.visible_base, normalized_name.clone());
        if !self.load_order.iter().any(|name| name == &normalized_name) {
            self.load_order.push(normalized_name);
        }
    }

    /// Unloads one previously loaded module by its mapped image base.
    pub fn unload_module(&mut self, base: u64) -> bool {
        let Some(name) = self.loaded_by_base.remove(&base) else {
            return false;
        };
        if let Some(module) = self.loaded_by_name.get(&name).cloned() {
            self.remove_visible_alias_for_module(&module);
            let _ = self.memory.unmap(module.base, module.size);
            self.loaded_by_visible_base.remove(&module.visible_base);
        }
        self.load_order.retain(|loaded| loaded != &name);
        self.base_index.retain(|(b, _)| *b != base);
        self.alias_by_name
            .retain(|_, storage_name| storage_name != &name);
        self.loaded_by_name.remove(&name).is_some()
    }

    /// Marks one loaded module as initialized after its TLS callbacks / entrypoint run.
    pub fn mark_initialized(&mut self, base: u64) -> bool {
        let Some(name) = self.loaded_by_base.get(&base).cloned() else {
            return false;
        };
        let Some(module) = self.loaded_by_name.get_mut(&name) else {
            return false;
        };
        module.initialized = true;
        true
    }

    /// Loads a real PE module from disk and records it by name and base address.
    pub fn load_real_module(&mut self, path: PathBuf) -> Result<ModuleRecord, VmError> {
        let normalized_name = normalize_module_name(&path);
        if let Some(existing) = self.loaded_by_name.get(&normalized_name) {
            return Ok(existing.clone());
        }
        let module = map_image(&path, &mut self.memory)?;
        self.loaded_by_base
            .insert(module.base, normalized_name.clone());
        self.loaded_by_visible_base
            .insert(module.visible_base, normalized_name.clone());
        self.insert_base_index(module.base, &normalized_name);
        self.load_order.push(normalized_name.clone());
        self.loaded_by_name.insert(normalized_name, module.clone());
        Ok(module)
    }

    /// Resolves and loads one module name using the configured module-search paths.
    pub fn load_from_search_paths(
        &mut self,
        name_or_path: &str,
        search_paths: &[PathBuf],
    ) -> Result<ModuleRecord, VmError> {
        let path = resolve_module_path(name_or_path, search_paths)?;
        self.load_real_module(path)
    }

    /// Loads the main executable image and resolves its imports.
    pub fn load_runtime_main(
        &mut self,
        path: PathBuf,
        config: &EngineConfig,
        hooks: &mut HookRegistry,
    ) -> Result<ModuleRecord, VmError> {
        let module = self.load_real_module(path)?;
        self.resolve_imports_for_module(&module, config, hooks)?;
        Ok(module)
    }

    /// Loads one dependency module using the whitelist policy and resolves imports.
    pub fn load_runtime_dependency(
        &mut self,
        name_or_path: &str,
        config: &EngineConfig,
        hooks: &mut HookRegistry,
    ) -> Result<ModuleRecord, VmError> {
        let normalized_name = normalize_module_name(Path::new(name_or_path));
        let canonical_name = if should_canonicalize_runtime_request(name_or_path) {
            canonical_runtime_module_name(&normalized_name)
        } else {
            normalized_name.clone()
        };
        let prefer_synthetic_contract = contract_hook_family(&normalized_name)
            .or_else(|| contract_hook_family(&canonical_name))
            .is_some();
        if let Some(existing) = self.get_loaded(&normalized_name).cloned() {
            let storage_name = normalize_module_name(Path::new(&existing.name));
            self.register_runtime_aliases(&normalized_name, &canonical_name, &storage_name);
            return Ok(existing.clone());
        }

        let load_target = if canonical_name != normalized_name {
            canonical_name.as_str()
        } else {
            name_or_path
        };
        let resolution_paths = config.module_resolution_paths_for_arch(self.arch.name);
        let is_whitelisted =
            config.is_whitelisted(&normalized_name) || config.is_whitelisted(&canonical_name);
        let search_path_has_real_module =
            resolve_module_path(load_target, &resolution_paths).is_ok();

        if is_whitelisted {
            // --- Whitelist mode: full execution ---
            // Whitelisted modules (e.g. a legitimate EXE loading a malicious DLL)
            // get full execution: DllMain runs, code executes natively in Unicorn.
            // Only their external imports (kernel32, etc.) are intercepted by hooks.
            //
            // `load_target` may be a Windows path (e.g. F:\a\..\b.dll) that
            // resolve_module_path cannot find on Linux.  Fall back to the
            // normalized bare name (e.g. "b.dll") when the full path fails.
            let module = match self.load_from_search_paths(load_target, &resolution_paths) {
                Ok(module) => module,
                Err(_) => self.load_from_search_paths(&normalized_name, &resolution_paths)?,
            };
            // Normalize: module.name preserves filesystem casing (e.g. "KernelBase.dll")
            // but loaded_by_name keys are always lowercase (e.g. "kernelbase.dll").
            let storage_name = normalize_module_name(Path::new(&module.name));
            self.register_runtime_aliases(&normalized_name, &canonical_name, &storage_name);
            self.bind_all_real_exports(&storage_name, hooks);
            self.resolve_imports_for_module(&module, config, hooks)?;
            self.patch_forwarding_jmp_stubs(&storage_name);
            Ok(module)
        } else if prefer_synthetic_contract {
            // API-set contract DLLs in Windows snapshots are often tiny
            // re-export shells that forward back into host DLLs or other
            // contract DLLs. Treat manually supported contract families as
            // synthetic identities so forward chains terminate at the
            // registry-backed hook space instead of looping through re-export
            // shims on disk.
            let anticipated_exports = hooks.functions_for_module(&canonical_name).len();
            let module = self.load_synthetic_module(&canonical_name, anticipated_exports)?;
            let storage_name = normalize_module_name(Path::new(&module.name));
            self.register_runtime_aliases(&normalized_name, &canonical_name, &storage_name);
            self.populate_synthetic_module_exports(module.base, hooks)?;
            Ok(self.get_by_base(module.base).cloned().unwrap_or(module))
        } else if search_path_has_real_module {
            // --- Memory-only mode: real DLL bytes readable, no execution ---
            // Non-whitelisted real DLLs (e.g. system DLLs like kernel32) are mapped
            // into memory so that malware reading their prologues sees normal,
            // unhooked code (anti-hook detection bypass).  However the native code
            // must NOT execute — instead the hook system intercepts all API calls.
            let module = self.load_from_search_paths(load_target, &resolution_paths)?;
            // Normalize: module.name preserves filesystem casing (e.g. "KernelBase.dll")
            // but loaded_by_name keys are always lowercase (e.g. "kernelbase.dll").
            let storage_name = normalize_module_name(Path::new(&module.name));
            self.register_runtime_aliases(&normalized_name, &canonical_name, &storage_name);
            // DllMain / TLS callbacks cannot run inside the sandbox; clear them.
            if let Some(loaded) = self.loaded_by_name.get_mut(&storage_name) {
                loaded.allow_execution = false;
                loaded.entrypoint = 0;
                loaded.tls_callbacks.clear();
            }
            self.strip_execute_from_image(module.base, module.size);
            // Register ALL real export addresses with the hook system so that
            // malware resolving functions by manually walking the PE export
            // table (hash-based API resolution, etc.) will also be intercepted.
            self.bind_all_real_exports(&storage_name, hooks);
            self.resolve_imports_for_module(&module, config, hooks)?;
            // After imports are resolved, patch JMP forwarding stubs so
            // malware cannot follow them to discover underlying DLL addresses.
            self.patch_forwarding_jmp_stubs(&storage_name);
            Ok(self.get_loaded(&storage_name).cloned().unwrap_or(module))
        } else if config.modules_always_exist() {
            let anticipated_exports = hooks.functions_for_module(&canonical_name).len();
            let module = self.load_synthetic_module(&canonical_name, anticipated_exports)?;
            let storage_name = normalize_module_name(Path::new(&module.name));
            self.register_runtime_aliases(&normalized_name, &canonical_name, &storage_name);
            self.populate_synthetic_module_exports(module.base, hooks)?;
            Ok(self.get_by_base(module.base).cloned().unwrap_or(module))
        } else {
            Err(VmError::ModuleNotFound(load_target.to_string()))
        }
    }

    /// Re-binds all real exports for every loaded module.  Call this after
    /// `set_visible_base` / `refresh_all_visible_bases` so the hook registry
    /// learns the new visible-base address variants.
    pub fn rebind_all_real_exports(&self, hooks: &mut HookRegistry) {
        for name in &self.load_order {
            self.bind_all_real_exports(name, hooks);
        }
    }

    /// Registers every real export address of the named module with the hook
    /// dispatcher.  This ensures that malware which resolves functions by
    /// manually walking the PE export table (rather than through the IAT) is
    /// still intercepted.
    pub(super) fn bind_all_real_exports(&self, module_name: &str, hooks: &mut HookRegistry) {
        let Some(module) = self.loaded_by_name.get(module_name) else {
            return;
        };
        if module.synthetic {
            return;
        }
        // Non-executable real modules must dispatch through hooks when their
        // exports are reached. Executable real modules should only be observed
        // so their native code can continue running.
        let mut name_bound_addresses = std::collections::HashSet::new();
        for (func_name, &address) in &module.exports_by_name {
            let visible_address = Self::guest_visible_address_for_module(module, address);
            if module.allow_execution {
                Self::observe_real_export_address_variants(
                    hooks,
                    module_name,
                    func_name,
                    address,
                    visible_address,
                );
            } else {
                Self::bind_real_export_address_variants(
                    hooks,
                    module_name,
                    func_name,
                    address,
                    visible_address,
                );
            }
            name_bound_addresses.insert(address);
            name_bound_addresses.insert(visible_address);
        }
        for (&ordinal, &address) in &module.exports_by_ordinal {
            // Skip ordinal bindings at addresses already bound by name —
            // hook signatures are keyed by function name, not ordinal string.
            if name_bound_addresses.contains(&address) {
                continue;
            }
            let visible_address = Self::guest_visible_address_for_module(module, address);
            if name_bound_addresses.contains(&visible_address) {
                continue;
            }
            if module.allow_execution {
                Self::observe_real_export_address_variants(
                    hooks,
                    module_name,
                    &format!("ordinal_{ordinal}"),
                    address,
                    visible_address,
                );
            } else {
                Self::bind_real_export_address_variants(
                    hooks,
                    module_name,
                    &format!("ordinal_{ordinal}"),
                    address,
                    visible_address,
                );
            }
        }
    }

    /// Strips EXECUTE permission from every memory region within a loaded
    /// image.  After `finalize_image_protections` the image is split into
    /// per-section sub-regions so we cannot `protect(base, size)` in one
    /// shot.  Instead we iterate the region list and clear EXECUTE from
    /// each region that falls inside the image address range.
    pub(super) fn strip_execute_from_image(&mut self, base: u64, size: u64) {
        use crate::memory::manager::PROT_EXEC;
        let end = base + size;
        let updates: Vec<(u64, u64, u32)> = self
            .memory
            .regions
            .values()
            .filter(|r| r.base >= base && r.base < end)
            .filter(|r| r.perms & PROT_EXEC != 0)
            .map(|r| (r.base, r.size, r.perms & !PROT_EXEC))
            .collect();
        for (rbase, rsize, new_perms) in updates {
            if let Err(e) = self.memory.protect(rbase, rsize, new_perms) {
                eprintln!("[WARN] strip_execute: protect(0x{rbase:X}, 0x{rsize:X}) failed: {e}");
            }
        }
    }

    /// Patches JMP forwarding stubs in a real module's mapped memory.
    ///
    /// Many system DLL exports (notably kernel32.dll) are thin JMP stubs that
    /// redirect to kernelbase.dll through IAT entries (e.g., `FF 25 [iat_addr]`).
    /// Malware samples read the code at GetProcAddress return values, detect
    /// these JMP patterns, and follow them to discover the underlying DLL
    /// addresses — then use those addresses instead of the GetProcAddress results.
    /// This breaks anti-hook / anti-analysis checks and causes address-space
    /// mismatches in resolver chains.
    ///
    /// This function replaces those JMP stub bytes with a benign function
    /// prologue so that the sample sees normal code and accepts the address
    /// returned by GetProcAddress.
    pub(super) fn patch_forwarding_jmp_stubs(&mut self, module_name: &str) {
        let addresses: Vec<u64> = {
            let Some(module) = self.loaded_by_name.get(module_name) else {
                return;
            };
            if module.synthetic {
                return;
            }
            module
                .exports_by_name
                .values()
                .chain(module.exports_by_ordinal.values())
                .copied()
                .collect()
        };
        for address in addresses {
            self.patch_single_jmp_stub(address);
        }
    }

    /// Returns 1 if a JMP stub was patched at `address`, 0 otherwise.
    ///
    /// For `FF 25 [addr]` (indirect JMP), the stub redirects through an IAT
    /// slot.  We must also neutralize the IAT entry so malware cannot follow
    /// the forwarding chain by reading the IAT directly.  The IAT value is
    /// overwritten with the export's own address so the forwarding chain
    /// self-references instead of pointing into the underlying DLL.
    pub(super) fn patch_single_jmp_stub(&mut self, address: u64) -> u32 {
        if let Ok(code) = self.memory.read(address, 6) {
            match code[0] {
                0xFF if code.len() >= 2 && code[1] == 0x25 => {
                    // FF 25 xx xx xx xx = JMP DWORD PTR [addr]
                    let iat_addr = u32::from_le_bytes([code[2], code[3], code[4], code[5]]) as u64;
                    // Patch the IAT entry to point back to this export's own address.
                    // This prevents malware from reading the IAT to discover the
                    // underlying DLL (e.g., kernelbase) addresses.
                    let iat_val = (address as u32).to_le_bytes();
                    let _ = self.memory.write(iat_addr, &iat_val);
                    // Now replace the JMP stub bytes with a benign prologue.
                    let safe: [u8; 6] = [0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x5D];
                    let _ = self.memory.write(address, &safe);
                    1
                }
                0xE9 => {
                    // E9 xx xx xx xx = JMP rel32
                    let safe: [u8; 5] = [0x8B, 0xFF, 0x55, 0x8B, 0xEC];
                    let _ = self.memory.write(address, &safe);
                    1
                }
                _ => 0,
            }
        } else {
            0
        }
    }

    /// Re-patches JMP forwarding stubs in the visible alias after it has been
    /// re-relocated.  The re-relocation adjusts absolute addresses (IAT entries,
    /// JMP operands) to point into the visible address space, but it corrupts
    /// the benign prologue bytes that `patch_forwarding_jmp_stubs` previously
    /// wrote over the original JMP stubs.  This function restores those benign
    /// prologues in the visible alias.
    ///
    /// Unlike `patch_single_jmp_stub`, this does NOT patch the IAT — the
    /// re-relocation has already adjusted the IAT values to visible addresses,
    /// and the original `patch_single_jmp_stub` has already set them to
    /// self-reference the mapped address.  After re-relocation, the IAT values
    /// become visible addresses (correct outcome).
    pub(super) fn patch_visible_alias_jmp_stubs(&mut self, module_name: &str) {
        let Some(module) = self.loaded_by_name.get(module_name) else {
            return;
        };
        if module.synthetic || module.visible_base == 0 || module.visible_base == module.base {
            return;
        }
        let safe_prologue: [u8; 6] = [0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x5D];
        let addresses: Vec<u64> = module
            .exports_by_name
            .values()
            .chain(module.exports_by_ordinal.values())
            .copied()
            .collect();
        for mapped_address in addresses {
            let visible_address = Self::guest_visible_address_for_module(module, mapped_address);
            if visible_address == mapped_address {
                continue;
            }
            // Overwrite with benign prologue regardless of current content.
            // The re-relocation may have corrupted whatever was there, so we
            // unconditionally restore the safe bytes.
            let _ = self.memory.write(visible_address, &safe_prologue);
        }
    }

    /// Resolves one export by name or ordinal.
    pub fn resolve_export(
        &mut self,
        module_base: u64,
        config: &EngineConfig,
        hooks: &mut HookRegistry,
        name: Option<&str>,
        ordinal: Option<u16>,
    ) -> u64 {
        self.resolve_export_with_depth(module_base, config, hooks, name, ordinal, 0)
    }
}
