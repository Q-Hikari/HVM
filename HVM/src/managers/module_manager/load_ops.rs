use super::*;

impl ModuleManager {
    pub(super) fn load_synthetic_module(
        &mut self,
        module_name: &str,
        anticipated_exports: usize,
    ) -> Result<ModuleRecord, VmError> {
        let normalized_name = normalize_module_name(Path::new(module_name));
        if let Some(existing) = self.loaded_by_name.get(&normalized_name) {
            return Ok(existing.clone());
        }

        let size = synthetic_module_reserve_size(anticipated_exports);
        let base =
            self.memory
                .reserve(size, None, &format!("synthetic:{normalized_name}"), true)?;
        let module = ModuleRecord {
            name: normalized_name.clone(),
            path: None,
            arch: self.arch.name.to_string(),
            is_dll: true,
            allow_execution: true,
            base,
            visible_base: base,
            size,
            entrypoint: base + SYNTHETIC_TEXT_RVA,
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
            stub_cursor: SYNTHETIC_STUB_RVA_START,
        };
        initialize_synthetic_module_image(&module, &mut self.memory);
        self.loaded_by_base.insert(base, normalized_name.clone());
        self.loaded_by_visible_base
            .insert(module.visible_base, normalized_name.clone());
        self.insert_base_index(base, &normalized_name);
        self.load_order.push(normalized_name.clone());
        self.loaded_by_name
            .insert(normalized_name.clone(), module.clone());
        Ok(module)
    }

    pub(super) fn populate_synthetic_module_exports(
        &mut self,
        module_base: u64,
        hooks: &mut HookRegistry,
    ) -> Result<(), VmError> {
        let Some(module_name) = self.loaded_by_base.get(&module_base).cloned() else {
            return Ok(());
        };
        let functions = hooks.functions_for_module(&module_name);
        if functions.is_empty() {
            return Ok(());
        }
        let (memory, loaded_by_name) = (&mut self.memory, &mut self.loaded_by_name);
        let Some(module) = loaded_by_name.get_mut(&module_name) else {
            return Ok(());
        };
        if !module.synthetic {
            return Ok(());
        }
        for function in functions {
            hooks.bind_module_stub(module, function, None, memory);
        }
        Ok(())
    }

    pub(super) fn register_runtime_aliases(
        &mut self,
        requested_name: &str,
        canonical_name: &str,
        storage_name: &str,
    ) {
        self.register_loaded_alias(requested_name, storage_name);
        self.register_loaded_alias(canonical_name, storage_name);
    }

    pub(super) fn register_loaded_alias(&mut self, alias_name: &str, storage_name: &str) {
        let normalized_alias = normalize_module_name(Path::new(alias_name));
        let normalized_storage = normalize_module_name(Path::new(storage_name));
        if normalized_alias == normalized_storage {
            return;
        }
        self.alias_by_name
            .insert(normalized_alias, normalized_storage);
    }

    /// Binds hook definitions to real export addresses for a PE loaded from disk.
    /// This allows the engine to intercept calls at real function entry points instead
    /// of synthetic stubs, which makes prologue-byte integrity checks pass.
    #[allow(dead_code)]
    pub(super) fn bind_hooks_to_real_exports(
        &mut self,
        module_name: &str,
        hooks: &mut HookRegistry,
    ) {
        let functions = hooks.functions_for_module(module_name);
        if functions.is_empty() {
            return;
        }
        let Some(module) = self.loaded_by_name.get(module_name) else {
            return;
        };
        if module.synthetic {
            return;
        }
        let bindings: Vec<(&str, u64)> = functions
            .iter()
            .filter_map(|&function| {
                let key = function.to_ascii_lowercase();
                module
                    .exports_by_name
                    .get(&key)
                    .map(|addr| (function, *addr))
            })
            .collect();
        for (function, address) in bindings {
            let visible_address = Self::guest_visible_address_for_module(module, address);
            if module.allow_execution {
                Self::observe_real_export_address_variants(
                    hooks,
                    module_name,
                    function,
                    address,
                    visible_address,
                );
            } else {
                Self::bind_real_export_address_variants(
                    hooks,
                    module_name,
                    function,
                    address,
                    visible_address,
                );
            }
        }
    }

    pub(super) fn resolve_imports_for_module(
        &mut self,
        module: &ModuleRecord,
        config: &EngineConfig,
        hooks: &mut HookRegistry,
    ) -> Result<(), VmError> {
        if module.synthetic {
            return Ok(());
        }
        let path = module
            .path
            .as_ref()
            .ok_or_else(|| VmError::ModuleNotFound(module.name.clone()))?;
        let bytes = fs::read(path).map_err(|source| VmError::ReadFile {
            path: path.clone(),
            source,
        })?;
        let pe = PE::parse(&bytes).map_err(|source| VmError::ParsePe {
            path: path.clone(),
            source,
        })?;

        for import in collect_import_bindings(&pe) {
            let dependency = self.load_runtime_dependency(&import.dll, config, hooks)?;
            let thunk = module.base + import.offset;
            let resolved_binding = if import.by_ordinal {
                self.resolve_export_binding_with_depth(
                    dependency.base,
                    &import.dll,
                    &import.function,
                    config,
                    hooks,
                    None,
                    Some(import.ordinal),
                    0,
                )
            } else {
                self.resolve_export_binding_with_depth(
                    dependency.base,
                    &import.dll,
                    &import.function,
                    config,
                    hooks,
                    Some(&import.function),
                    None,
                    0,
                )
            };
            let resolved = resolved_binding
                .as_ref()
                .map(|binding| binding.resolved_address)
                .unwrap_or(0);
            self.write_pointer(thunk, resolved, import.size)?;
            if let Some(binding) = resolved_binding {
                hooks.record_import_binding(
                    thunk,
                    &module.name,
                    &binding.requested_module,
                    &binding.requested_function,
                    &binding.resolved_module,
                    &binding.resolved_function,
                    binding.resolved_address,
                );
            }
        }

        Ok(())
    }

    pub(super) fn write_pointer(
        &mut self,
        address: u64,
        value: u64,
        size: usize,
    ) -> Result<(), VmError> {
        let bytes = match size {
            0..=4 => (value as u32).to_le_bytes()[..size.max(4).min(4)].to_vec(),
            8 => value.to_le_bytes().to_vec(),
            _ => value.to_le_bytes()[..8].to_vec(),
        };
        self.memory.write(address, &bytes).map_err(VmError::from)
    }

    pub(super) fn resolve_export_with_depth(
        &mut self,
        module_base: u64,
        config: &EngineConfig,
        hooks: &mut HookRegistry,
        name: Option<&str>,
        ordinal: Option<u16>,
        depth: usize,
    ) -> u64 {
        let requested_module = self
            .get_by_any_base(module_base)
            .map(|module| module.name.clone())
            .unwrap_or_default();
        let requested_function = match (name, ordinal) {
            (Some(name), _) => name.to_string(),
            (None, Some(ordinal)) => format!("ordinal_{ordinal}"),
            (None, None) => return 0,
        };
        self.resolve_export_binding_with_depth(
            module_base,
            &requested_module,
            &requested_function,
            config,
            hooks,
            name,
            ordinal,
            depth,
        )
        .map(|binding| binding.resolved_address)
        .unwrap_or(0)
    }

    pub(super) fn resolve_export_binding_with_depth(
        &mut self,
        module_base: u64,
        requested_module: &str,
        requested_function: &str,
        config: &EngineConfig,
        hooks: &mut HookRegistry,
        name: Option<&str>,
        ordinal: Option<u16>,
        depth: usize,
    ) -> Option<ResolvedExportBinding> {
        if depth >= MAX_FORWARD_EXPORT_DEPTH {
            return None;
        }

        let mapped_base = self.mapped_base_for_any_base(module_base)?;
        let module_name = self.loaded_by_base.get(&mapped_base)?.clone();
        enum ExportResolution {
            Address {
                address: u64,
                resolved_function: String,
            },
            Forward(ForwardedExportTarget),
            SyntheticName(String),
            SyntheticOrdinal(u16),
            ExternalSyntheticName(String),
            ExternalSyntheticOrdinal(u16),
            Missing,
        }

        let resolution = {
            let module = self.loaded_by_name.get(&module_name)?;

            if let Some(name) = name {
                let normalized_name = name.to_ascii_lowercase();
                if let Some(address) = module.exports_by_name.get(&normalized_name) {
                    let visible_address = Self::guest_visible_address_for_module(module, *address);
                    if module.allow_execution && !module.synthetic {
                        Self::observe_real_export_address_variants(
                            hooks,
                            &module_name,
                            &normalized_name,
                            *address,
                            visible_address,
                        );
                    } else {
                        Self::bind_real_export_address_variants(
                            hooks,
                            &module_name,
                            &normalized_name,
                            *address,
                            visible_address,
                        );
                    }
                    let resolved_function = module
                        .export_name_text_by_key
                        .get(&normalized_name)
                        .cloned()
                        .unwrap_or(normalized_name);
                    ExportResolution::Address {
                        address: visible_address,
                        resolved_function,
                    }
                } else if let Some(target) = module.forwarded_exports_by_name.get(&normalized_name)
                {
                    ExportResolution::Forward(target.clone())
                } else if module.synthetic
                    && (hooks.has_signature_for(&module_name, &normalized_name)
                        || config.functions_always_exist())
                {
                    ExportResolution::SyntheticName(normalized_name)
                } else if hooks.has_signature_for(&module_name, &normalized_name)
                    || config.functions_always_exist()
                {
                    ExportResolution::ExternalSyntheticName(normalized_name)
                } else {
                    ExportResolution::Missing
                }
            } else if let Some(ordinal) = ordinal {
                let ordinal_key = format!("ordinal_{ordinal}");
                if let Some(address) = module.exports_by_ordinal.get(&ordinal) {
                    let visible_address = Self::guest_visible_address_for_module(module, *address);
                    if module.allow_execution && !module.synthetic {
                        Self::observe_real_export_address_variants(
                            hooks,
                            &module_name,
                            &ordinal_key,
                            *address,
                            visible_address,
                        );
                    } else {
                        Self::bind_real_export_address_variants(
                            hooks,
                            &module_name,
                            &ordinal_key,
                            *address,
                            visible_address,
                        );
                    }
                    ExportResolution::Address {
                        address: visible_address,
                        resolved_function: ordinal_key,
                    }
                } else if let Some(target) = module.forwarded_exports_by_ordinal.get(&ordinal) {
                    ExportResolution::Forward(target.clone())
                } else if module.synthetic
                    && (hooks.has_signature_for(&module_name, &ordinal_key)
                        || config.functions_always_exist())
                {
                    ExportResolution::SyntheticOrdinal(ordinal)
                } else if hooks.has_signature_for(&module_name, &ordinal_key)
                    || config.functions_always_exist()
                {
                    ExportResolution::ExternalSyntheticOrdinal(ordinal)
                } else {
                    ExportResolution::Missing
                }
            } else {
                ExportResolution::Missing
            }
        };

        match resolution {
            ExportResolution::Address {
                address,
                resolved_function,
            } => Some(ResolvedExportBinding {
                requested_module: requested_module.to_string(),
                requested_function: requested_function.to_string(),
                resolved_module: module_name,
                resolved_function,
                resolved_address: address,
            }),
            ExportResolution::Forward(target) => self.resolve_forwarded_export_binding_target(
                requested_module,
                requested_function,
                config,
                hooks,
                target,
                depth + 1,
            ),
            ExportResolution::SyntheticName(name) => {
                let (memory, loaded_by_name) = (&mut self.memory, &mut self.loaded_by_name);
                let module = loaded_by_name.get_mut(&module_name)?;
                let address = hooks.bind_module_stub(module, &name, None, memory);
                let visible_address = Self::guest_visible_address_for_module(module, address);
                // bind_module_stub writes the stub (mapped) address to bindings_by_name.
                // Overwrite with the canonical guest-visible address so that name-based
                // lookups always return the guest-facing address.
                if visible_address != address {
                    hooks.bind_real_export_canonical(&module_name, &name, visible_address);
                }
                Some(ResolvedExportBinding {
                    requested_module: requested_module.to_string(),
                    requested_function: requested_function.to_string(),
                    resolved_module: module_name,
                    resolved_function: name,
                    resolved_address: visible_address,
                })
            }
            ExportResolution::SyntheticOrdinal(ordinal) => {
                let (memory, loaded_by_name) = (&mut self.memory, &mut self.loaded_by_name);
                let module = loaded_by_name.get_mut(&module_name)?;
                let resolved_function = format!("ordinal_{ordinal}");
                let address =
                    hooks.bind_module_stub(module, &resolved_function, Some(ordinal), memory);
                let visible_address = Self::guest_visible_address_for_module(module, address);
                if visible_address != address {
                    hooks.bind_real_export_canonical(
                        &module_name,
                        &resolved_function,
                        visible_address,
                    );
                }
                Some(ResolvedExportBinding {
                    requested_module: requested_module.to_string(),
                    requested_function: requested_function.to_string(),
                    resolved_module: module_name,
                    resolved_function,
                    resolved_address: visible_address,
                })
            }
            ExportResolution::ExternalSyntheticName(name) => {
                // External stubs are allocated from a global counter (not
                // module-relative), so guest_visible_address_for_module is
                // a no-op for them.  Still, register both the stub address
                // and the module-aware visible variant so that dispatch
                // works regardless of which address the guest uses.
                let stub_address = hooks.bind_stub(&module_name, &name);
                // bind_stub writes the global-counter stub address to bindings_by_name.
                // For external stubs guest_visible_address_for_module is normally a
                // no-op (stub lies outside the module range), but if the stub happens
                // to land inside a relocated module's range, overwrite the canonical
                // name mapping so GetProcAddress returns the guest-facing address.
                let module = self.loaded_by_name.get(&module_name);
                let visible_address = module
                    .map(|m| Self::guest_visible_address_for_module(m, stub_address))
                    .unwrap_or(stub_address);
                if visible_address != stub_address {
                    hooks.bind_real_export_canonical(&module_name, &name, visible_address);
                }
                Some(ResolvedExportBinding {
                    requested_module: requested_module.to_string(),
                    requested_function: requested_function.to_string(),
                    resolved_module: module_name,
                    resolved_function: name,
                    resolved_address: visible_address,
                })
            }
            ExportResolution::ExternalSyntheticOrdinal(ordinal) => {
                let resolved_function = format!("ordinal_{ordinal}");
                let stub_address = hooks.bind_stub(&module_name, &resolved_function);
                let module = self.loaded_by_name.get(&module_name);
                let visible_address = module
                    .map(|m| Self::guest_visible_address_for_module(m, stub_address))
                    .unwrap_or(stub_address);
                if visible_address != stub_address {
                    hooks.bind_real_export_canonical(
                        &module_name,
                        &resolved_function,
                        visible_address,
                    );
                }
                Some(ResolvedExportBinding {
                    requested_module: requested_module.to_string(),
                    requested_function: requested_function.to_string(),
                    resolved_module: module_name,
                    resolved_function,
                    resolved_address: visible_address,
                })
            }
            ExportResolution::Missing => None,
        }
    }

    pub(super) fn resolve_forwarded_export_binding_target(
        &mut self,
        requested_module: &str,
        requested_function: &str,
        config: &EngineConfig,
        hooks: &mut HookRegistry,
        target: ForwardedExportTarget,
        depth: usize,
    ) -> Option<ResolvedExportBinding> {
        // Use visible_base (guest-facing base) for the recursive lookup so
        // that the guest-visible address semantics are preserved throughout
        // the forwarding chain.  Fall back to mapped base when no module is
        // found by visible_base.
        let dep_module = match &target {
            ForwardedExportTarget::ByName { module, .. }
            | ForwardedExportTarget::ByOrdinal { module, .. } => {
                self.load_runtime_dependency(module, config, hooks).ok()?
            }
        };
        let dep_base = if dep_module.visible_base != 0 {
            dep_module.visible_base
        } else {
            dep_module.base
        };

        match target {
            ForwardedExportTarget::ByName { function, .. } => self
                .resolve_export_binding_with_depth(
                    dep_base,
                    requested_module,
                    requested_function,
                    config,
                    hooks,
                    Some(&function),
                    None,
                    depth,
                ),
            ForwardedExportTarget::ByOrdinal { ordinal, .. } => self
                .resolve_export_binding_with_depth(
                    dep_base,
                    requested_module,
                    requested_function,
                    config,
                    hooks,
                    None,
                    Some(ordinal),
                    depth,
                ),
        }
    }
}
