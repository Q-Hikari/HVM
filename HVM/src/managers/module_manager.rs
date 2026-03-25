use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use goblin::pe::PE;

use crate::arch::{ArchSpec, X86_ARCH};
use crate::config::EngineConfig;
use crate::error::VmError;
use crate::hooks::registry::{
    initialize_synthetic_module_image, HookRegistry, SYNTHETIC_STUB_RVA_START, SYNTHETIC_TEXT_RVA,
};
use crate::memory::manager::MemoryManager;
use crate::models::{ForwardedExportTarget, ModuleRecord};
use crate::pe::imports::collect_import_bindings;
use crate::pe::loader::map_image;

const MAX_FORWARD_EXPORT_DEPTH: usize = 8;
const SNAPSHOT_SEARCH_SUFFIXES: &[&str] = &[
    "",
    "System32",
    "SysWOW64",
    "Windows",
    "Windows/System32",
    "Windows/SysWOW64",
    "dlls",
    "dlls/System32",
    "dlls/SysWOW64",
];

/// Owns loaded module records and the memory manager that backs them.
#[derive(Debug)]
pub struct ModuleManager {
    arch: &'static ArchSpec,
    memory: MemoryManager,
    loaded_by_name: BTreeMap<String, ModuleRecord>,
    loaded_by_base: BTreeMap<u64, String>,
    load_order: Vec<String>,
}

impl ModuleManager {
    /// Builds a module manager for one target architecture.
    pub fn for_arch(arch: &'static ArchSpec) -> Self {
        Self {
            arch,
            memory: MemoryManager::for_arch(arch),
            loaded_by_name: BTreeMap::new(),
            loaded_by_base: BTreeMap::new(),
            load_order: Vec::new(),
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

    /// Returns one already loaded module by name using the Python-compatible normalization rules.
    pub fn get_loaded(&self, name: &str) -> Option<&ModuleRecord> {
        let normalized_name = normalize_module_name(Path::new(name));
        self.loaded_by_name.get(&normalized_name).or_else(|| {
            let canonical_name = canonical_runtime_module_name(&normalized_name);
            (canonical_name != normalized_name)
                .then_some(canonical_name)
                .and_then(|name| self.loaded_by_name.get(&name))
        })
    }

    /// Returns one already loaded module by its mapped image base.
    pub fn get_by_base(&self, base: u64) -> Option<&ModuleRecord> {
        let name = self.loaded_by_base.get(&base)?;
        self.loaded_by_name.get(name)
    }

    /// Returns one already loaded module that owns the requested virtual address.
    pub fn get_by_address(&self, address: u64) -> Option<&ModuleRecord> {
        self.load_order.iter().rev().find_map(|name| {
            let module = self.loaded_by_name.get(name)?;
            (module.base <= address && address < module.base + module.size).then_some(module)
        })
    }

    /// Returns a snapshot of the currently loaded modules in Python-compatible load order.
    pub fn loaded_modules(&self) -> Vec<ModuleRecord> {
        self.load_order
            .iter()
            .filter_map(|name| self.loaded_by_name.get(name).cloned())
            .collect()
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
        }
        self.loaded_by_base
            .insert(module.base, normalized_name.clone());
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
            let _ = self.memory.unmap(module.base, module.size);
        }
        self.load_order.retain(|loaded| loaded != &name);
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

    /// Loads the main executable image and resolves its imports using Python-compatible rules.
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

    /// Loads one dependency module using the Python whitelist policy and resolves its imports.
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
        if let Some(existing) = self
            .loaded_by_name
            .get(&canonical_name)
            .or_else(|| self.loaded_by_name.get(&normalized_name))
        {
            return Ok(existing.clone());
        }

        let load_target = if canonical_name != normalized_name {
            canonical_name.as_str()
        } else {
            name_or_path
        };
        let resolution_paths = config.module_resolution_paths_for_arch(self.arch.name);
        let search_path_has_real_module =
            resolve_module_path(load_target, &resolution_paths).is_ok();
        if config.is_whitelisted(&normalized_name)
            || config.is_whitelisted(&canonical_name)
            || search_path_has_real_module
        {
            let module = self.load_from_search_paths(load_target, &resolution_paths)?;
            self.resolve_imports_for_module(&module, config, hooks)?;
            Ok(module)
        } else if config.modules_always_exist() {
            let module = self.load_synthetic_module(&canonical_name)?;
            self.populate_synthetic_module_exports(module.base, hooks)?;
            Ok(self.get_by_base(module.base).cloned().unwrap_or(module))
        } else {
            Err(VmError::ModuleNotFound(load_target.to_string()))
        }
    }

    /// Resolves one export by name or ordinal using the same rules as the Python baseline.
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

fn normalize_module_name(path: &Path) -> String {
    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    if file_name.contains('.') {
        file_name
    } else if file_name.is_empty() {
        file_name
    } else {
        format!("{file_name}.dll")
    }
}

fn canonical_runtime_module_name(module_name: &str) -> String {
    aliased_host_module(module_name)
        .map(str::to_string)
        .unwrap_or_else(|| module_name.to_string())
}

fn aliased_host_module(module_name: &str) -> Option<&'static str> {
    if module_name.starts_with("api-ms-win-core-") || module_name.starts_with("ext-ms-win-") {
        Some("kernel32.dll")
    } else if module_name.starts_with("api-ms-win-crt-")
        || module_name.eq_ignore_ascii_case("ucrtbase.dll")
        || module_name.eq_ignore_ascii_case("vcruntime140.dll")
        || module_name.eq_ignore_ascii_case("vcruntime140_1.dll")
    {
        Some("msvcrt.dll")
    } else {
        None
    }
}

fn should_canonicalize_runtime_request(name_or_path: &str) -> bool {
    !name_or_path.contains('/') && !name_or_path.contains('\\') && !name_or_path.contains(':')
}

fn resolve_module_path(name_or_path: &str, search_paths: &[PathBuf]) -> Result<PathBuf, VmError> {
    let raw_path = Path::new(name_or_path);
    if raw_path.exists() {
        return std::path::absolute(raw_path).map_err(|source| VmError::ReadFile {
            path: raw_path.to_path_buf(),
            source,
        });
    }
    if raw_path.is_absolute() {
        return Err(VmError::ModuleNotFound(name_or_path.to_string()));
    }

    let candidate_names = if raw_path.extension().is_some() {
        vec![raw_path.to_path_buf()]
    } else {
        vec![raw_path.to_path_buf(), raw_path.with_extension("dll")]
    };

    for root in search_paths {
        for search_root in module_snapshot_search_roots(root) {
            for candidate_name in &candidate_names {
                if let Some(candidate) =
                    resolve_case_insensitive_relative(&search_root, candidate_name)
                {
                    return std::path::absolute(&candidate).map_err(|source| VmError::ReadFile {
                        path: candidate.clone(),
                        source,
                    });
                }
            }
        }
    }

    Err(VmError::ModuleNotFound(name_or_path.to_string()))
}

fn module_snapshot_search_roots(root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for suffix in SNAPSHOT_SEARCH_SUFFIXES {
        let candidate = if suffix.is_empty() {
            root.to_path_buf()
        } else {
            root.join(suffix)
        };
        if !roots.iter().any(|existing| existing == &candidate) {
            roots.push(candidate);
        }
    }
    roots
}

fn resolve_case_insensitive_relative(base: &Path, relative: &Path) -> Option<PathBuf> {
    let mut current = base.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return None;
        };
        let exact = current.join(name);
        if exact.exists() {
            current = exact;
            continue;
        }
        let needle = name.to_string_lossy().to_ascii_lowercase();
        let matched = fs::read_dir(&current)
            .ok()?
            .filter_map(Result::ok)
            .find(|entry| entry.file_name().to_string_lossy().to_ascii_lowercase() == needle)?;
        current = matched.path();
    }
    current.exists().then_some(current)
}

impl ModuleManager {
    fn load_synthetic_module(&mut self, module_name: &str) -> Result<ModuleRecord, VmError> {
        let normalized_name = normalize_module_name(Path::new(module_name));
        if let Some(existing) = self.loaded_by_name.get(&normalized_name) {
            return Ok(existing.clone());
        }

        let size = 0x400000;
        let base =
            self.memory
                .reserve(size, None, &format!("synthetic:{normalized_name}"), true)?;
        let module = ModuleRecord {
            name: normalized_name.clone(),
            path: None,
            arch: self.arch.name.to_string(),
            is_dll: true,
            base,
            size,
            entrypoint: base + SYNTHETIC_TEXT_RVA,
            image_base: base,
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
        self.load_order.push(normalized_name.clone());
        self.loaded_by_name
            .insert(normalized_name.clone(), module.clone());
        Ok(module)
    }

    fn populate_synthetic_module_exports(
        &mut self,
        module_base: u64,
        hooks: &mut HookRegistry,
    ) -> Result<(), VmError> {
        let Some(module_name) = self.loaded_by_base.get(&module_base).cloned() else {
            return Ok(());
        };
        let definitions = hooks.definitions_for_module(&module_name);
        if definitions.is_empty() {
            return Ok(());
        }
        let (memory, loaded_by_name) = (&mut self.memory, &mut self.loaded_by_name);
        let Some(module) = loaded_by_name.get_mut(&module_name) else {
            return Ok(());
        };
        if !module.synthetic {
            return Ok(());
        }
        for definition in definitions {
            hooks.bind_module_stub(module, definition.function, None, memory);
        }
        Ok(())
    }

    fn resolve_imports_for_module(
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
            let resolved = if import.by_ordinal {
                self.resolve_export(dependency.base, config, hooks, None, Some(import.ordinal))
            } else {
                self.resolve_export(dependency.base, config, hooks, Some(&import.function), None)
            };
            self.write_pointer(module.base + import.offset, resolved, import.size)?;
        }

        Ok(())
    }

    fn write_pointer(&mut self, address: u64, value: u64, size: usize) -> Result<(), VmError> {
        let bytes = match size {
            0..=4 => (value as u32).to_le_bytes()[..size.max(4).min(4)].to_vec(),
            8 => value.to_le_bytes().to_vec(),
            _ => value.to_le_bytes()[..8].to_vec(),
        };
        self.memory.write(address, &bytes).map_err(VmError::from)
    }

    fn resolve_export_with_depth(
        &mut self,
        module_base: u64,
        config: &EngineConfig,
        hooks: &mut HookRegistry,
        name: Option<&str>,
        ordinal: Option<u16>,
        depth: usize,
    ) -> u64 {
        if depth >= MAX_FORWARD_EXPORT_DEPTH {
            return 0;
        }

        let Some(module_name) = self.loaded_by_base.get(&module_base).cloned() else {
            return 0;
        };
        enum ExportResolution {
            Address(u64),
            Forward(ForwardedExportTarget),
            SyntheticName(String),
            SyntheticOrdinal(u16),
            ExternalSyntheticName(String),
            ExternalSyntheticOrdinal(u16),
            Missing,
        }

        let resolution = {
            let Some(module) = self.loaded_by_name.get(&module_name) else {
                return 0;
            };

            if let Some(name) = name {
                let normalized_name = name.to_ascii_lowercase();
                if let Some(address) = module.exports_by_name.get(&normalized_name) {
                    ExportResolution::Address(*address)
                } else if let Some(target) = module.forwarded_exports_by_name.get(&normalized_name)
                {
                    ExportResolution::Forward(target.clone())
                } else if module.synthetic {
                    ExportResolution::SyntheticName(normalized_name)
                } else if config.functions_always_exist() {
                    ExportResolution::ExternalSyntheticName(normalized_name)
                } else {
                    ExportResolution::Missing
                }
            } else if let Some(ordinal) = ordinal {
                if let Some(address) = module.exports_by_ordinal.get(&ordinal) {
                    ExportResolution::Address(*address)
                } else if let Some(target) = module.forwarded_exports_by_ordinal.get(&ordinal) {
                    ExportResolution::Forward(target.clone())
                } else if module.synthetic {
                    ExportResolution::SyntheticOrdinal(ordinal)
                } else if config.functions_always_exist() {
                    ExportResolution::ExternalSyntheticOrdinal(ordinal)
                } else {
                    ExportResolution::Missing
                }
            } else {
                ExportResolution::Missing
            }
        };

        match resolution {
            ExportResolution::Address(address) => address,
            ExportResolution::Forward(target) => {
                self.resolve_forwarded_export_target(config, hooks, target, depth + 1)
            }
            ExportResolution::SyntheticName(name) => {
                let (memory, loaded_by_name) = (&mut self.memory, &mut self.loaded_by_name);
                let Some(module) = loaded_by_name.get_mut(&module_name) else {
                    return 0;
                };
                hooks.bind_module_stub(module, &name, None, memory)
            }
            ExportResolution::SyntheticOrdinal(ordinal) => {
                let (memory, loaded_by_name) = (&mut self.memory, &mut self.loaded_by_name);
                let Some(module) = loaded_by_name.get_mut(&module_name) else {
                    return 0;
                };
                hooks.bind_module_stub(module, &format!("ordinal_{ordinal}"), Some(ordinal), memory)
            }
            ExportResolution::ExternalSyntheticName(name) => hooks.bind_stub(&module_name, &name),
            ExportResolution::ExternalSyntheticOrdinal(ordinal) => {
                hooks.bind_stub(&module_name, &format!("ordinal_{ordinal}"))
            }
            ExportResolution::Missing => 0,
        }
    }

    fn resolve_forwarded_export_target(
        &mut self,
        config: &EngineConfig,
        hooks: &mut HookRegistry,
        target: ForwardedExportTarget,
        depth: usize,
    ) -> u64 {
        let dependency = match &target {
            ForwardedExportTarget::ByName { module, .. }
            | ForwardedExportTarget::ByOrdinal { module, .. } => {
                match self.load_runtime_dependency(module, config, hooks) {
                    Ok(module) => module,
                    Err(_) => return 0,
                }
            }
        };

        match target {
            ForwardedExportTarget::ByName { function, .. } => self.resolve_export_with_depth(
                dependency.base,
                config,
                hooks,
                Some(&function),
                None,
                depth,
            ),
            ForwardedExportTarget::ByOrdinal { ordinal, .. } => self.resolve_export_with_depth(
                dependency.base,
                config,
                hooks,
                None,
                Some(ordinal),
                depth,
            ),
        }
    }
}
