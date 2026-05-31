use std::collections::HashMap;

use crate::api_set::{aliased_host_module, contract_hook_family};
use crate::hooks::signature::HookSignature;
use crate::memory::manager::MemoryManager;
use crate::models::ModuleRecord;

const SYNTHETIC_EXPORT_SECTION_RVA: u32 = 0x1000;
const SYNTHETIC_EXPORT_DIRECTORY_RVA: u32 = SYNTHETIC_EXPORT_SECTION_RVA;
const SYNTHETIC_EXPORT_ADDRESS_TABLE_RVA: u32 = SYNTHETIC_EXPORT_DIRECTORY_RVA + 0x40;
pub(crate) const SYNTHETIC_TEXT_RVA: u64 = 0x20000;
pub(crate) const SYNTHETIC_STUB_RVA_START: u64 = 0x22000;
const SYNTHETIC_STUB_SIZE: u64 = 0x10;
const SYNTHETIC_MODULE_MIN_RESERVE_SIZE: u64 = 0x80000;
const SYNTHETIC_HEADER_SIZE: u32 = 0x200;
const SYNTHETIC_SECTION_ALIGNMENT: u32 = 0x1000;
const SYNTHETIC_FILE_ALIGNMENT: u32 = 0x200;
const SYNTHETIC_STACK_SIZE: u32 = 0x1000;
const SYNTHETIC_STACK_SIZE_X64: u64 = 0x1000;
const SYNTHETIC_SECTION_DATA_FLAGS: u32 = 0x4000_0040;
const SYNTHETIC_SECTION_CODE_FLAGS: u32 = 0x6000_0020;
const SYNTHETIC_DLL_CHARACTERISTICS: u16 = 0x0140;
const SYNTHETIC_SUBSYSTEM: u16 = 0x0002;
const SYNTHETIC_SECTION_NAME_EDATA: [u8; 8] = *b".edata\0\0";
const SYNTHETIC_SECTION_NAME_TEXT: [u8; 8] = *b".text\0\0\0";
const SYNTHETIC_STUB_BYTES: [u8; 16] = [0xC3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const KI_USER_EXCEPTION_DISPATCHER_STUB_BYTES: [u8; 16] = [
    0x48, 0x8B, 0x05, 0x01, 0x00, 0x00, 0x00, 0xC3, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn guest_visible_address_for_module(module: &ModuleRecord, address: u64) -> u64 {
    if module.visible_base == 0 || module.visible_base == module.base {
        return address;
    }
    if address < module.base || address >= module.base.saturating_add(module.size) {
        return address;
    }
    module.visible_base + (address - module.base)
}

fn write_module_image_bytes(
    module: &ModuleRecord,
    memory: &mut MemoryManager,
    address: u64,
    data: &[u8],
) {
    let _ = memory.write(address, data);
    let visible_address = guest_visible_address_for_module(module, address);
    if visible_address != address && memory.is_range_mapped(visible_address, data.len() as u64) {
        let _ = memory.write(visible_address, data);
    }
}

/// Stores synthetic export bindings for DLL hook dispatch.
#[derive(Debug, Default)]
pub struct HookRegistry {
    next_stub: u64,
    signatures: HashMap<(String, String), HookSignature>,
    bindings_by_name: HashMap<(String, String), u64>,
    bindings_by_address: HashMap<u64, (String, String)>,
    observed_real_exports_by_address: HashMap<u64, (String, String)>,
    import_bindings_by_thunk: HashMap<u64, ImportThunkBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportThunkBinding {
    pub importing_module: String,
    pub requested_module: String,
    pub requested_function: String,
    pub resolved_module: String,
    pub resolved_function: String,
    pub resolved_address: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct BoundHookLookup<'a> {
    pub module: &'a str,
    pub function: &'a str,
    pub signature: Option<&'a HookSignature>,
}

impl HookRegistry {
    /// Builds a test-friendly empty hook registry.
    pub fn for_tests() -> Self {
        Self {
            next_stub: 0x1000_0000,
            signatures: HashMap::new(),
            bindings_by_name: HashMap::new(),
            bindings_by_address: HashMap::new(),
            observed_real_exports_by_address: HashMap::new(),
            import_bindings_by_thunk: HashMap::new(),
        }
    }

    /// Registers minimal stub signatures for functions that only need module/function identity.
    ///
    /// Each function gets a `HookSignature` with empty params and default return spec.
    /// If a full signature was already registered (e.g. via `register_signatures()`),
    /// the existing entry is preserved.
    pub fn register_function_stubs(
        &mut self,
        module: &'static str,
        functions: &[(&'static str, crate::hooks::types::LogicalAbi)],
    ) {
        for &(function, abi) in functions {
            let key = normalized_key(module, function);
            self.signatures.entry(key).or_insert_with(|| HookSignature {
                module,
                function,
                abi,
                params: &[],
                ret: crate::hooks::signature::ReturnSpec::default(),
                flags: crate::hooks::types::HookFlags::empty(),
            });
        }
    }

    /// Registers (or overrides) full `HookSignature` entries.
    ///
    /// Called after `register_library()` to replace the bridged empty signatures
    /// with complete ones that carry typed parameters and return specs.
    pub fn register_signatures(&mut self, signatures: &[HookSignature]) {
        for sig in signatures {
            let key = normalized_key(sig.module, sig.function);
            self.signatures.insert(key, sig.clone());
        }
    }

    /// Binds or reuses a synthetic export stub address for one module and function name.
    pub fn bind_stub(&mut self, module: &str, function: &str) -> u64 {
        let key = normalized_key(module, function);
        if let Some(existing) = self.bindings_by_name.get(&key) {
            return *existing;
        }

        let stub = self.next_stub;
        self.next_stub += 0x10;
        self.bindings_by_address.insert(stub, key.clone());
        self.bindings_by_name.insert(key, stub);
        stub
    }

    /// Binds one synthetic export inside the owning module so `GetProcAddress` resolves correctly.
    pub fn bind_module_stub(
        &mut self,
        module: &mut ModuleRecord,
        function: &str,
        ordinal: Option<u16>,
        memory: &mut MemoryManager,
    ) -> u64 {
        let key = normalized_key(&module.name, function);
        let function_key = function.to_ascii_lowercase();
        if let Some(existing) = module.exports_by_name.get(&function_key) {
            if self.observed_real_exports_by_address.contains_key(existing) {
                self.bindings_by_name.remove(&key);
                return *existing;
            }
            self.bindings_by_address.insert(*existing, key.clone());
            self.bindings_by_name.insert(key, *existing);
            let mut refresh_needed = false;
            if !module.export_name_text_by_key.contains_key(&function_key) {
                module
                    .export_name_text_by_key
                    .insert(function_key.clone(), function.to_string());
                refresh_needed = true;
            }
            if let Some(ordinal) = ordinal {
                if module.exports_by_ordinal.get(&ordinal).copied() != Some(*existing) {
                    module.exports_by_ordinal.insert(ordinal, *existing);
                    refresh_needed = true;
                }
            }
            if refresh_needed {
                refresh_synthetic_export_image(module, memory);
            }
            return *existing;
        }

        let stub = module.base + module.stub_cursor;
        module.stub_cursor += 0x10;
        write_module_image_bytes(
            module,
            memory,
            stub,
            &synthetic_stub_bytes(&module.name, function),
        );
        self.bindings_by_address.insert(stub, key.clone());
        self.bindings_by_name.insert(key, stub);
        module.exports_by_name.insert(function_key, stub);
        module
            .export_name_text_by_key
            .insert(function.to_ascii_lowercase(), function.to_string());
        if let Some(ordinal) = ordinal {
            module.exports_by_ordinal.insert(ordinal, stub);
        }
        refresh_synthetic_export_image(module, memory);
        stub
    }

    /// Registers a hook binding at a real export address from a PE loaded from disk.
    /// Unlike `bind_module_stub`, this does not create synthetic stubs — it simply
    /// maps the real function address to its hook signature so the engine dispatches
    /// the hook when the PC reaches that address.
    ///
    /// This is the **canonical** registration: both `bindings_by_name` (name → address)
    /// and `bindings_by_address` (address → name) are updated so that
    /// `binding_address(module, function)` returns this address.
    pub fn bind_real_export(&mut self, module: &str, function: &str, address: u64) {
        if self.observed_real_exports_by_address.contains_key(&address) {
            return;
        }
        let key = normalized_key(module, function);
        self.bindings_by_address.insert(address, key.clone());
        self.bindings_by_name.insert(key, address);
    }

    /// Registers the canonical guest-facing address for one real export.
    ///
    /// This is the single address exposed to the guest via `GetProcAddress`,
    /// PEB/Ldr, IAT writes, and API logs.  Both `bindings_by_name` and
    /// `bindings_by_address` are updated.
    pub fn bind_real_export_canonical(&mut self, module: &str, function: &str, guest_address: u64) {
        if self
            .observed_real_exports_by_address
            .contains_key(&guest_address)
        {
            return;
        }
        let key = normalized_key(module, function);
        self.bindings_by_address.insert(guest_address, key.clone());
        self.bindings_by_name.insert(key, guest_address);
    }

    /// Registers an additional dispatch alias for one real export.
    ///
    /// Unlike `bind_real_export_canonical`, this only adds an entry to the
    /// address dispatch table (`bindings_by_address`).  It does **not** modify
    /// the canonical name lookup (`bindings_by_name`), so the guest-facing
    /// address remains stable regardless of alias registration order.
    pub fn bind_real_export_alias(&mut self, module: &str, function: &str, alias_address: u64) {
        if self
            .observed_real_exports_by_address
            .contains_key(&alias_address)
        {
            return;
        }
        let key = normalized_key(module, function);
        self.bindings_by_address.insert(alias_address, key);
    }

    /// Registers one real export address for observation-only logging.
    ///
    /// Unlike `bind_real_export_*`, this does not make the address dispatchable
    /// through the hook system.  It is used for allow_execution modules whose
    /// real exports must continue executing natively while still being visible
    /// in API logs.
    pub fn observe_real_export(&mut self, module: &str, function: &str, address: u64) {
        let key = normalized_key(module, function);
        self.bindings_by_address.remove(&address);
        if self.bindings_by_name.get(&key).copied() == Some(address) {
            self.bindings_by_name.remove(&key);
        }
        self.observed_real_exports_by_address.insert(address, key);
    }

    /// Returns the already-bound synthetic stub address for one module and function name.
    pub fn binding_address(&self, module: &str, function: &str) -> Option<u64> {
        self.bindings_by_name
            .get(&normalized_key(module, function))
            .copied()
    }

    /// Returns the registered signature for one already-bound stub address.
    pub fn signature_for_address(&self, address: u64) -> Option<&HookSignature> {
        let key = self.bindings_by_address.get(&address)?;
        self.signature_from_key(key)
    }

    /// Returns the registered signature for one hook if present.
    pub fn signature(&self, module: &str, function: &str) -> Option<&HookSignature> {
        let key = normalized_key(module, function);
        self.signature_from_key(&key)
    }

    /// Returns one bound-hook lookup without paying for multiple address lookups.
    pub fn bound_lookup(&self, address: u64) -> Option<BoundHookLookup<'_>> {
        let (key_module, key_function) = self.bindings_by_address.get(&address)?;
        let signature = self.signature_from_parts(key_module, key_function);
        let module = key_module.as_str();
        let function = if let Some(sig) = signature {
            sig.function
        } else {
            key_function.as_str()
        };
        Some(BoundHookLookup {
            module,
            function,
            signature,
        })
    }

    /// Returns the normalized module/function pair bound at one synthetic stub address.
    pub fn binding_for_address(&self, address: u64) -> Option<(&str, &str)> {
        let (module, function) = self.bindings_by_address.get(&address)?;
        Some((module.as_str(), function.as_str()))
    }

    /// Returns the observed real-export identity for one address without
    /// making it dispatchable through the hook system.
    pub fn observed_real_export_for_address(&self, address: u64) -> Option<(&str, &str)> {
        let (module, function) = self.observed_real_exports_by_address.get(&address)?;
        Some((module.as_str(), function.as_str()))
    }

    /// Records one resolved import thunk so diagnostics can distinguish the
    /// original import identity from the real export that satisfied it.
    pub fn record_import_binding(
        &mut self,
        thunk: u64,
        importing_module: &str,
        requested_module: &str,
        requested_function: &str,
        resolved_module: &str,
        resolved_function: &str,
        resolved_address: u64,
    ) {
        self.import_bindings_by_thunk.insert(
            thunk,
            ImportThunkBinding {
                importing_module: importing_module.to_string(),
                requested_module: requested_module.to_string(),
                requested_function: requested_function.to_string(),
                resolved_module: resolved_module.to_string(),
                resolved_function: resolved_function.to_string(),
                resolved_address,
            },
        );
    }

    /// Returns the resolved binding metadata for one import thunk.
    pub fn import_binding_for_thunk(&self, thunk: u64) -> Option<&ImportThunkBinding> {
        self.import_bindings_by_thunk.get(&thunk)
    }

    /// Returns the full import thunk binding map for batch iteration.
    pub fn import_bindings_by_thunk(&self) -> &HashMap<u64, ImportThunkBinding> {
        &self.import_bindings_by_thunk
    }

    /// Returns whether the address is one previously bound synthetic stub.
    pub fn is_bound_address(&self, address: u64) -> bool {
        self.bindings_by_address.contains_key(&address)
    }

    /// Returns all currently bound synthetic stub addresses.
    pub fn bound_addresses(&self) -> Vec<u64> {
        self.bindings_by_address.keys().copied().collect()
    }

    // ── Signature-based query API ──

    /// Returns all registered hook function names for one module in deterministic name order.
    pub fn functions_for_module(&self, module: &str) -> Vec<&'static str> {
        let mut functions = self
            .signatures
            .values()
            .filter(|sig| modules_share_hook_space(sig.module, module))
            .map(|sig| sig.function)
            .collect::<Vec<_>>();
        functions.sort();
        functions.dedup();
        functions
    }

    /// Returns whether a hook signature exists for the given module and function.
    pub fn has_signature_for(&self, module: &str, function: &str) -> bool {
        self.signature_from_parts(module, function).is_some()
    }

    /// Returns whether any hook signatures exist for the given module name.
    pub fn has_signatures_for_module(&self, module: &str) -> bool {
        self.signatures
            .values()
            .any(|sig| modules_share_hook_space(sig.module, module))
    }

    fn signature_from_key(&self, key: &(String, String)) -> Option<&HookSignature> {
        self.signature_from_parts(&key.0, &key.1)
    }

    fn signature_from_parts(&self, module: &str, function: &str) -> Option<&HookSignature> {
        let mod_lower = module.to_ascii_lowercase();
        let func_lower = function.to_ascii_lowercase();
        // First try: direct lookup with the normalized key (moves ownership into temporary tuple).
        let key = (mod_lower, func_lower);
        if let Some(sig) = self.signatures.get(&key) {
            return Some(sig);
        }
        let (mod_lower, func_lower) = key;
        // Second try: hook-space module alias (e.g. api-ms-win-core-crt → msvcrt.dll).
        let hook_space_module = normalized_hook_space_module(&mod_lower);
        if hook_space_module != mod_lower {
            let hook_key = (hook_space_module.to_string(), func_lower.clone());
            if let Some(sig) = self.signatures.get(&hook_key) {
                return Some(sig);
            }
        }
        // Fallback: linear scan for module families that share hook space.
        self.signatures
            .iter()
            .find_map(|((sig_module, sig_function), sig)| {
                (sig_function == &func_lower && modules_share_hook_space(sig_module, &mod_lower))
                    .then_some(sig)
            })
    }
}

fn synthetic_stub_bytes(module: &str, function: &str) -> [u8; 16] {
    if module.eq_ignore_ascii_case("ntdll.dll")
        && function.eq_ignore_ascii_case("KiUserExceptionDispatcher")
    {
        KI_USER_EXCEPTION_DISPATCHER_STUB_BYTES
    } else {
        SYNTHETIC_STUB_BYTES
    }
}

pub(crate) fn initialize_synthetic_module_image(module: &ModuleRecord, memory: &mut MemoryManager) {
    write_synthetic_pe_headers(module, memory, 0, synthetic_active_image_size(module));

    let export_fill = vec![0u8; synthetic_export_section_capacity() as usize];
    write_module_image_bytes(
        module,
        memory,
        module.base + SYNTHETIC_EXPORT_SECTION_RVA as u64,
        &export_fill,
    );
    let text_fill = vec![0u8; (SYNTHETIC_STUB_RVA_START - SYNTHETIC_TEXT_RVA) as usize];
    write_module_image_bytes(module, memory, module.base + SYNTHETIC_TEXT_RVA, &text_fill);
    refresh_synthetic_export_image(module, memory);
}

pub(crate) fn synthetic_module_reserve_size(anticipated_exports: usize) -> u64 {
    let anticipated_stub_end = SYNTHETIC_STUB_RVA_START
        .saturating_add((anticipated_exports as u64).saturating_mul(SYNTHETIC_STUB_SIZE));
    align_u64(
        anticipated_stub_end.max(SYNTHETIC_MODULE_MIN_RESERVE_SIZE),
        SYNTHETIC_SECTION_ALIGNMENT as u64,
    )
}

fn write_section_header(
    buffer: &mut [u8],
    offset: usize,
    name: &[u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
) {
    buffer[offset..offset + 8].copy_from_slice(name);
    buffer[offset + 8..offset + 12].copy_from_slice(&virtual_size.to_le_bytes());
    buffer[offset + 12..offset + 16].copy_from_slice(&virtual_address.to_le_bytes());
    buffer[offset + 16..offset + 20].copy_from_slice(&raw_size.to_le_bytes());
    buffer[offset + 20..offset + 24].copy_from_slice(&raw_pointer.to_le_bytes());
    buffer[offset + 36..offset + 40].copy_from_slice(&characteristics.to_le_bytes());
}

fn synthetic_export_section_capacity() -> u32 {
    (SYNTHETIC_TEXT_RVA as u32).saturating_sub(SYNTHETIC_EXPORT_SECTION_RVA)
}

fn synthetic_active_image_size(module: &ModuleRecord) -> u32 {
    let used_end = module
        .stub_cursor
        .max(SYNTHETIC_STUB_RVA_START)
        .max(SYNTHETIC_TEXT_RVA + SYNTHETIC_SECTION_ALIGNMENT as u64);
    align_u32(
        used_end.min(u64::from(u32::MAX)) as u32,
        SYNTHETIC_SECTION_ALIGNMENT,
    )
}

fn write_synthetic_pe_headers(
    module: &ModuleRecord,
    memory: &mut MemoryManager,
    export_directory_size: u32,
    reported_image_size: u32,
) {
    let mut headers = vec![0u8; SYNTHETIC_HEADER_SIZE as usize];
    headers[0] = b'M';
    headers[1] = b'Z';
    headers[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    let pe_offset = 0x80usize;
    headers[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    let coff_offset = pe_offset + 4;
    let optional_offset = coff_offset + 20;
    let section_offset;
    let is_x64 = module.arch.eq_ignore_ascii_case("x64");
    let size_of_optional_header = if is_x64 { 0xF0u16 } else { 0xE0u16 };
    let export_virtual_size = export_directory_size.max(0x40);
    let export_raw_size = align_u32(export_virtual_size, SYNTHETIC_FILE_ALIGNMENT);
    let text_virtual_size = reported_image_size
        .saturating_sub(SYNTHETIC_TEXT_RVA as u32)
        .max(SYNTHETIC_SECTION_ALIGNMENT);
    let text_raw_size = align_u32(text_virtual_size, SYNTHETIC_FILE_ALIGNMENT);
    let text_raw_pointer = align_u32(
        SYNTHETIC_HEADER_SIZE + export_raw_size,
        SYNTHETIC_FILE_ALIGNMENT,
    );
    let coff_characteristics = if is_x64 { 0x2022u16 } else { 0x2102u16 };

    headers[coff_offset..coff_offset + 2]
        .copy_from_slice(&(if is_x64 { 0x8664u16 } else { 0x014Cu16 }).to_le_bytes());
    headers[coff_offset + 2..coff_offset + 4].copy_from_slice(&2u16.to_le_bytes());
    headers[coff_offset + 16..coff_offset + 18]
        .copy_from_slice(&size_of_optional_header.to_le_bytes());
    headers[coff_offset + 18..coff_offset + 20]
        .copy_from_slice(&coff_characteristics.to_le_bytes());

    if is_x64 {
        headers[optional_offset..optional_offset + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        headers[optional_offset + 4..optional_offset + 8]
            .copy_from_slice(&text_raw_size.to_le_bytes());
        headers[optional_offset + 8..optional_offset + 12]
            .copy_from_slice(&export_raw_size.to_le_bytes());
        headers[optional_offset + 16..optional_offset + 20]
            .copy_from_slice(&(SYNTHETIC_TEXT_RVA as u32).to_le_bytes());
        headers[optional_offset + 20..optional_offset + 24]
            .copy_from_slice(&(SYNTHETIC_TEXT_RVA as u32).to_le_bytes());
        headers[optional_offset + 24..optional_offset + 32]
            .copy_from_slice(&module.image_base.to_le_bytes());
        headers[optional_offset + 32..optional_offset + 36]
            .copy_from_slice(&SYNTHETIC_SECTION_ALIGNMENT.to_le_bytes());
        headers[optional_offset + 36..optional_offset + 40]
            .copy_from_slice(&SYNTHETIC_FILE_ALIGNMENT.to_le_bytes());
        headers[optional_offset + 56..optional_offset + 60]
            .copy_from_slice(&reported_image_size.to_le_bytes());
        headers[optional_offset + 60..optional_offset + 64]
            .copy_from_slice(&SYNTHETIC_HEADER_SIZE.to_le_bytes());
        headers[optional_offset + 68..optional_offset + 70]
            .copy_from_slice(&SYNTHETIC_SUBSYSTEM.to_le_bytes());
        headers[optional_offset + 70..optional_offset + 72]
            .copy_from_slice(&SYNTHETIC_DLL_CHARACTERISTICS.to_le_bytes());
        headers[optional_offset + 72..optional_offset + 80]
            .copy_from_slice(&SYNTHETIC_STACK_SIZE_X64.to_le_bytes());
        headers[optional_offset + 80..optional_offset + 88]
            .copy_from_slice(&SYNTHETIC_STACK_SIZE_X64.to_le_bytes());
        headers[optional_offset + 88..optional_offset + 96]
            .copy_from_slice(&SYNTHETIC_STACK_SIZE_X64.to_le_bytes());
        headers[optional_offset + 96..optional_offset + 104]
            .copy_from_slice(&SYNTHETIC_STACK_SIZE_X64.to_le_bytes());
        headers[optional_offset + 108..optional_offset + 112].copy_from_slice(&16u32.to_le_bytes());
        headers[optional_offset + 112..optional_offset + 116]
            .copy_from_slice(&SYNTHETIC_EXPORT_DIRECTORY_RVA.to_le_bytes());
        headers[optional_offset + 116..optional_offset + 120]
            .copy_from_slice(&export_directory_size.to_le_bytes());
    } else {
        headers[optional_offset..optional_offset + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        headers[optional_offset + 4..optional_offset + 8]
            .copy_from_slice(&text_raw_size.to_le_bytes());
        headers[optional_offset + 8..optional_offset + 12]
            .copy_from_slice(&export_raw_size.to_le_bytes());
        headers[optional_offset + 16..optional_offset + 20]
            .copy_from_slice(&(SYNTHETIC_TEXT_RVA as u32).to_le_bytes());
        headers[optional_offset + 20..optional_offset + 24]
            .copy_from_slice(&(SYNTHETIC_TEXT_RVA as u32).to_le_bytes());
        headers[optional_offset + 24..optional_offset + 28]
            .copy_from_slice(&SYNTHETIC_EXPORT_SECTION_RVA.to_le_bytes());
        headers[optional_offset + 28..optional_offset + 32]
            .copy_from_slice(&(module.image_base as u32).to_le_bytes());
        headers[optional_offset + 32..optional_offset + 36]
            .copy_from_slice(&SYNTHETIC_SECTION_ALIGNMENT.to_le_bytes());
        headers[optional_offset + 36..optional_offset + 40]
            .copy_from_slice(&SYNTHETIC_FILE_ALIGNMENT.to_le_bytes());
        headers[optional_offset + 56..optional_offset + 60]
            .copy_from_slice(&reported_image_size.to_le_bytes());
        headers[optional_offset + 60..optional_offset + 64]
            .copy_from_slice(&SYNTHETIC_HEADER_SIZE.to_le_bytes());
        headers[optional_offset + 68..optional_offset + 70]
            .copy_from_slice(&SYNTHETIC_SUBSYSTEM.to_le_bytes());
        headers[optional_offset + 70..optional_offset + 72]
            .copy_from_slice(&SYNTHETIC_DLL_CHARACTERISTICS.to_le_bytes());
        headers[optional_offset + 72..optional_offset + 76]
            .copy_from_slice(&SYNTHETIC_STACK_SIZE.to_le_bytes());
        headers[optional_offset + 76..optional_offset + 80]
            .copy_from_slice(&SYNTHETIC_STACK_SIZE.to_le_bytes());
        headers[optional_offset + 80..optional_offset + 84]
            .copy_from_slice(&SYNTHETIC_STACK_SIZE.to_le_bytes());
        headers[optional_offset + 84..optional_offset + 88]
            .copy_from_slice(&SYNTHETIC_STACK_SIZE.to_le_bytes());
        headers[optional_offset + 92..optional_offset + 96].copy_from_slice(&16u32.to_le_bytes());
        headers[optional_offset + 96..optional_offset + 100]
            .copy_from_slice(&SYNTHETIC_EXPORT_DIRECTORY_RVA.to_le_bytes());
        headers[optional_offset + 100..optional_offset + 104]
            .copy_from_slice(&export_directory_size.to_le_bytes());
    }

    section_offset = optional_offset + size_of_optional_header as usize;
    write_section_header(
        &mut headers,
        section_offset,
        &SYNTHETIC_SECTION_NAME_EDATA,
        export_virtual_size,
        SYNTHETIC_EXPORT_SECTION_RVA,
        export_raw_size,
        SYNTHETIC_HEADER_SIZE,
        SYNTHETIC_SECTION_DATA_FLAGS,
    );
    write_section_header(
        &mut headers,
        section_offset + 40,
        &SYNTHETIC_SECTION_NAME_TEXT,
        text_virtual_size,
        SYNTHETIC_TEXT_RVA as u32,
        text_raw_size,
        text_raw_pointer,
        SYNTHETIC_SECTION_CODE_FLAGS,
    );
    write_module_image_bytes(module, memory, module.base, &headers);
}

fn refresh_synthetic_export_image(module: &ModuleRecord, memory: &mut MemoryManager) {
    let export_fill = vec![0u8; synthetic_export_section_capacity() as usize];
    write_module_image_bytes(
        module,
        memory,
        module.base + SYNTHETIC_EXPORT_SECTION_RVA as u64,
        &export_fill,
    );

    let export_base = module.exports_by_ordinal.keys().copied().min().unwrap_or(1);
    let max_ordinal = module
        .exports_by_ordinal
        .keys()
        .copied()
        .max()
        .unwrap_or(export_base.saturating_sub(1));
    let ordinal_slots = max_ordinal
        .checked_sub(export_base)
        .map(|delta| delta as usize + 1)
        .unwrap_or(0);
    let mut function_rvas = vec![0u32; ordinal_slots];
    let mut address_to_index = HashMap::new();

    for (ordinal, address) in &module.exports_by_ordinal {
        let slot = ordinal.saturating_sub(export_base) as usize;
        if slot >= function_rvas.len() {
            continue;
        }
        let rva = address.saturating_sub(module.base) as u32;
        function_rvas[slot] = rva;
        address_to_index.entry(*address).or_insert(slot as u16);
    }
    for address in module.exports_by_name.values().copied() {
        if address_to_index.contains_key(&address) {
            continue;
        }
        let index = function_rvas.len() as u16;
        address_to_index.insert(address, index);
        function_rvas.push(address.saturating_sub(module.base) as u32);
    }

    let mut named_exports = module
        .exports_by_name
        .iter()
        .filter_map(|(name, address)| {
            let export_name = module
                .export_name_text_by_key
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.clone());
            address_to_index
                .get(address)
                .copied()
                .map(|index| (export_name, index))
        })
        .collect::<Vec<_>>();
    named_exports.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    let address_table_offset = SYNTHETIC_EXPORT_ADDRESS_TABLE_RVA - SYNTHETIC_EXPORT_SECTION_RVA;
    let ordinal_table_offset = address_table_offset + function_rvas.len().saturating_mul(4) as u32;
    let name_pointer_table_offset = align_u32(
        ordinal_table_offset + named_exports.len().saturating_mul(2) as u32,
        4,
    );
    let mut string_offset = align_u32(
        name_pointer_table_offset + named_exports.len().saturating_mul(4) as u32,
        4,
    );
    let module_name_offset = string_offset;
    let mut blob = vec![0u8; string_offset as usize];

    for (index, rva) in function_rvas.iter().enumerate() {
        let offset = address_table_offset as usize + index * 4;
        blob[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
    }

    blob.extend_from_slice(module.name.as_bytes());
    blob.push(0);
    string_offset = string_offset.saturating_add(module.name.len() as u32 + 1);

    for (index, (name, function_index)) in named_exports.iter().enumerate() {
        let name_offset = string_offset;
        blob.extend_from_slice(name.as_bytes());
        blob.push(0);

        let name_pointer_offset = name_pointer_table_offset as usize + index * 4;
        let name_rva = SYNTHETIC_EXPORT_SECTION_RVA + name_offset;
        blob[name_pointer_offset..name_pointer_offset + 4].copy_from_slice(&name_rva.to_le_bytes());

        let ordinal_offset = ordinal_table_offset as usize + index * 2;
        blob[ordinal_offset..ordinal_offset + 2].copy_from_slice(&function_index.to_le_bytes());

        string_offset = string_offset.saturating_add(name.len() as u32 + 1);
    }

    let mut directory = [0u8; 40];
    directory[12..16]
        .copy_from_slice(&(SYNTHETIC_EXPORT_SECTION_RVA + module_name_offset).to_le_bytes());
    directory[16..20].copy_from_slice(&(export_base as u32).to_le_bytes());
    directory[20..24].copy_from_slice(&(function_rvas.len() as u32).to_le_bytes());
    directory[24..28].copy_from_slice(&(named_exports.len() as u32).to_le_bytes());
    directory[28..32].copy_from_slice(&SYNTHETIC_EXPORT_ADDRESS_TABLE_RVA.to_le_bytes());
    directory[32..36]
        .copy_from_slice(&(SYNTHETIC_EXPORT_SECTION_RVA + name_pointer_table_offset).to_le_bytes());
    directory[36..40]
        .copy_from_slice(&(SYNTHETIC_EXPORT_SECTION_RVA + ordinal_table_offset).to_le_bytes());
    blob[0..directory.len()].copy_from_slice(&directory);

    let export_directory_size = align_u32(blob.len() as u32, 4);
    write_module_image_bytes(
        module,
        memory,
        module.base + SYNTHETIC_EXPORT_SECTION_RVA as u64,
        &blob,
    );
    write_synthetic_pe_headers(
        module,
        memory,
        export_directory_size,
        synthetic_active_image_size(module),
    );
    restore_synthetic_export_stubs(module, memory);
}

fn restore_synthetic_export_stubs(module: &ModuleRecord, memory: &mut MemoryManager) {
    let mut restored = HashMap::new();
    for (name_key, address) in &module.exports_by_name {
        if restored.contains_key(address) {
            continue;
        }
        let function = module
            .export_name_text_by_key
            .get(name_key)
            .cloned()
            .unwrap_or_else(|| name_key.clone());
        write_module_image_bytes(
            module,
            memory,
            *address,
            &synthetic_stub_bytes(&module.name, &function),
        );
        restored.insert(*address, ());
    }
}

fn align_u32(value: u32, alignment: u32) -> u32 {
    if alignment <= 1 {
        return value;
    }
    let mask = alignment - 1;
    value.saturating_add(mask) & !mask
}

fn align_u64(value: u64, alignment: u64) -> u64 {
    if alignment <= 1 {
        return value;
    }
    let mask = alignment - 1;
    value.saturating_add(mask) & !mask
}

fn normalized_key(module: &str, function: &str) -> (String, String) {
    (module.to_ascii_lowercase(), function.to_ascii_lowercase())
}

fn normalized_hook_space_module(module: &str) -> &str {
    let manual_contract = contract_hook_family(module);
    match manual_contract.unwrap_or_else(|| aliased_host_module(module).unwrap_or(module)) {
        "api-ms-win-core-crt" | "api-ms-win-crt" => "msvcrt.dll",
        // Keep loading/runtime aliasing separate from hook-space matching so
        // real ucrtbase.dll can be mapped into memory while still reusing the
        // existing CRT hook implementations registered under msvcrt.dll.
        "ucrtbase.dll" | "msvcrt.dll" | "msvcr71.dll" | "msvcr80.dll" | "msvcr100.dll"
        | "msvcr120.dll" => "msvcrt.dll",
        "kernel32.dll" | "kernelbase.dll" => "kernel32.dll",
        "netapi32.dll" | "samcli.dll" | "wkscli.dll" => "netapi32.dll",
        other => other,
    }
}

fn modules_share_hook_space(definition_module: &str, requested_module: &str) -> bool {
    let definition_lower = definition_module.to_ascii_lowercase();
    let requested_lower = requested_module.to_ascii_lowercase();
    if definition_lower == requested_lower {
        return true;
    }
    normalized_hook_space_module(&definition_lower)
        == normalized_hook_space_module(&requested_lower)
}

#[cfg(test)]
mod tests {
    use super::HookRegistry;
    use crate::hooks::families::core::api_set_contracts::register_api_set_contract_hooks;
    use crate::hooks::families::core::kernel32::register_kernel32_hooks;
    use crate::hooks::families::crt::msvcrt::register_msvcrt_hooks;
    use crate::hooks::families::network::netapi32::register_netapi32_hooks;
    use crate::hooks::families::security::advapi32::register_advapi32_hooks;
    use crate::hooks::families::shell_services;
    use crate::hooks::families::ui;
    use crate::hooks::types::{ParamType, ParamTypeDiscriminant};

    #[test]
    fn ucrtbase_real_exports_share_msvcrt_hook_space() {
        let mut registry = HookRegistry::for_tests();
        register_msvcrt_hooks(&mut registry);

        registry.bind_real_export("ucrtbase.dll", "memcpy", 0x401000);

        let bound = registry
            .bound_lookup(0x401000)
            .expect("ucrtbase real export should be bound");
        assert_eq!(bound.module, "ucrtbase.dll");
        assert_eq!(bound.function, "memcpy");
        assert!(
            bound.signature.is_some(),
            "ucrtbase real export should resolve into the CRT hook space"
        );
    }

    #[test]
    fn api_set_core_crt_contracts_resolve_into_crt_hook_space() {
        let mut registry = HookRegistry::for_tests();
        register_msvcrt_hooks(&mut registry);

        assert!(
            registry.has_signature_for("api-ms-win-core-crt-l1-1-0.dll", "memcpy"),
            "api-ms-win-core-crt contracts should reuse existing CRT hooks"
        );
        assert!(
            registry.has_signature_for("ucrtbase.dll", "memcpy"),
            "real ucrtbase exports should reuse existing CRT hooks"
        );
    }

    #[test]
    fn kernelbase_real_exports_share_kernel32_hook_space() {
        let mut registry = HookRegistry::for_tests();
        register_kernel32_hooks(&mut registry);

        registry.bind_real_export("kernelbase.dll", "GetProcAddress", 0x402000);

        let bound = registry
            .bound_lookup(0x402000)
            .expect("kernelbase real export should be bound");
        assert_eq!(bound.module, "kernelbase.dll");
        assert_eq!(bound.function, "GetProcAddress");
        assert!(
            bound.signature.is_some(),
            "kernelbase real exports should reuse kernel32 hook implementations"
        );
    }

    #[test]
    fn libraryloader_contract_versions_share_manual_hook_family() {
        let mut registry = HookRegistry::for_tests();
        register_api_set_contract_hooks(&mut registry);

        assert!(
            registry
                .has_signature_for("api-ms-win-core-libraryloader-l1-2-0.dll", "GetProcAddress"),
            "versioned libraryloader contracts should reuse manual contract hooks"
        );
        assert!(
            registry.has_signature_for("api-ms-win-core-libraryloader-l1-2-1.dll", "LoadLibraryW"),
            "later libraryloader contract versions should resolve through the same family key"
        );
    }

    #[test]
    fn second_wave_contract_families_bind_versioned_exports() {
        let mut registry = HookRegistry::for_tests();
        register_api_set_contract_hooks(&mut registry);

        for (module, function) in [
            ("api-ms-win-core-memory-l1-1-0.dll", "VirtualAlloc"),
            ("api-ms-win-core-memory-l1-1-1.dll", "PrefetchVirtualMemory"),
            ("api-ms-win-core-console-l3-2-0.dll", "GetConsoleWindow"),
            (
                "api-ms-win-core-registryuserspecific-l1-1-0.dll",
                "SHRegGetBoolUSValueW",
            ),
            ("api-ms-win-core-atoms-l1-1-0.dll", "GlobalAddAtomA"),
            ("api-ms-win-core-path-l1-1-0.dll", "PathCchRemoveFileSpec"),
            ("api-ms-win-core-wow64-l1-1-1.dll", "IsWow64Process2"),
            (
                "api-ms-win-core-delayload-l1-1-1.dll",
                "ResolveDelayLoadedAPI",
            ),
        ] {
            assert!(
                registry.has_signature_for(module, function),
                "expected {module}!{function} to resolve through second-wave contract hooks"
            );
        }
    }

    #[test]
    fn third_wave_contract_families_bind_high_frequency_imports() {
        let mut registry = HookRegistry::for_tests();
        register_api_set_contract_hooks(&mut registry);

        for (module, function) in [
            ("api-ms-win-core-com-l1-1-0.dll", "CoCreateInstance"),
            ("api-ms-win-core-synch-l1-2-1.dll", "WaitForMultipleObjects"),
            ("api-ms-win-core-file-l1-2-2.dll", "GetTempPathA"),
            (
                "api-ms-win-core-localization-l2-1-0.dll",
                "GetNumberFormatEx",
            ),
            ("api-ms-win-core-registry-l1-1-1.dll", "RegSetKeyValueW"),
            (
                "api-ms-win-core-shlwapi-legacy-l1-1-0.dll",
                "SHExpandEnvironmentStringsW",
            ),
            ("api-ms-win-core-string-l2-1-1.dll", "SHLoadIndirectString"),
            (
                "api-ms-win-core-versionansi-l1-1-0.dll",
                "GetFileVersionInfoExA",
            ),
            (
                "api-ms-win-core-psapi-l1-1-0.dll",
                "QueryFullProcessImageNameW",
            ),
        ] {
            assert!(
                registry.has_signature_for(module, function),
                "expected {module}!{function} to resolve through third-wave contract hooks"
            );
        }
    }

    #[test]
    fn init_once_execute_once_signature_is_available_for_kernel32_and_versioned_synch_contract() {
        let mut registry = HookRegistry::for_tests();
        register_kernel32_hooks(&mut registry);
        register_api_set_contract_hooks(&mut registry);

        assert!(registry.has_signature_for("kernel32.dll", "InitOnceExecuteOnce"));
        assert!(
            registry.has_signature_for("api-ms-win-core-synch-l1-2-0.dll", "InitOnceExecuteOnce")
        );
    }

    #[test]
    fn high_frequency_signatures_use_refined_pointer_metadata() {
        let mut registry = HookRegistry::for_tests();
        register_kernel32_hooks(&mut registry);
        register_advapi32_hooks(&mut registry);
        shell_services::register(&mut registry);
        ui::register(&mut registry);

        let read_file = registry.signature("kernel32.dll", "ReadFile").unwrap();
        assert_eq!(
            read_file.params[3].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::U32)
        );

        let get_console_mode = registry
            .signature("kernel32.dll", "GetConsoleMode")
            .unwrap();
        assert_eq!(
            get_console_mode.params[1].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::U32)
        );

        let get_module_handle_ex = registry
            .signature("kernel32.dll", "GetModuleHandleExW")
            .unwrap();
        assert_eq!(
            get_module_handle_ex.params[2].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::Handle)
        );

        let wide_char_to_multi_byte = registry
            .signature("kernel32.dll", "WideCharToMultiByte")
            .unwrap();
        assert_eq!(wide_char_to_multi_byte.params[6].ty, ParamType::PCStr);
        assert_eq!(
            wide_char_to_multi_byte.params[7].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::U32)
        );

        let reg_query_value = registry
            .signature("advapi32.dll", "RegQueryValueExW")
            .unwrap();
        assert_eq!(
            reg_query_value.params[3].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::U32)
        );
        assert_eq!(
            reg_query_value.params[4].ty,
            ParamType::OutBuffer { len_param: 5 }
        );
        assert_eq!(
            reg_query_value.params[5].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::U32)
        );

        let open_process_token = registry
            .signature("advapi32.dll", "OpenProcessToken")
            .unwrap();
        assert_eq!(
            open_process_token.params[2].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::Handle)
        );

        let command_line_to_argv = registry
            .signature("shell32.dll", "CommandLineToArgvW")
            .unwrap();
        assert_eq!(
            command_line_to_argv.params[1].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::I32)
        );

        let sh_get_known_folder_path = registry
            .signature("shell32.dll", "SHGetKnownFolderPath")
            .unwrap();
        assert_eq!(
            sh_get_known_folder_path.params[3].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::GuestPtr)
        );

        let sh_get_image_list = registry.signature("shell32.dll", "SHGetImageList").unwrap();
        assert_eq!(
            sh_get_image_list.params[2].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::GuestPtr)
        );

        let imalloc_query_interface = registry
            .signature("shell32.dll", "IMalloc_QueryInterface")
            .unwrap();
        assert_eq!(
            imalloc_query_interface.params[2].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::GuestPtr)
        );

        let sh_get_desktop_folder = registry
            .signature("shell32.dll", "SHGetDesktopFolder")
            .unwrap();
        assert_eq!(
            sh_get_desktop_folder.params[0].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::GuestPtr)
        );

        let sh_get_malloc = registry.signature("shell32.dll", "SHGetMalloc").unwrap();
        assert_eq!(
            sh_get_malloc.params[0].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::GuestPtr)
        );

        let sh_get_special_folder_location = registry
            .signature("shell32.dll", "SHGetSpecialFolderLocation")
            .unwrap();
        assert_eq!(
            sh_get_special_folder_location.params[2].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::GuestPtr)
        );

        let sh_create_item_from_parsing_name = registry
            .signature("shell32.dll", "SHCreateItemFromParsingName")
            .unwrap();
        assert_eq!(
            sh_create_item_from_parsing_name.params[3].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::GuestPtr)
        );

        let get_window_thread_process_id = registry
            .signature("user32.dll", "GetWindowThreadProcessId")
            .unwrap();
        assert_eq!(
            get_window_thread_process_id.params[1].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::U32)
        );
    }

    #[test]
    fn api_set_aliases_inherit_refined_pointer_metadata() {
        let mut registry = HookRegistry::for_tests();
        register_api_set_contract_hooks(&mut registry);

        let open_process_token = registry
            .signature("api-ms-win-core-processthreads", "OpenProcessToken")
            .unwrap();
        assert_eq!(
            open_process_token.params[2].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::Handle)
        );

        let get_module_handle_ex = registry
            .signature("api-ms-win-core-libraryloader", "GetModuleHandleExW")
            .unwrap();
        assert_eq!(
            get_module_handle_ex.params[2].ty,
            ParamType::GuestPtrTo(ParamTypeDiscriminant::Handle)
        );
    }

    #[test]
    fn records_requested_and_resolved_identity_per_import_thunk() {
        let mut registry = HookRegistry::for_tests();

        registry.record_import_binding(
            0x401200,
            "sample.exe",
            "api-ms-win-core-libraryloader-l1-2-0.dll",
            "GetProcAddress",
            "kernel32.dll",
            "GetProcAddress",
            0x7712_1000,
        );

        let binding = registry
            .import_binding_for_thunk(0x401200)
            .expect("thunk binding should be recorded");
        assert_eq!(binding.importing_module, "sample.exe");
        assert_eq!(
            binding.requested_module,
            "api-ms-win-core-libraryloader-l1-2-0.dll"
        );
        assert_eq!(binding.requested_function, "GetProcAddress");
        assert_eq!(binding.resolved_module, "kernel32.dll");
        assert_eq!(binding.resolved_function, "GetProcAddress");
        assert_eq!(binding.resolved_address, 0x7712_1000);
    }

    #[test]
    fn canonical_name_lookup_is_stable_across_alias_registrations() {
        let mut registry = HookRegistry::for_tests();
        let guest_address = 0x76A2_1000u64;
        let mapped_address = 0x6B80_1000u64;

        // Register canonical guest-facing address
        registry.bind_real_export_canonical("kernel32.dll", "CreateFileA", guest_address);
        assert_eq!(
            registry.binding_address("kernel32.dll", "CreateFileA"),
            Some(guest_address),
            "canonical should be the guest address"
        );

        // Register mapped address as alias — must NOT change canonical
        registry.bind_real_export_alias("kernel32.dll", "CreateFileA", mapped_address);
        assert_eq!(
            registry.binding_address("kernel32.dll", "CreateFileA"),
            Some(guest_address),
            "canonical must remain stable after alias registration"
        );

        // Both addresses must dispatch to the same hook
        let guest_bound = registry
            .bound_lookup(guest_address)
            .expect("guest address should dispatch");
        let mapped_bound = registry
            .bound_lookup(mapped_address)
            .expect("mapped alias should dispatch");
        assert_eq!(guest_bound.module, mapped_bound.module);
        assert_eq!(guest_bound.function, mapped_bound.function);
    }

    #[test]
    fn alias_registration_does_not_overwrite_canonical() {
        let mut registry = HookRegistry::for_tests();

        // Register canonical, then register multiple aliases
        registry.bind_real_export_canonical("kernel32.dll", "CloseHandle", 0x76A2_2000);
        registry.bind_real_export_alias("kernel32.dll", "CloseHandle", 0x6B80_2000);
        registry.bind_real_export_alias("kernel32.dll", "CloseHandle", 0x1234_5678);

        // Canonical must remain unchanged
        assert_eq!(
            registry.binding_address("kernel32.dll", "CloseHandle"),
            Some(0x76A2_2000)
        );

        // All three addresses dispatch
        assert!(registry.bound_lookup(0x76A2_2000).is_some());
        assert!(registry.bound_lookup(0x6B80_2000).is_some());
        assert!(registry.bound_lookup(0x1234_5678).is_some());
    }

    #[test]
    fn real_export_winexec_resolves_to_registered_signature() {
        let mut registry = HookRegistry::for_tests();
        register_kernel32_hooks(&mut registry);

        registry.bind_real_export_canonical("kernel32.dll", "WinExec", 0x76A2_3000);

        let bound = registry
            .bound_lookup(0x76A2_3000)
            .expect("real export should dispatch");
        let signature = bound.signature.expect("WinExec signature should resolve");
        assert_eq!(bound.module, "kernel32.dll");
        assert_eq!(signature.function, "WinExec");
    }

    #[test]
    fn kernelbase_real_export_reuses_kernel32_winexec_signature() {
        let mut registry = HookRegistry::for_tests();
        register_kernel32_hooks(&mut registry);

        registry.bind_real_export_canonical("kernelbase.dll", "WinExec", 0x6B80_3000);

        let bound = registry
            .bound_lookup(0x6B80_3000)
            .expect("kernelbase alias should dispatch");
        let signature = bound.signature.expect("WinExec signature should resolve");
        assert_eq!(bound.module, "kernelbase.dll");
        assert_eq!(signature.module, "kernel32.dll");
        assert_eq!(signature.function, "WinExec");
    }

    #[test]
    fn samcli_real_export_reuses_netapi32_hook_space() {
        let mut registry = HookRegistry::for_tests();
        register_netapi32_hooks(&mut registry);

        registry.bind_real_export_canonical("samcli.dll", "NetUserAdd", 0x6B80_4000);

        let bound = registry
            .bound_lookup(0x6B80_4000)
            .expect("samcli real export should dispatch");
        let signature = bound
            .signature
            .expect("NetUserAdd signature should resolve");
        assert_eq!(bound.module, "samcli.dll");
        assert_eq!(signature.module, "netapi32.dll");
        assert_eq!(signature.function, "NetUserAdd");
    }

    #[test]
    fn wkscli_real_export_reuses_netapi32_hook_space() {
        let mut registry = HookRegistry::for_tests();
        register_netapi32_hooks(&mut registry);

        registry.bind_real_export_canonical("wkscli.dll", "NetGetJoinInformation", 0x6B80_5000);

        let bound = registry
            .bound_lookup(0x6B80_5000)
            .expect("wkscli real export should dispatch");
        let signature = bound
            .signature
            .expect("NetGetJoinInformation signature should resolve");
        assert_eq!(bound.module, "wkscli.dll");
        assert_eq!(signature.module, "netapi32.dll");
        assert_eq!(signature.function, "NetGetJoinInformation");
    }

    #[test]
    fn observe_real_export_removes_stale_dispatch_binding() {
        let mut registry = HookRegistry::for_tests();
        register_kernel32_hooks(&mut registry);

        registry.bind_real_export_canonical("sample.dll", "RunMe", 0x6B80_1010);
        assert!(
            registry.bound_lookup(0x6B80_1010).is_some(),
            "precondition: stale dispatch binding should exist"
        );

        registry.observe_real_export("sample.dll", "RunMe", 0x6B80_1010);

        assert!(
            registry.bound_lookup(0x6B80_1010).is_none(),
            "observed real exports must not remain hook-dispatchable"
        );
        assert_eq!(registry.binding_address("sample.dll", "RunMe"), None);
        let observed = registry
            .observed_real_export_for_address(0x6B80_1010)
            .expect("observed export should remain queryable");
        assert_eq!(observed.0, "sample.dll");
        assert_eq!(observed.1, "runme");
    }

    #[test]
    fn observed_real_export_rejects_later_real_export_bindings() {
        let mut registry = HookRegistry::for_tests();

        registry.observe_real_export("sample.dll", "RunMe", 0x6B80_1010);
        registry.bind_real_export("sample.dll", "RunMe", 0x6B80_1010);
        registry.bind_real_export_canonical("sample.dll", "RunMe", 0x6B80_1010);
        registry.bind_real_export_alias("sample.dll", "RunMe", 0x6B80_1010);

        assert!(
            registry.bound_lookup(0x6B80_1010).is_none(),
            "later real-export binds must not override observed addresses"
        );
        assert_eq!(registry.binding_address("sample.dll", "RunMe"), None);
        assert!(
            registry
                .observed_real_export_for_address(0x6B80_1010)
                .is_some(),
            "observed export identity should be retained"
        );
    }
}
