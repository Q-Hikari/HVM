use std::collections::HashMap;

use crate::hooks::base::{CallConv, HookDefinition, HookLibrary};
use crate::memory::manager::MemoryManager;
use crate::models::ModuleRecord;

const SYNTHETIC_EXPORT_SECTION_RVA: u32 = 0x1000;
const SYNTHETIC_EXPORT_DIRECTORY_RVA: u32 = SYNTHETIC_EXPORT_SECTION_RVA;
const SYNTHETIC_EXPORT_ADDRESS_TABLE_RVA: u32 = SYNTHETIC_EXPORT_DIRECTORY_RVA + 0x40;
pub(crate) const SYNTHETIC_TEXT_RVA: u64 = 0x8000;
pub(crate) const SYNTHETIC_STUB_RVA_START: u64 = 0xA000;
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

/// Stores synthetic export bindings for DLL hook dispatch.
#[derive(Debug, Default)]
pub struct HookRegistry {
    next_stub: u64,
    definitions: HashMap<(String, String), HookDefinition>,
    bindings_by_name: HashMap<(String, String), u64>,
    bindings_by_address: HashMap<u64, (String, String)>,
}

#[derive(Debug, Clone, Copy)]
pub struct BoundHookLookup<'a> {
    pub module: &'a str,
    pub function: &'a str,
    pub definition: Option<&'a HookDefinition>,
}

impl HookRegistry {
    /// Builds a test-friendly empty hook registry.
    pub fn for_tests() -> Self {
        Self {
            next_stub: 0x1000_0000,
            definitions: HashMap::new(),
            bindings_by_name: HashMap::new(),
            bindings_by_address: HashMap::new(),
        }
    }

    /// Registers all definitions provided by one hook library.
    pub fn register_library(&mut self, library: &dyn HookLibrary) {
        for definition in library.collect() {
            let key = normalized_key(definition.module, definition.function);
            self.definitions.insert(key, definition);
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

    /// Binds one synthetic export inside the owning module so `GetProcAddress` matches Python.
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
            self.bindings_by_address.insert(*existing, key.clone());
            self.bindings_by_name.insert(key, *existing);
            return *existing;
        }

        let stub = module.base + module.stub_cursor;
        module.stub_cursor += 0x10;
        let _ = memory.write(stub, &SYNTHETIC_STUB_BYTES);
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

    /// Returns the already-bound synthetic stub address for one module and function name.
    pub fn binding_address(&self, module: &str, function: &str) -> Option<u64> {
        self.bindings_by_name
            .get(&normalized_key(module, function))
            .copied()
    }

    /// Returns the registered definition for one already-bound stub address.
    pub fn definition_for_address(&self, address: u64) -> Option<&HookDefinition> {
        let key = self.bindings_by_address.get(&address)?;
        self.definition_from_key(key)
    }

    /// Returns one bound-hook lookup without paying for multiple address lookups.
    pub fn bound_lookup(&self, address: u64) -> Option<BoundHookLookup<'_>> {
        let (module, function) = self.bindings_by_address.get(&address)?;
        Some(BoundHookLookup {
            module,
            function,
            definition: self.definition_from_parts(module, function),
        })
    }

    /// Returns the normalized module/function pair bound at one synthetic stub address.
    pub fn binding_for_address(&self, address: u64) -> Option<(&str, &str)> {
        let (module, function) = self.bindings_by_address.get(&address)?;
        Some((module.as_str(), function.as_str()))
    }

    /// Returns whether the address is one previously bound synthetic stub.
    pub fn is_bound_address(&self, address: u64) -> bool {
        self.bindings_by_address.contains_key(&address)
    }

    /// Returns all currently bound synthetic stub addresses.
    pub fn bound_addresses(&self) -> Vec<u64> {
        self.bindings_by_address.keys().copied().collect()
    }

    /// Returns the registered definition for one hook if present.
    pub fn definition(&self, module: &str, function: &str) -> Option<&HookDefinition> {
        let key = normalized_key(module, function);
        self.definition_from_key(&key)
    }

    /// Returns all registered hook definitions for one module in deterministic name order.
    pub fn definitions_for_module(&self, module: &str) -> Vec<HookDefinition> {
        let mut definitions = self
            .definitions
            .values()
            .filter(|definition| definition.module.eq_ignore_ascii_case(module))
            .cloned()
            .collect::<Vec<_>>();
        definitions.sort_by(|left, right| {
            left.function
                .cmp(right.function)
                .then_with(|| left.argc.cmp(&right.argc))
        });
        definitions
    }

    fn definition_from_key(&self, key: &(String, String)) -> Option<&HookDefinition> {
        self.definition_from_parts(&key.0, &key.1)
    }

    fn definition_from_parts(&self, module: &str, function: &str) -> Option<&HookDefinition> {
        if let Some(definition) = self
            .definitions
            .get(&(module.to_ascii_lowercase(), function.to_ascii_lowercase()))
        {
            return Some(definition);
        }

        let alias = aliased_host_module(module)?;
        self.definitions
            .get(&(alias.to_string(), function.to_ascii_lowercase()))
    }
}

pub(crate) fn initialize_synthetic_module_image(module: &ModuleRecord, memory: &mut MemoryManager) {
    write_synthetic_pe_headers(module, memory, 0, synthetic_active_image_size(module));

    let export_fill = vec![0u8; synthetic_export_section_capacity() as usize];
    let _ = memory.write(
        module.base + SYNTHETIC_EXPORT_SECTION_RVA as u64,
        &export_fill,
    );
    let text_fill = vec![0u8; (SYNTHETIC_STUB_RVA_START - SYNTHETIC_TEXT_RVA) as usize];
    let _ = memory.write(module.base + SYNTHETIC_TEXT_RVA, &text_fill);
    refresh_synthetic_export_image(module, memory);
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
    let _ = memory.write(module.base, &headers);
}

fn refresh_synthetic_export_image(module: &ModuleRecord, memory: &mut MemoryManager) {
    let export_fill = vec![0u8; synthetic_export_section_capacity() as usize];
    let _ = memory.write(
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
    let _ = memory.write(module.base + SYNTHETIC_EXPORT_SECTION_RVA as u64, &blob);
    write_synthetic_pe_headers(
        module,
        memory,
        export_directory_size,
        synthetic_active_image_size(module),
    );
}

fn align_u32(value: u32, alignment: u32) -> u32 {
    if alignment <= 1 {
        return value;
    }
    let mask = alignment - 1;
    value.saturating_add(mask) & !mask
}

fn normalized_key(module: &str, function: &str) -> (String, String) {
    (module.to_ascii_lowercase(), function.to_ascii_lowercase())
}

fn aliased_host_module(module: &str) -> Option<&'static str> {
    if module.starts_with("api-ms-win-core-") || module.starts_with("ext-ms-win-") {
        Some("kernel32.dll")
    } else if module.starts_with("api-ms-win-crt-")
        || module.eq_ignore_ascii_case("ucrtbase.dll")
        || module.eq_ignore_ascii_case("vcruntime140.dll")
        || module.eq_ignore_ascii_case("vcruntime140_1.dll")
    {
        Some("msvcrt.dll")
    } else {
        None
    }
}

impl HookDefinition {
    /// Builds a default synthetic definition when no more specific metadata is available yet.
    pub fn synthetic(module: &'static str, function: &'static str) -> Self {
        Self {
            module,
            function,
            argc: 0,
            call_conv: CallConv::Stdcall,
        }
    }
}
