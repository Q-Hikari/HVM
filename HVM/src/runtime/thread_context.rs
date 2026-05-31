use std::collections::BTreeMap;

use crate::arch::ArchSpec;
use crate::error::MemoryError;
use crate::memory::manager::MemoryManager;

/// Carries the thread-local layout bases needed by the Windows environment mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadContext {
    pub teb_base: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
}

/// Fixed-size register file replacing `BTreeMap<String, u64>` for thread state.
///
/// Stores all x86 and x64 general-purpose registers plus flags. Architecture-specific
/// serialization picks the relevant subset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegisterFile {
    // x86 GP registers
    pub eax: u64,
    pub ebx: u64,
    pub ecx: u64,
    pub edx: u64,
    pub esi: u64,
    pub edi: u64,
    pub ebp: u64,
    pub esp: u64,
    pub eip: u64,
    pub eflags: u64,
    // x64 GP registers
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl RegisterFile {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads one register by its standard lowercase name.
    pub fn get(&self, name: &str) -> u64 {
        match name {
            "eax" => self.eax,
            "ebx" => self.ebx,
            "ecx" => self.ecx,
            "edx" => self.edx,
            "esi" => self.esi,
            "edi" => self.edi,
            "ebp" => self.ebp,
            "esp" => self.esp,
            "eip" => self.eip,
            "eflags" => self.eflags,
            "rax" => self.rax,
            "rbx" => self.rbx,
            "rcx" => self.rcx,
            "rdx" => self.rdx,
            "rsi" => self.rsi,
            "rdi" => self.rdi,
            "rbp" => self.rbp,
            "rsp" => self.rsp,
            "rip" => self.rip,
            "rflags" => self.rflags,
            "r8" => self.r8,
            "r9" => self.r9,
            "r10" => self.r10,
            "r11" => self.r11,
            "r12" => self.r12,
            "r13" => self.r13,
            "r14" => self.r14,
            "r15" => self.r15,
            _ => 0,
        }
    }

    /// Visits all register name-value pairs, calling `visitor` for each.
    /// Only non-zero values are visited, matching the old BTreeMap behavior.
    pub fn for_each_nonzero(&self, mut visitor: impl FnMut(&'static str, u64)) {
        const NAMES: &[&str] = &[
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags", "rax", "rbx",
            "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "rflags", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ];
        for &name in NAMES {
            let v = self.get(name);
            if v != 0 {
                visitor(name, v);
            }
        }
    }

    /// Writes one register by its standard lowercase name.
    pub fn set(&mut self, name: &str, value: u64) {
        match name {
            "eax" => self.eax = value,
            "ebx" => self.ebx = value,
            "ecx" => self.ecx = value,
            "edx" => self.edx = value,
            "esi" => self.esi = value,
            "edi" => self.edi = value,
            "ebp" => self.ebp = value,
            "esp" => self.esp = value,
            "eip" => self.eip = value,
            "eflags" => self.eflags = value,
            "rax" => self.rax = value,
            "rbx" => self.rbx = value,
            "rcx" => self.rcx = value,
            "rdx" => self.rdx = value,
            "rsi" => self.rsi = value,
            "rdi" => self.rdi = value,
            "rbp" => self.rbp = value,
            "rsp" => self.rsp = value,
            "rip" => self.rip = value,
            "rflags" => self.rflags = value,
            "r8" => self.r8 = value,
            "r9" => self.r9 = value,
            "r10" => self.r10 = value,
            "r11" => self.r11 = value,
            "r12" => self.r12 = value,
            "r13" => self.r13 = value,
            "r14" => self.r14 = value,
            "r15" => self.r15 = value,
            _ => {}
        }
    }
}

const X86_CONTEXT_FIELDS: &[(&str, usize, usize)] = &[
    ("edi", 0x9C, 4),
    ("esi", 0xA0, 4),
    ("ebx", 0xA4, 4),
    ("edx", 0xA8, 4),
    ("ecx", 0xAC, 4),
    ("eax", 0xB0, 4),
    ("ebp", 0xB4, 4),
    ("eip", 0xB8, 4),
    ("eflags", 0xC0, 4),
    ("esp", 0xC4, 4),
];

const X64_CONTEXT_FIELDS: &[(&str, usize, usize)] = &[
    ("rflags", 0x44, 4),
    ("rax", 0x78, 8),
    ("rcx", 0x80, 8),
    ("rdx", 0x88, 8),
    ("rbx", 0x90, 8),
    ("rsp", 0x98, 8),
    ("rbp", 0xA0, 8),
    ("rsi", 0xA8, 8),
    ("rdi", 0xB0, 8),
    ("r8", 0xB8, 8),
    ("r9", 0xC0, 8),
    ("r10", 0xC8, 8),
    ("r11", 0xD0, 8),
    ("r12", 0xD8, 8),
    ("r13", 0xE0, 8),
    ("r14", 0xE8, 8),
    ("r15", 0xF0, 8),
    ("rip", 0xF8, 8),
];

fn context_fields(arch: &'static ArchSpec) -> &'static [(&'static str, usize, usize)] {
    if arch.is_x86() {
        X86_CONTEXT_FIELDS
    } else {
        X64_CONTEXT_FIELDS
    }
}

pub fn serialize_register_context(
    memory: &mut MemoryManager,
    arch: &'static ArchSpec,
    address: u64,
    registers: &RegisterFile,
) -> Result<(), MemoryError> {
    for (name, offset, size) in context_fields(arch) {
        let value = registers.get(name);
        if *size == 4 {
            let bytes = (value as u32).to_le_bytes();
            memory.write(address + *offset as u64, &bytes)?;
        } else {
            let bytes = value.to_le_bytes();
            memory.write(address + *offset as u64, &bytes)?;
        }
    }
    Ok(())
}

pub fn deserialize_register_context(
    memory: &MemoryManager,
    arch: &'static ArchSpec,
    address: u64,
) -> Result<RegisterFile, MemoryError> {
    let mut registers = RegisterFile::new();
    for (name, offset, size) in context_fields(arch) {
        let value = if *size == 4 {
            memory.read_u32(address + *offset as u64)? as u64
        } else {
            u64::from_le_bytes(memory.read_fixed::<8>(address + *offset as u64)?)
        };
        registers.set(name, value);
    }
    Ok(registers)
}

/// Converts a legacy `BTreeMap<String, u64>` into the new `RegisterFile`.
pub fn register_file_from_map(map: &BTreeMap<String, u64>) -> RegisterFile {
    let mut rf = RegisterFile::new();
    for (name, value) in map {
        rf.set(name, *value);
    }
    rf
}

/// Converts a `RegisterFile` into a legacy `BTreeMap<String, u64>`.
pub fn register_file_to_map(rf: &RegisterFile) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    rf.for_each_nonzero(|name, value| {
        map.insert(name.to_string(), value);
    });
    map
}
