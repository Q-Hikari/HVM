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
    registers: &BTreeMap<String, u64>,
) -> Result<(), MemoryError> {
    for (name, offset, size) in context_fields(arch) {
        let value = registers.get(*name).copied().unwrap_or(0);
        let bytes = if *size == 4 {
            (value as u32).to_le_bytes().to_vec()
        } else {
            value.to_le_bytes().to_vec()
        };
        memory.write(address + *offset as u64, &bytes[..*size])?;
    }
    Ok(())
}

pub fn deserialize_register_context(
    memory: &MemoryManager,
    arch: &'static ArchSpec,
    address: u64,
) -> Result<BTreeMap<String, u64>, MemoryError> {
    let mut registers = BTreeMap::new();
    for (name, offset, size) in context_fields(arch) {
        let value = if *size == 4 {
            memory.read_u32(address + *offset as u64)? as u64
        } else {
            u64::from_le_bytes(memory.read_fixed::<8>(address + *offset as u64)?)
        };
        registers.insert((*name).to_string(), value);
    }
    Ok(registers)
}
