/// The 32-bit PE machine identifier used by the Python baseline.
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x14C;

/// The 64-bit PE machine identifier used by the Python baseline.
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// Captures the architecture-specific layout and ABI values the runtime needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchSpec {
    pub name: &'static str,
    pub bits: u8,
    pub pointer_size: usize,
    pub stack_base: u64,
    pub stack_size: u64,
    pub alloc_base: u64,
}

impl ArchSpec {
    pub fn is_x86(self) -> bool {
        self.bits == 32
    }

    pub fn is_x64(self) -> bool {
        self.bits == 64
    }
}

pub const X86_ARCH: ArchSpec = ArchSpec {
    name: "x86",
    bits: 32,
    pointer_size: 4,
    stack_base: 0x7020_0000,
    stack_size: 0x20_0000,
    alloc_base: 0x5000_0000,
};

pub const X64_ARCH: ArchSpec = ArchSpec {
    name: "x64",
    bits: 64,
    pointer_size: 8,
    stack_base: 0x0000_7FF0_0000_0000,
    stack_size: 0x40_0000,
    alloc_base: 0x0000_7FF6_0000_0000,
};

/// Converts a PE machine identifier into the Python-compatible architecture name.
pub fn arch_name(machine: u16) -> Option<&'static str> {
    arch_spec(machine).map(|arch| arch.name)
}

/// Returns the runtime architecture descriptor for a PE machine identifier.
pub fn arch_spec(machine: u16) -> Option<&'static ArchSpec> {
    match machine {
        IMAGE_FILE_MACHINE_I386 => Some(&X86_ARCH),
        IMAGE_FILE_MACHINE_AMD64 => Some(&X64_ARCH),
        _ => None,
    }
}

/// Returns one runtime architecture descriptor from a normalized architecture name.
pub fn arch_spec_from_name(name: &str) -> Option<&'static ArchSpec> {
    match name {
        "x86" => Some(&X86_ARCH),
        "x64" => Some(&X64_ARCH),
        _ => None,
    }
}
