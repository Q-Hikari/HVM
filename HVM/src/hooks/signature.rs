use super::types::{
    HookFlags, LogPolicy, LogicalAbi, ParamDirection, ParamFlags, ParamType, VariadicDecoderKind,
};

/// Describes one hook parameter: name, type, direction, logging, and flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSpec {
    pub name: &'static str,
    pub ty: ParamType,
    pub dir: ParamDirection,
    pub log: LogPolicy,
    pub flags: ParamFlags,
}

impl ParamSpec {
    /// Convenience constructor for a simple input parameter.
    pub const fn new(name: &'static str, ty: ParamType) -> Self {
        Self {
            name,
            ty,
            dir: ParamDirection::In,
            log: LogPolicy::Default,
            flags: ParamFlags::empty(),
        }
    }

    /// Constructor with explicit direction.
    pub const fn with_dir(name: &'static str, ty: ParamType, dir: ParamDirection) -> Self {
        Self {
            name,
            ty,
            dir,
            log: LogPolicy::Default,
            flags: ParamFlags::empty(),
        }
    }

    /// Constructor with explicit log policy.
    pub const fn with_log(name: &'static str, ty: ParamType, log: LogPolicy) -> Self {
        Self {
            name,
            ty,
            dir: ParamDirection::In,
            log,
            flags: ParamFlags::empty(),
        }
    }
}

/// Describes the return value semantics of a hook.
///
/// This drives automatic width adaptation (pointer truncation, sign extension,
/// invalid-handle encoding) across x86/x64/arm64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnSpec {
    /// No return value (void function).
    Void,
    /// Win32 BOOL (0 / non-zero).
    Bool32,
    /// Signed 32-bit integer, sign-extended on x64.
    I32,
    /// Unsigned 32-bit integer, zero-extended.
    U32,
    /// Unsigned 16-bit integer, zero-extended.
    U16,
    /// Signed 64-bit integer.
    I64,
    /// Unsigned 64-bit integer.
    U64,
    /// NTSTATUS (u32 error code).
    NtStatus,
    /// Win32 error code (u32).
    Win32Error,
    /// Win32 HANDLE — sign-extended for pseudo-handles on x64.
    Handle,
    /// Module handle / image base (HMODULE / HINSTANCE) — pointer semantics.
    ModuleHandle,
    /// Pointer — truncated to 32-bit on x86.
    Pointer,
    /// Unsigned pointer-sized integer.
    PointerSizedUInt,
    /// Signed pointer-sized integer.
    PointerSizedInt,
}

impl Default for ReturnSpec {
    fn default() -> Self {
        Self::U32
    }
}

/// Complete static signature for one hook.
///
/// This is the **single source of truth** for a hook's metadata:
/// module, function name, ABI, parameter types, return type, and flags.
/// The dispatch layer, logging layer, and typed decoders all consume
/// this one structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookSignature {
    pub module: &'static str,
    pub function: &'static str,
    pub abi: LogicalAbi,
    pub params: &'static [ParamSpec],
    pub ret: ReturnSpec,
    pub flags: HookFlags,
}

impl HookSignature {
    /// Returns the number of declared parameters.
    pub fn argc(&self) -> usize {
        self.params.len()
    }
}

/// Describes the parameter list structure of a hook.
///
/// Most hooks have a fixed parameter list, but variadic functions (printf, sprintf, etc.)
/// have a fixed prefix followed by format-driven variadic arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamListKind {
    /// Fixed parameter list — all parameters are statically known.
    Fixed(&'static [ParamSpec]),
    /// Variadic parameter list — fixed prefix + format-driven variable tail.
    Variadic {
        /// The fixed (non-variadic) parameters before the format-driven tail.
        fixed: &'static [ParamSpec],
        /// How to decode the variadic tail.
        decoder: VariadicDecoderKind,
    },
}
