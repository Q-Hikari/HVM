use crate::arch::ArchSpec;
use crate::hooks::signature::ReturnSpec;

/// Semantic return value from a hook handler.
///
/// Each variant carries the meaning of the return value so that the
/// dispatch layer can automatically apply architecture-specific encoding
/// (pointer truncation, sign extension, handle widening, etc.).
///
/// Existing hooks that return a plain `u64` continue to work via the
/// `From<u64>` impl — they are treated as `Raw` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookValue {
    /// No return value (void function).
    Void,
    /// Raw `u64` — written as-is, no adjustment.
    Raw(u64),
    /// Unsigned 32-bit value, zero-extended.
    U32(u32),
    /// Signed 32-bit value, sign-extended on x64.
    I32(i32),
    /// Guest pointer — truncated to 32-bit on x86.
    Ptr(u64),
    /// Win32 HANDLE — sign-extended for pseudo-handles on x64.
    Handle(u64),
    /// `INVALID_HANDLE_VALUE` (`-1`) — auto-sized per architecture.
    #[allow(dead_code)]
    InvalidHandle,
    /// NTSTATUS error code (u32).
    NtStatus(u32),
    /// Win32 error code (u32).
    Win32Error(u32),
}

#[allow(dead_code)]
impl HookValue {
    /// Wraps a raw `u64` without any architecture adjustment.
    pub fn raw(value: u64) -> Self {
        Self::Raw(value)
    }

    /// Wraps a `bool` as `0` or `1`.
    pub fn from_bool(value: bool) -> Self {
        Self::Raw(value as u64)
    }

    /// Wraps a Win32 `BOOL` (any non-zero = `TRUE`).
    pub fn win32_bool(value: bool) -> Self {
        Self::Raw(value as u64)
    }

    /// Wraps a Win32 error code (`u32` — fits unchanged in both archs).
    pub fn win32_error(code: u32) -> Self {
        Self::Win32Error(code)
    }

    /// Wraps an NTSTATUS value (`u32` — fits unchanged in both archs).
    pub fn ntstatus(status: u32) -> Self {
        Self::NtStatus(status)
    }

    /// Wraps a pointer-sized value, truncating to 32-bit for x86 guests.
    pub fn ptr(value: u64, arch: &ArchSpec) -> Self {
        if arch.is_x86() {
            Self::Ptr(value as u32 as u64)
        } else {
            Self::Ptr(value)
        }
    }

    /// Wraps a Win32 `HANDLE` with proper sign-extension for x64.
    ///
    /// Kernel pseudo-handles (e.g. `GetCurrentProcess()` returns `-1`)
    /// have bit 31 set and must be sign-extended to 64 bits on x64.
    pub fn handle(value: u64, arch: &ArchSpec) -> Self {
        let lower = value & 0xFFFF_FFFF;
        if arch.is_x86() || lower & 0x8000_0000 == 0 {
            Self::Handle(lower)
        } else {
            Self::Handle(lower | 0xFFFF_FFFF_0000_0000)
        }
    }

    /// Returns `INVALID_HANDLE_VALUE` (`-1`) for the current architecture.
    ///
    /// x86: `0xFFFFFFFF`, x64: `0xFFFFFFFFFFFFFFFF`.
    pub fn invalid_handle(arch: &ArchSpec) -> Self {
        if arch.is_x86() {
            Self::InvalidHandle
        } else {
            Self::InvalidHandle
        }
    }

    /// Wraps a signed `i32` value, sign-extending to 64-bit on x64.
    pub fn i32_value(value: i32, arch: &ArchSpec) -> Self {
        if arch.is_x86() {
            Self::I32(value)
        } else {
            Self::I32(value)
        }
    }

    /// Creates a semantic `HookValue` from a raw `u64` return value and the
    /// `ReturnSpec` from the hook's signature.
    ///
    /// This is the dispatch-layer mechanism: the handler returns a plain `u64`,
    /// and this method interprets it according to the declared return semantics.
    pub fn from_raw_with_spec(raw: u64, spec: ReturnSpec, arch: &ArchSpec) -> Self {
        match spec {
            ReturnSpec::Void => Self::Void,
            ReturnSpec::Bool32 => Self::Raw(raw),
            ReturnSpec::I32 => Self::I32(raw as u32 as i32),
            ReturnSpec::U32 | ReturnSpec::U16 => Self::U32(raw as u32),
            ReturnSpec::I64 => Self::Raw(raw),
            ReturnSpec::U64 => Self::Raw(raw),
            ReturnSpec::NtStatus => Self::NtStatus(raw as u32),
            ReturnSpec::Win32Error => Self::Win32Error(raw as u32),
            ReturnSpec::Handle => {
                let lower = raw & 0xFFFF_FFFF;
                if arch.is_x86() || lower & 0x8000_0000 == 0 {
                    Self::Handle(lower)
                } else {
                    Self::Handle(lower | 0xFFFF_FFFF_0000_0000)
                }
            }
            ReturnSpec::ModuleHandle | ReturnSpec::Pointer => {
                if arch.is_x86() {
                    Self::Ptr(raw as u32 as u64)
                } else {
                    Self::Ptr(raw)
                }
            }
            ReturnSpec::PointerSizedUInt | ReturnSpec::PointerSizedInt => Self::Raw(raw),
        }
    }

    /// Encodes the semantic value into the raw `u64` to write to the
    /// return register (EAX/RAX), applying architecture-specific rules.
    pub fn into_raw(self, arch: &ArchSpec) -> u64 {
        match self {
            Self::Void => 0,
            Self::Raw(v) => v,
            Self::U32(v) => v as u64,
            Self::I32(v) => {
                if arch.is_x86() {
                    v as u32 as u64
                } else {
                    v as i64 as u64
                }
            }
            Self::Ptr(v) => {
                if arch.is_x86() {
                    v as u32 as u64
                } else {
                    v
                }
            }
            Self::Handle(v) => {
                let lower = v & 0xFFFF_FFFF;
                if arch.is_x86() || lower & 0x8000_0000 == 0 {
                    lower
                } else {
                    lower | 0xFFFF_FFFF_0000_0000
                }
            }
            Self::InvalidHandle => {
                if arch.is_x86() {
                    0xFFFF_FFFF
                } else {
                    0xFFFF_FFFF_FFFF_FFFF
                }
            }
            Self::NtStatus(v) => v as u64,
            Self::Win32Error(v) => v as u64,
        }
    }

    /// Backward-compatible extraction: returns the raw `u64` assuming x64
    /// encoding (no truncation). Existing code that does not pass an
    /// `ArchSpec` should migrate to `into_raw(arch)`.
    #[allow(dead_code)]
    pub fn into_raw_u64(self) -> u64 {
        match self {
            Self::Void => 0,
            Self::Raw(v) => v,
            Self::U32(v) => v as u64,
            Self::I32(v) => v as i64 as u64,
            Self::Ptr(v) => v,
            Self::Handle(v) => {
                let lower = v & 0xFFFF_FFFF;
                if lower & 0x8000_0000 == 0 {
                    lower
                } else {
                    lower | 0xFFFF_FFFF_0000_0000
                }
            }
            Self::InvalidHandle => 0xFFFF_FFFF_FFFF_FFFF,
            Self::NtStatus(v) => v as u64,
            Self::Win32Error(v) => v as u64,
        }
    }
}

// -- Backward-compatible conversions ----------------------------------

impl From<u64> for HookValue {
    fn from(value: u64) -> Self {
        Self::Raw(value)
    }
}

impl From<u32> for HookValue {
    fn from(value: u32) -> Self {
        Self::U32(value)
    }
}

impl From<i32> for HookValue {
    fn from(value: i32) -> Self {
        Self::I32(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::X64_ARCH;

    #[test]
    fn module_handle_does_not_sign_extend_on_x64() {
        let arch = X64_ARCH;
        let raw = 0x0000_0000_B408_3000u64;
        let value = HookValue::from_raw_with_spec(raw, ReturnSpec::ModuleHandle, &arch);
        assert_eq!(value.into_raw(&arch), raw);
    }

    #[test]
    fn kernel_handle_still_sign_extends_on_x64() {
        let arch = X64_ARCH;
        let raw = 0x0000_0000_FFFF_FFF6u64;
        let value = HookValue::from_raw_with_spec(raw, ReturnSpec::Handle, &arch);
        assert_eq!(value.into_raw(&arch), 0xFFFF_FFFF_FFFF_FFF6u64);
    }
}
