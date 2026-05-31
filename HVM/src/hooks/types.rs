/// Logical ABI model that decouples hook signatures from concrete platform ABIs.
///
/// Each variant maps to platform-specific calling conventions at runtime
/// (e.g. `WinApi` → x86 stdcall, x64 Win64, arm64 AAPCS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalAbi {
    /// Windows API default: stdcall on x86, Win64 on x64, AAPCS on arm64.
    WinApi,
    /// Cdecl on x86, platform default on x64/arm64.
    Cdecl,
    /// Variadic CRT functions (printf, sprintf, etc.).
    VariadicCdecl,
    /// Win64-only entry point (rare, for functions that only exist on x64).
    Win64Only,
    /// COM vtable method (implicit `this` as first param).
    ComMethod,
    /// Callback / user-provided function pointer.
    Callback,
    /// Escape hatch for unusual ABIs.
    Custom(&'static str),
}

/// Direction of a parameter's data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamDirection {
    /// Input-only parameter.
    In,
    /// Output-only parameter (written by callee).
    Out,
    /// Input-output parameter (read and written).
    InOut,
}

impl Default for ParamDirection {
    fn default() -> Self {
        Self::In
    }
}

/// Logging/rendering policy for a single parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogPolicy {
    /// Do not render this parameter in logs.
    Skip,
    /// Render using the default format for the parameter type.
    Default,
    /// Render as hexadecimal.
    Hex,
    /// Render with a maximum display length (for strings/buffers).
    Truncate(usize),
    /// Use a custom renderer identified by name.
    Custom(&'static str),
}

impl Default for LogPolicy {
    fn default() -> Self {
        Self::Default
    }
}

/// Per-parameter extension flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamFlags(u8);

impl ParamFlags {
    pub const IS_VARIADIC: u8 = 0x01;
    pub const IS_OPTIONAL: u8 = 0x02;
    pub const IS_COMPOUND: u8 = 0x04;

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    pub fn insert(&mut self, flag: u8) {
        self.0 |= flag;
    }
}

impl Default for ParamFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// Per-hook extension flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookFlags(u8);

impl HookFlags {
    pub const NO_LOG: u8 = 0x01;
    pub const NO_RETURN_LOG: u8 = 0x02;
    pub const VARIADIC: u8 = 0x04;

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    pub fn insert(&mut self, flag: u8) {
        self.0 |= flag;
    }
}

impl Default for HookFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// Typed parameter classification.
///
/// First-pass coverage: scalars, handles, pointers, strings, and common
/// Windows types. Complex structs use `OpaqueStructPtr` initially and
/// will be expanded in later phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    // --- Scalars ---
    Bool32,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    Hex32,
    Hex64,
    SizeT,
    SSizeT,
    /// Unsigned value that is pointer-sized on the target architecture.
    PointerSizedUInt,
    /// Signed value that is pointer-sized on the target architecture.
    PointerSizedInt,

    // --- Handles / Addresses ---
    /// Win32 object handle.
    Handle,
    /// Kernel pseudo-handle (e.g. GetCurrentProcess returns -1).
    PseudoHandle,
    /// Module handle (HMODULE / base address).
    ModuleHandle,
    /// Untyped guest pointer.
    GuestPtr,
    /// Pointer to another value described by the inner type.
    GuestPtrTo(ParamTypeDiscriminant),
    /// Function pointer (opaque).
    FunctionPtr,

    // --- Strings ---
    /// Null-terminated ANSI string (PCSTR / `const char*`).
    PCStr,
    /// Null-terminated wide string (PCWSTR / `const wchar_t*`).
    PCWStr,
    /// Mutable null-terminated ANSI string (PSTR).
    PStr,
    /// Mutable null-terminated wide string (PWSTR).
    PWStr,
    /// FARPROC selector: ANSI export name or 16-bit ordinal.
    ProcName,
    /// Counted ANSI string with length from another parameter.
    CountedAnsi {
        len_param: usize,
        code_page_param: Option<usize>,
    },
    /// Counted wide string with length from another parameter.
    CountedWide {
        len_param: usize,
    },

    // --- Buffers ---
    /// Input buffer with length from another parameter.
    Buffer {
        len_param: usize,
    },
    /// Output buffer with length from another parameter.
    OutBuffer {
        len_param: usize,
    },
    /// Byte slice with length from another parameter.
    ByteSlice {
        len_param: usize,
    },
    /// Wide buffer with element count from another parameter.
    WideBuffer {
        len_param: usize,
    },

    // --- Common Windows structures ---
    /// Pointer to a GUID/IID/CLSID.
    GuidPtr,
    /// Pointer to a SID.
    SidPtr,
    /// Pointer to SECURITY_ATTRIBUTES.
    SecurityAttributesPtr,
    /// Pointer to STARTUPINFO(A/W).
    StartupInfoPtr,
    /// Pointer to PROCESS_INFORMATION.
    ProcessInformationPtr,
    /// Pointer to OVERLAPPED.
    OverlappedPtr,
    /// Pointer to FILETIME.
    FileTimePtr,
    /// Pointer to SYSTEMTIME.
    SystemTimePtr,

    // --- Opaque / Escape ---
    /// Opaque struct pointer — display address only.
    OpaqueStructPtr(&'static str),
    /// ANSI_STRING / STRING struct (ntdll).
    AnsiStringStruct,
    /// UNICODE_STRING struct (ntdll).
    UnicodeStringStruct,
}

/// Lightweight discriminant for `ParamType` used in `GuestPtrTo`.
///
/// Stores only the enum discriminant so `ParamType` remains `Copy`.
/// Full inner-type information is recovered at decode time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamTypeDiscriminant {
    U16,
    U32,
    I32,
    Handle,
    GuestPtr,
    GuidPtr,
    Void,
}

/// Identifies the variadic argument decoding strategy for functions with
/// variable-length argument lists (e.g. printf, sprintf, wsprintf).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariadicDecoderKind {
    /// printf-style: format string is ANSI, variadic args follow on stack/registers.
    PrintfStyle,
    /// wprintf-style: format string is wide (wchar_t*), variadic args follow.
    WprintfStyle,
    /// sprintf-style: like printf but with output buffer as first arg.
    SprintfStyle,
    /// swprintf-style: like wprintf but with output buffer as first arg.
    SwprintfStyle,
    /// wsprintfA-style: Windows wsprintf with ANSI format.
    WsprintfAStyle,
    /// wsprintfW-style: Windows wsprintf with wide format.
    WsprintfWStyle,
    /// FormatMessage-style: special dwFlags-based format string resolution.
    FormatMessageStyle,
    /// Custom decoder identified by name.
    Custom(&'static str),
}
