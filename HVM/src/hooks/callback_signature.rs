use super::signature::{ParamSpec, ReturnSpec};
use super::types::{LogicalAbi, ParamType, ParamTypeDiscriminant};

/// Static signature for a callback function pointer.
///
/// Used by the ABI adapter's `prepare_callback_frame()` to set up
/// the correct call frame when invoking a guest callback.
///
/// Unlike `HookSignature`, callbacks have no `module` or `function` name
/// — they are identified by their address in guest memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackSignature {
    /// Logical ABI for the callback.
    pub abi: LogicalAbi,
    /// Parameter specifications.
    pub params: &'static [ParamSpec],
    /// Return value semantics.
    pub ret: ReturnSpec,
}

/// BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
pub static ENUM_WINDOWS_CALLBACK: CallbackSignature = CallbackSignature {
    abi: LogicalAbi::Callback,
    params: &[
        ParamSpec::new("hwnd", ParamType::Handle),
        ParamSpec::new("lParam", ParamType::PointerSizedUInt),
    ],
    ret: ReturnSpec::Bool32,
};

/// LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
pub static WNDPROC_CALLBACK: CallbackSignature = CallbackSignature {
    abi: LogicalAbi::Callback,
    params: &[
        ParamSpec::new("hwnd", ParamType::Handle),
        ParamSpec::new("msg", ParamType::U32),
        ParamSpec::new("wParam", ParamType::PointerSizedUInt),
        ParamSpec::new("lParam", ParamType::PointerSizedUInt),
    ],
    ret: ReturnSpec::PointerSizedInt,
};

/// VOID CALLBACK TimerProc(HWND hwnd, UINT msg, UINT_PTR idTimer, DWORD dwTime)
pub static TIMERPROC_CALLBACK: CallbackSignature = CallbackSignature {
    abi: LogicalAbi::Callback,
    params: &[
        ParamSpec::new("hwnd", ParamType::Handle),
        ParamSpec::new("msg", ParamType::U32),
        ParamSpec::new("idTimer", ParamType::PointerSizedUInt),
        ParamSpec::new("dwTime", ParamType::U32),
    ],
    ret: ReturnSpec::Void,
};

/// void _initterm_fn(void) -- zero-arg CRT init function
pub static INITTERM_CALLBACK: CallbackSignature = CallbackSignature {
    abi: LogicalAbi::Callback,
    params: &[],
    ret: ReturnSpec::Void,
};

/// VOID CALLBACK LdrEnumCallback(PLDR_DATA_TABLE_ENTRY Module, PVOID Context, BOOLEAN *Stop)
pub static LDR_ENUM_CALLBACK: CallbackSignature = CallbackSignature {
    abi: LogicalAbi::Callback,
    params: &[
        ParamSpec::new("Module", ParamType::GuestPtr),
        ParamSpec::new("Context", ParamType::GuestPtr),
        ParamSpec::new("Stop", ParamType::GuestPtrTo(ParamTypeDiscriminant::Void)),
    ],
    ret: ReturnSpec::Void,
};
