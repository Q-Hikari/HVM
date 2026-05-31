use crate::hooks::registry::HookRegistry;
use crate::hooks::signature::{HookSignature, ParamSpec, ReturnSpec};
use crate::hooks::types::{
    HookFlags, LogicalAbi, ParamDirection::Out, ParamType::*, ParamTypeDiscriminant,
};

/// COM vtable dispatch hooks. These are synthetic hook addresses placed in
/// COM object vtables. When the emulated code calls through the vtable,
/// the engine dispatches to `dispatch_com_method` in `common.rs`.
///
/// All COM methods on x86 use stdcall (callee cleans the stack). Each
/// method must have the exact correct argument count, otherwise the stack
/// is corrupted and the caller crashes.
#[allow(dead_code)]
const STDCALL_EXPORTS: &[(&str, usize)] = &[
    // IUnknown
    ("QueryInterface", 3), // this, riid, ppvObject
    ("AddRef", 1),         // this
    ("Release", 1),        // this
    // IDispatch
    ("GetTypeInfoCount", 2), // this, pctinfo
    ("GetTypeInfo", 4),      // this, iTInfo, lcid, ppTInfo
    ("GetIDsOfNames", 6),    // this, riid, rgszNames, cNames, lcid, rgDispId
    ("Invoke", 9),           // this, dispidMember, riid, lcid, wFlags,
    //   pdispparams, pvarResult, pexcepinfo, puArgErr
    // IShellWindows (inherits IDispatch)
    ("ShellWindows_get_Count", 2), // this, long *pCount
    ("ShellWindows_Item", 3),      // this, VARIANT index, IDispatch **ppDisp
    ("ShellWindows__NewEnum", 2),  // this, IUnknown **ppEnum
    // IEnumUnknown (returned by _NewEnum)
    ("IEnumUnknown_Next", 4),  // this, celt, rgelt, pceltFetched
    ("IEnumUnknown_Skip", 2),  // this, celt
    ("IEnumUnknown_Reset", 1), // this
    ("IEnumUnknown_Clone", 2), // this, IEnumUnknown **ppenum
    // IWebBrowser / IWebBrowser2 / IShellBrowser (used by elevated COM)
    ("ShellBrowser_get_Document", 2),    // this, IDispatch **ppDisp
    ("ShellBrowser_Navigate", 2),        // this, BSTR url
    ("ShellBrowser_get_Application", 2), // this, IDispatch **ppDisp
    ("ShellBrowser_get_Parent", 2),      // this, IDispatch **ppDisp
    ("ShellBrowser_get_Count", 2),       // this, long *pCount
    ("ShellBrowser_Item", 3),            // this, VARIANT, IDispatch**
    ("ShellBrowser__NewEnum", 2),        // this, IUnknown**
    // Generic catch-all for unknown vtable methods
    ("ComMethodExtra2", 2),
    ("ComMethodExtra3", 3),
    ("ComMethodExtra6", 6),
];

// Synthetic COM vtable stubs must carry the real COM method arity.
// On x86 the interpreter captures `signature.params.len()` stack arguments
// and uses the same count for stdcall cleanup. Empty stub signatures will
// dispatch but corrupt the call frame.
static SIGNATURES: &[HookSignature] = &[
    HookSignature {
        module: "com_dispatch.dll",
        function: "QueryInterface",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::with_dir(
                "ppvObject",
                GuestPtrTo(ParamTypeDiscriminant::GuestPtr),
                Out,
            ),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "AddRef",
        abi: LogicalAbi::ComMethod,
        params: &[ParamSpec::new("this", GuestPtr)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "Release",
        abi: LogicalAbi::ComMethod,
        params: &[ParamSpec::new("this", GuestPtr)],
        ret: ReturnSpec::U32,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "GetTypeInfoCount",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::with_dir("pctinfo", GuestPtrTo(ParamTypeDiscriminant::U32), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "GetTypeInfo",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("iTInfo", U32),
            ParamSpec::new("lcid", U32),
            ParamSpec::with_dir("ppTInfo", GuestPtrTo(ParamTypeDiscriminant::GuestPtr), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "GetIDsOfNames",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::new("rgszNames", GuestPtr),
            ParamSpec::new("cNames", U32),
            ParamSpec::new("lcid", U32),
            ParamSpec::with_dir("rgDispId", GuestPtrTo(ParamTypeDiscriminant::U32), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "Invoke",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("dispidMember", I32),
            ParamSpec::new("riid", GuidPtr),
            ParamSpec::new("lcid", U32),
            ParamSpec::new("wFlags", U16),
            ParamSpec::new("pDispParams", OpaqueStructPtr("DISPPARAMS")),
            ParamSpec::with_dir("pVarResult", OpaqueStructPtr("VARIANT"), Out),
            ParamSpec::with_dir("pExcepInfo", OpaqueStructPtr("EXCEPINFO"), Out),
            ParamSpec::with_dir("puArgErr", GuestPtrTo(ParamTypeDiscriminant::U32), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ShellWindows_get_Count",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::with_dir("pCount", GuestPtrTo(ParamTypeDiscriminant::I32), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ShellWindows_Item",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("index", OpaqueStructPtr("VARIANT")),
            ParamSpec::with_dir("ppDisp", GuestPtrTo(ParamTypeDiscriminant::GuestPtr), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ShellWindows__NewEnum",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::with_dir("ppEnum", GuestPtrTo(ParamTypeDiscriminant::GuestPtr), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "IEnumUnknown_Next",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("celt", U32),
            ParamSpec::new("rgelt", GuestPtr),
            ParamSpec::with_dir("pceltFetched", GuestPtrTo(ParamTypeDiscriminant::U32), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "IEnumUnknown_Skip",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("celt", U32),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "IEnumUnknown_Reset",
        abi: LogicalAbi::ComMethod,
        params: &[ParamSpec::new("this", GuestPtr)],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "IEnumUnknown_Clone",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::with_dir("ppenum", GuestPtrTo(ParamTypeDiscriminant::GuestPtr), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ShellBrowser_get_Document",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::with_dir("ppDisp", GuestPtrTo(ParamTypeDiscriminant::GuestPtr), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ShellBrowser_Navigate",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("url", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ShellBrowser_get_Application",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::with_dir("ppDisp", GuestPtrTo(ParamTypeDiscriminant::GuestPtr), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ShellBrowser_get_Parent",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::with_dir("ppDisp", GuestPtrTo(ParamTypeDiscriminant::GuestPtr), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ShellBrowser_get_Count",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::with_dir("pCount", GuestPtrTo(ParamTypeDiscriminant::I32), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ShellBrowser_Item",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("index", OpaqueStructPtr("VARIANT")),
            ParamSpec::with_dir("ppDisp", GuestPtrTo(ParamTypeDiscriminant::GuestPtr), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ShellBrowser__NewEnum",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::with_dir("ppEnum", GuestPtrTo(ParamTypeDiscriminant::GuestPtr), Out),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ComMethodExtra2",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("arg1", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ComMethodExtra3",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("arg1", GuestPtr),
            ParamSpec::new("arg2", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
    HookSignature {
        module: "com_dispatch.dll",
        function: "ComMethodExtra6",
        abi: LogicalAbi::ComMethod,
        params: &[
            ParamSpec::new("this", GuestPtr),
            ParamSpec::new("arg1", GuestPtr),
            ParamSpec::new("arg2", GuestPtr),
            ParamSpec::new("arg3", GuestPtr),
            ParamSpec::new("arg4", GuestPtr),
            ParamSpec::new("arg5", GuestPtr),
        ],
        ret: ReturnSpec::Win32Error,
        flags: HookFlags::empty(),
    },
];

pub fn register_com_dispatch_hooks(registry: &mut HookRegistry) {
    registry.register_signatures(SIGNATURES);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_com_dispatch_vtable_methods() {
        let mut registry = HookRegistry::for_tests();
        register_com_dispatch_hooks(&mut registry);

        for (function, argc) in STDCALL_EXPORTS {
            let sig = registry
                .signature("com_dispatch.dll", function)
                .unwrap_or_else(|| panic!("missing com_dispatch signature for {function}"));
            assert_eq!(sig.abi, LogicalAbi::ComMethod);
            assert_eq!(sig.argc(), *argc, "wrong argc for {function}");
        }
    }
}
