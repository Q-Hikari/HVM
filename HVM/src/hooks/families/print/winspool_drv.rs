use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "winspool.dll",
        "OpenPrinterA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "OpenPrinterW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "ClosePrinter",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "GetDefaultPrinterA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "GetDefaultPrinterW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "StartDocPrinterA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "StartDocPrinterW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "EndDocPrinter",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "AbortPrinter",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "StartPagePrinter",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "EndPagePrinter",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "WritePrinter",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "EnumPrintersA",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "EnumPrintersW",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.dll",
        "DocumentPropertiesW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinspoolDrvHookLibrary;

impl HookLibrary for WinspoolDrvHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_winspool_drv_hooks(registry: &mut HookRegistry) {
    registry.register_library(&WinspoolDrvHookLibrary);
}
