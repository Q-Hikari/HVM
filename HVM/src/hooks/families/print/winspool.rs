use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "winspool.drv",
        "OpenPrinterA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "OpenPrinterW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "ClosePrinter",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "GetDefaultPrinterA",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "GetDefaultPrinterW",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "StartDocPrinterA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "StartDocPrinterW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "EndDocPrinter",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "AbortPrinter",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "StartPagePrinter",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "EndPagePrinter",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "WritePrinter",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "EnumPrintersA",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "EnumPrintersW",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "winspool.drv",
        "DocumentPropertiesW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinspoolHookLibrary;

impl HookLibrary for WinspoolHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_winspool_hooks(registry: &mut HookRegistry) {
    registry.register_library(&WinspoolHookLibrary);
}
