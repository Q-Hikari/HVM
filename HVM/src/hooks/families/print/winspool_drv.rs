use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("OpenPrinterA", LogicalAbi::WinApi),
    ("OpenPrinterW", LogicalAbi::WinApi),
    ("ClosePrinter", LogicalAbi::WinApi),
    ("GetDefaultPrinterA", LogicalAbi::WinApi),
    ("GetDefaultPrinterW", LogicalAbi::WinApi),
    ("StartDocPrinterA", LogicalAbi::WinApi),
    ("StartDocPrinterW", LogicalAbi::WinApi),
    ("EndDocPrinter", LogicalAbi::WinApi),
    ("AbortPrinter", LogicalAbi::WinApi),
    ("StartPagePrinter", LogicalAbi::WinApi),
    ("EndPagePrinter", LogicalAbi::WinApi),
    ("WritePrinter", LogicalAbi::WinApi),
    ("EnumPrintersA", LogicalAbi::WinApi),
    ("EnumPrintersW", LogicalAbi::WinApi),
    ("DocumentPropertiesW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_winspool_drv_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("winspool.dll", &FUNCTIONS);
}
