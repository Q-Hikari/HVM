use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "comdlg32.dll",
        "CommDlgExtendedError",
        0,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "GetOpenFileNameA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "GetOpenFileNameW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "GetSaveFileNameA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "GetSaveFileNameW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "GetFileTitleA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "GetFileTitleW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "ChooseColorA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "ChooseColorW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "ChooseFontA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "ChooseFontW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "PrintDlgA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "PrintDlgW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "PageSetupDlgA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "PageSetupDlgW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "FindTextA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "FindTextW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "ReplaceTextA",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "comdlg32.dll",
        "ReplaceTextW",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Comdlg32HookLibrary;

impl HookLibrary for Comdlg32HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_comdlg32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Comdlg32HookLibrary);
}
