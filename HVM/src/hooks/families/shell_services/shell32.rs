use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;
use crate::tests_support::LoadedTestEngine;

pub const SHELL_EXECUTE_SUCCESS: u32 = 33;
pub const SEE_MASK_NOCLOSEPROCESS: u32 = 0x00000040;

const STUB_EXPORTS: &[(&str, LogicalAbi)] = &[
    ("DragFinish", LogicalAbi::WinApi),
    ("DragQueryFileW", LogicalAbi::WinApi),
    ("SHAppBarMessage", LogicalAbi::WinApi),
    ("SHBrowseForFolderW", LogicalAbi::WinApi),
    ("SHGetDesktopFolder", LogicalAbi::WinApi),
    ("SHGetFileInfoW", LogicalAbi::WinApi),
    ("SHGetMalloc", LogicalAbi::WinApi),
    ("SHGetPathFromIDListW", LogicalAbi::WinApi),
    ("SHGetSpecialFolderLocation", LogicalAbi::WinApi),
    ("ordinal_165", LogicalAbi::WinApi),
    ("SHAddToRecentDocs", LogicalAbi::WinApi),
    ("SHCreateItemFromParsingName", LogicalAbi::WinApi),
    ("SHCreateItemInKnownFolder", LogicalAbi::WinApi),
    ("ShellAboutW", LogicalAbi::WinApi),
    ("SHGetSpecialFolderPathW", LogicalAbi::WinApi),
];

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("IsUserAnAdmin", LogicalAbi::WinApi),
    ("CommandLineToArgvW", LogicalAbi::WinApi),
    ("ShellExecuteW", LogicalAbi::WinApi),
    ("ShellExecuteA", LogicalAbi::WinApi),
    ("ShellExecuteExW", LogicalAbi::WinApi),
    ("SHBrowseForFolderA", LogicalAbi::WinApi),
    ("SHGetFolderPathW", LogicalAbi::WinApi),
    ("SHGetKnownFolderPath", LogicalAbi::WinApi),
    ("SHGetImageList", LogicalAbi::WinApi),
    ("IMalloc_QueryInterface", LogicalAbi::WinApi),
    ("IMalloc_AddRef", LogicalAbi::WinApi),
    ("IMalloc_Release", LogicalAbi::WinApi),
    ("IMalloc_Alloc", LogicalAbi::WinApi),
    ("IMalloc_Realloc", LogicalAbi::WinApi),
    ("IMalloc_Free", LogicalAbi::WinApi),
    ("IMalloc_GetSize", LogicalAbi::WinApi),
    ("IMalloc_DidAlloc", LogicalAbi::WinApi),
    ("IMalloc_HeapMinimize", LogicalAbi::WinApi),
];

/// Registers the currently supported `shell32.dll` hook definitions.
pub fn register_shell32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("shell32.dll", &FUNCTIONS);
    registry.register_function_stubs("shell32.dll", &STUB_EXPORTS);
}

/// Exposes test-only `shell32.dll` helpers over the loaded Rust runtime scaffold.
#[derive(Debug)]
pub struct Shell32Api<'a> {
    engine: &'a mut LoadedTestEngine,
}

impl<'a> Shell32Api<'a> {
    /// Builds a `shell32.dll` helper bound to one loaded test engine.
    pub(crate) fn new(engine: &'a mut LoadedTestEngine) -> Self {
        Self { engine }
    }

    /// Launches a synthetic child process through the ShellExecuteW compatibility path.
    pub fn shell_execute_w_for_test(
        &mut self,
        image: &str,
        parameters: Option<&str>,
        directory: Option<&str>,
    ) -> Option<u32> {
        self.engine
            .processes_mut()
            .spawn_shell_execute(image, parameters, directory)?;
        Some(SHELL_EXECUTE_SUCCESS)
    }

    /// Launches a synthetic child process through the ShellExecuteExW compatibility path.
    pub fn shell_execute_ex_w_for_test(
        &mut self,
        image: &str,
        parameters: Option<&str>,
        directory: Option<&str>,
        keep_process_handle: bool,
    ) -> Option<u32> {
        let handle = self
            .engine
            .processes_mut()
            .spawn_shell_execute(image, parameters, directory)?;
        if keep_process_handle {
            Some(handle)
        } else {
            Some(0)
        }
    }
}
