use crate::hooks::base::{CallConv, HookDefinition, HookLibrary};
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stdcall_definitions;
use crate::tests_support::LoadedTestEngine;

pub const SHELL_EXECUTE_SUCCESS: u32 = 33;
pub const SEE_MASK_NOCLOSEPROCESS: u32 = 0x00000040;

const STUB_EXPORTS: &[(&str, usize)] = &[
    ("DragFinish", 1),
    ("DragQueryFileW", 4),
    ("SHAppBarMessage", 2),
    ("SHBrowseForFolderW", 1),
    ("SHGetDesktopFolder", 1),
    ("SHGetFileInfoW", 5),
    ("SHGetMalloc", 1),
    ("SHGetPathFromIDListW", 2),
    ("SHGetSpecialFolderLocation", 3),
];

/// Collects the `shell32.dll` hook definitions currently backed by Rust code.
#[derive(Debug, Default, Clone, Copy)]
pub struct Shell32HookLibrary;

impl HookLibrary for Shell32HookLibrary {
    fn collect(&self) -> Vec<HookDefinition> {
        let mut definitions = vec![
            definition("IsUserAnAdmin", 0),
            definition("ShellExecuteW", 6),
            definition("ShellExecuteExW", 1),
            definition("SHBrowseForFolderA", 1),
            definition("SHGetFolderPathW", 5),
            definition("SHGetImageList", 3),
            definition("IMalloc_QueryInterface", 3),
            definition("IMalloc_AddRef", 1),
            definition("IMalloc_Release", 1),
            definition("IMalloc_Alloc", 2),
            definition("IMalloc_Realloc", 3),
            definition("IMalloc_Free", 2),
            definition("IMalloc_GetSize", 2),
            definition("IMalloc_DidAlloc", 2),
            definition("IMalloc_HeapMinimize", 1),
        ];
        definitions.extend(stdcall_definitions("shell32.dll", STUB_EXPORTS));
        definitions
    }
}

/// Registers the currently supported `shell32.dll` hook definitions.
pub fn register_shell32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Shell32HookLibrary);
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

fn definition(function: &'static str, argc: usize) -> HookDefinition {
    HookDefinition {
        module: "shell32.dll",
        function,
        argc,
        call_conv: CallConv::Stdcall,
    }
}
