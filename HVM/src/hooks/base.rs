/// Enumerates the calling conventions recognized by the synthetic hook registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallConv {
    Stdcall,
    Cdecl,
    Win64,
}

/// Describes one synthetic DLL hook binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookDefinition {
    pub module: &'static str,
    pub function: &'static str,
    pub argc: usize,
    pub call_conv: CallConv,
}

/// Allows one DLL-specific hook library to register its definitions.
pub trait HookLibrary {
    fn collect(&self) -> Vec<HookDefinition>;
}
