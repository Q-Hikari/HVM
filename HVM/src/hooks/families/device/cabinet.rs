use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("CreateCompressor", LogicalAbi::WinApi),
    ("SetCompressorInformation", LogicalAbi::WinApi),
    ("QueryCompressorInformation", LogicalAbi::WinApi),
    ("Compress", LogicalAbi::WinApi),
    ("ResetCompressor", LogicalAbi::WinApi),
    ("CloseCompressor", LogicalAbi::WinApi),
    ("CreateDecompressor", LogicalAbi::WinApi),
    ("SetDecompressorInformation", LogicalAbi::WinApi),
    ("QueryDecompressorInformation", LogicalAbi::WinApi),
    ("Decompress", LogicalAbi::WinApi),
    ("ResetDecompressor", LogicalAbi::WinApi),
    ("CloseDecompressor", LogicalAbi::WinApi),
    ("FDICreate", LogicalAbi::WinApi),
    ("FDIIsCabinet", LogicalAbi::WinApi),
    ("FDICopy", LogicalAbi::WinApi),
    ("FDIDestroy", LogicalAbi::WinApi),
    ("FCICreate", LogicalAbi::WinApi),
    ("FCIAddFile", LogicalAbi::WinApi),
    ("FCIFlushCabinet", LogicalAbi::WinApi),
    ("FCIFlushFolder", LogicalAbi::WinApi),
    ("FCIDestroy", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_cabinet_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("cabinet.dll", &FUNCTIONS);
}
