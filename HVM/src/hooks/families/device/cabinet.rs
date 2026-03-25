use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "cabinet.dll",
        "CreateCompressor",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "SetCompressorInformation",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "QueryCompressorInformation",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "Compress",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "ResetCompressor",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "CloseCompressor",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "CreateDecompressor",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "SetDecompressorInformation",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "QueryDecompressorInformation",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "Decompress",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "ResetDecompressor",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "CloseDecompressor",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "FDICreate",
        9,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "FDIIsCabinet",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "FDICopy",
        7,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "FDIDestroy",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "FCICreate",
        13,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "FCIAddFile",
        8,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "FCIFlushCabinet",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "FCIFlushFolder",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cabinet.dll",
        "FCIDestroy",
        1,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct CabinetHookLibrary;

impl HookLibrary for CabinetHookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_cabinet_hooks(registry: &mut HookRegistry) {
    registry.register_library(&CabinetHookLibrary);
}
