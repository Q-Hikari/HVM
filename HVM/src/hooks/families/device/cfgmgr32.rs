use crate::hooks::base::HookLibrary;
use crate::hooks::registry::HookRegistry;
use crate::hooks::stub::stub_definitions;

const EXPORTS: &[(&str, &str, usize, crate::hooks::base::CallConv)] = &[
    (
        "cfgmgr32.dll",
        "CM_Locate_DevNodeA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Locate_DevNodeW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_Device_IDA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_Device_IDW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_Device_ID_Size",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_Parent",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_Child",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_Sibling",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_DevNode_Status",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_DevNode_Registry_PropertyA",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_DevNode_Registry_PropertyW",
        6,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_MapCrToWin32Err",
        2,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_Device_ID_List_SizeA",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_Device_ID_List_SizeW",
        3,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_Device_ID_ListA",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
    (
        "cfgmgr32.dll",
        "CM_Get_Device_ID_ListW",
        4,
        crate::hooks::base::CallConv::Stdcall,
    ),
];

/// Collects the generated hook definitions for this DLL family.
#[derive(Debug, Default, Clone, Copy)]
pub struct Cfgmgr32HookLibrary;

impl HookLibrary for Cfgmgr32HookLibrary {
    fn collect(&self) -> Vec<crate::hooks::base::HookDefinition> {
        stub_definitions(EXPORTS)
    }
}

/// Registers the generated hook definitions for this DLL family.
pub fn register_cfgmgr32_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Cfgmgr32HookLibrary);
}
