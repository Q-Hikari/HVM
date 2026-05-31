use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("CM_Locate_DevNodeA", LogicalAbi::WinApi),
    ("CM_Locate_DevNodeW", LogicalAbi::WinApi),
    ("CM_Get_Device_IDA", LogicalAbi::WinApi),
    ("CM_Get_Device_IDW", LogicalAbi::WinApi),
    ("CM_Get_Device_ID_Size", LogicalAbi::WinApi),
    ("CM_Get_Parent", LogicalAbi::WinApi),
    ("CM_Get_Child", LogicalAbi::WinApi),
    ("CM_Get_Sibling", LogicalAbi::WinApi),
    ("CM_Get_DevNode_Status", LogicalAbi::WinApi),
    ("CM_Get_DevNode_Registry_PropertyA", LogicalAbi::WinApi),
    ("CM_Get_DevNode_Registry_PropertyW", LogicalAbi::WinApi),
    ("CM_MapCrToWin32Err", LogicalAbi::WinApi),
    ("CM_Get_Device_ID_List_SizeA", LogicalAbi::WinApi),
    ("CM_Get_Device_ID_List_SizeW", LogicalAbi::WinApi),
    ("CM_Get_Device_ID_ListA", LogicalAbi::WinApi),
    ("CM_Get_Device_ID_ListW", LogicalAbi::WinApi),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_cfgmgr32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("cfgmgr32.dll", &FUNCTIONS);
}
