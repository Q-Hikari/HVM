use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS_API_MS_WIN_EVENTING_CONTROLLER_L1_1_0_DLL: &[(&str, LogicalAbi)] = &[
    ("EventAccessQuery", LogicalAbi::WinApi),
    ("EventAccessRemove", LogicalAbi::WinApi),
    ("EventAccessControl", LogicalAbi::WinApi),
    ("StartTraceW", LogicalAbi::WinApi),
    ("ControlTraceW", LogicalAbi::WinApi),
    ("StopTraceW", LogicalAbi::WinApi),
    ("QueryAllTracesW", LogicalAbi::WinApi),
    ("TraceSetInformation", LogicalAbi::WinApi),
    ("EnableTraceEx2", LogicalAbi::WinApi),
    ("EnumerateTraceGuidsEx", LogicalAbi::WinApi),
];

static FUNCTIONS_API_MS_WIN_EVENTING_CONSUMER_L1_1_0_DLL: &[(&str, LogicalAbi)] = &[
    ("OpenTraceA", LogicalAbi::WinApi),
    ("OpenTraceW", LogicalAbi::WinApi),
    ("ProcessTrace", LogicalAbi::WinApi),
    ("CloseTrace", LogicalAbi::WinApi),
];

pub fn register_eventing_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs(
        "api-ms-win-eventing-controller-l1-1-0.dll",
        &FUNCTIONS_API_MS_WIN_EVENTING_CONTROLLER_L1_1_0_DLL,
    );
    registry.register_function_stubs(
        "api-ms-win-eventing-consumer-l1-1-0.dll",
        &FUNCTIONS_API_MS_WIN_EVENTING_CONSUMER_L1_1_0_DLL,
    );
}
