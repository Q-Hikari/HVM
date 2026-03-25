use crate::hooks::base::{CallConv, HookDefinition};

/// Builds a vector of static hook definitions for one generated DLL hook module.
pub fn stub_definitions(
    exports: &[(&'static str, &'static str, usize, CallConv)],
) -> Vec<HookDefinition> {
    exports
        .iter()
        .map(|(module, function, argc, call_conv)| HookDefinition {
            module,
            function,
            argc: *argc,
            call_conv: *call_conv,
        })
        .collect()
}

/// Builds stdcall hook definitions for one DLL from compact export metadata.
pub fn stdcall_definitions(
    module: &'static str,
    exports: &[(&'static str, usize)],
) -> Vec<HookDefinition> {
    exports
        .iter()
        .map(|(function, argc)| HookDefinition {
            module,
            function,
            argc: *argc,
            call_conv: CallConv::Stdcall,
        })
        .collect()
}
