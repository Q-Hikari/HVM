use super::*;

impl VirtualExecutionEngine {
    fn dispatch_known_family_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        match module_name {
            "advapi32.dll" => self.dispatch_advapi32_hook(function, args),
            "mpr.dll" => self.dispatch_mpr_hook(function, args),
            "netapi32.dll" => self.dispatch_netapi32_hook(function, args),
            "user32.dll" => self.dispatch_user32_hook(function, args),
            _ => {
                if let Some(retval) =
                    self.dispatch_appmodel_runtime_hook(module_name, function, args)
                {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_combase_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_ole32_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_oleaut32_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_rpcrt4_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_winhttp_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_wininet_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_ws2_32_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_mswsock_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_cfgmgr32_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_crypt32_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_iphlpapi_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_setupapi_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_wtsapi32_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_shell32_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_shlwapi_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_winmm_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_ntdll_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_msvcrt_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_vcruntime140_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_comctl32_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_gdi32_hook(module_name, function, args) {
                    return Some(retval);
                }
                if let Some(retval) = self.dispatch_psapi_hook(module_name, function, args) {
                    return Some(retval);
                }
                None
            }
        }
    }

    pub(super) fn dispatch_bound_stub_with_definition(
        &mut self,
        definition: &HookDefinition,
        stub_address: u64,
        return_address: Option<u64>,
        args: &[u64],
    ) -> Result<u64, VmError> {
        let _profile = self
            .runtime_profiler
            .start_scope("hook.dispatch_bound_stub_with_definition");
        self.defer_api_return = false;
        self.thread_yield_requested = false;
        let call_id = self.log_api_call(definition, stub_address, return_address, args)?;
        let module_name = definition.module.to_ascii_lowercase();
        let retval = match self.dispatch_known_family_hook(
            module_name.as_str(),
            definition.function,
            args,
        ) {
            Some(retval) => retval?,
            None => {
                if let Some(retval) = self.dispatch_kernel32_hook(
                    module_name.as_str(),
                    definition.function,
                    definition,
                    stub_address,
                    args,
                ) {
                    retval?
                } else {
                    match (module_name.as_str(), definition.function) {
                        _ => {
                            self.log_unsupported_runtime_stub(
                                definition,
                                stub_address,
                                if self.strict_unknown_api_policy() {
                                    "unknown_api_policy=strict"
                                } else {
                                    "default stub return 0"
                                },
                            )?;
                            if self.strict_unknown_api_policy() {
                                Err(VmError::NativeExecution {
                                        op: "dispatch",
                                        detail: format!(
                                            "unknown_api_policy={} rejected unimplemented runtime stub {}!{}",
                                            self.config.unknown_api_policy,
                                            definition.module,
                                            definition.function
                                        ),
                                    })
                            } else {
                                Ok(0)
                            }
                        }
                    }?
                }
            }
        };
        if self.defer_api_return {
            return Ok(retval);
        }
        self.log_api_return(call_id, definition, stub_address, args, retval)?;
        Ok(retval)
    }
}
