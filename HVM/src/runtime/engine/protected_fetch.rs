#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProtectedFetchBinding {
    pub module: String,
    pub function: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProtectedFetchModuleState {
    pub base: u64,
    pub synthetic: bool,
    pub allow_execution: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProtectedFetchContext {
    pub current_pc: u64,
    pub fault_address: u64,
    pub current_pc_module_base: Option<u64>,
    pub fault_module: Option<ProtectedFetchModuleState>,
    pub binding: Option<ProtectedFetchBinding>,
    pub has_definition: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProtectedFetchDecision {
    DispatchBound {
        address: u64,
    },
    SimulateReturn {
        address: u64,
        binding: Option<(String, String)>,
    },
    StaleFetchIgnore,
    RaiseFault,
}

pub(super) fn decide_protected_fetch(context: &ProtectedFetchContext) -> ProtectedFetchDecision {
    let fault_module_base = context.fault_module.map(|module| module.base);
    let in_real_non_executable_module = context
        .fault_module
        .map(|module| !module.synthetic && !module.allow_execution)
        .unwrap_or(false);
    let stale_redirect_fetch = context.current_pc != context.fault_address
        && in_real_non_executable_module
        && context.current_pc_module_base != fault_module_base;
    if stale_redirect_fetch {
        return ProtectedFetchDecision::StaleFetchIgnore;
    }

    if context.binding.is_some() && context.has_definition {
        return ProtectedFetchDecision::DispatchBound {
            address: context.fault_address,
        };
    }

    if context.binding.is_some() || in_real_non_executable_module {
        return ProtectedFetchDecision::SimulateReturn {
            address: context.fault_address,
            binding: context
                .binding
                .as_ref()
                .map(|binding| (binding.module.clone(), binding.function.clone())),
        };
    }

    ProtectedFetchDecision::RaiseFault
}
