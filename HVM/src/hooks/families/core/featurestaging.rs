use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

const EXPORTS: &[(&str, LogicalAbi)] = &[
    ("RecordFeatureUsage", LogicalAbi::WinApi),
    (
        "SubscribeFeatureStateChangeNotification",
        LogicalAbi::WinApi,
    ),
    (
        "UnsubscribeFeatureStateChangeNotification",
        LogicalAbi::WinApi,
    ),
];

/// Registers the generated hook definitions for this API-set family.
pub fn register_featurestaging_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("api-ms-win-core-featurestaging-l1-1-0.dll", &EXPORTS);
}
