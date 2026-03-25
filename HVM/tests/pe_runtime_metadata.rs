use hvm::config::load_config;
use hvm::pe::inspect::inspect_pe;
use hvm::runtime::engine::VirtualExecutionEngine;

#[test]
fn main_module_reports_python_compatible_tls_callbacks() {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    let config = load_config(config_path).unwrap();
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    let module = engine.load().unwrap().clone();
    let inspect = inspect_pe(module.path.as_ref().unwrap()).unwrap();

    if inspect.has_tls {
        assert!(!module.tls_callbacks.is_empty());
        assert!(module
            .tls_callbacks
            .iter()
            .all(|callback| *callback >= module.base));
    } else {
        assert!(module.tls_callbacks.is_empty());
    }
    assert!(!module.initialized);
}
