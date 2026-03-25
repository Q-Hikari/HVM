use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;
use serde_json::Value;

fn sample_config() -> hvm::config::EngineConfig {
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_567dbfa9f7d29702a70feb934ec08e54_trace.json");
    load_config(config_path).unwrap()
}

fn trace_config(test_name: &str) -> (hvm::config::EngineConfig, PathBuf) {
    let mut config = sample_config();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "hvm-hikari-virtual-engine-{test_name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let trace_path = root.join("trace.api.jsonl");
    config.trace_api_calls = true;
    config.trace_native_events = true;
    config.api_log_to_console = false;
    config.console_output_to_console = false;
    config.api_log_path = Some(root.join("trace.api.log"));
    config.api_jsonl_path = Some(trace_path.clone());
    config.console_output_path = Some(root.join("trace.console.log"));
    (config, trace_path)
}

fn load_markers(path: &std::path::Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter_map(|record| {
            record
                .get("marker")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn load_records(path: &std::path::Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect()
}

#[test]
fn call_native_executes_x86_stub_and_returns_eax() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let address = engine.allocate_executable_test_page(0x6000_0000).unwrap();
    engine
        .write_test_bytes(address, &[0xB8, 0x78, 0x56, 0x34, 0x12, 0xC3])
        .unwrap();

    let retval = engine.call_native_for_test(address, &[]).unwrap();
    assert_eq!(retval, 0x1234_5678);
}

#[test]
fn call_native_uses_python_style_stack_top_for_first_argument() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    let main_tid = engine.main_thread_tid().unwrap();
    let thread = engine.scheduler().thread_snapshot(main_tid).unwrap();
    let address = engine.allocate_executable_test_page(0x6000_1000).unwrap();
    engine
        .write_test_bytes(address, &[0x8D, 0x44, 0x24, 0x04, 0xC2, 0x04, 0x00])
        .unwrap();

    let retval = engine
        .call_native_for_test(address, &[0x4141_4141])
        .unwrap();
    assert_eq!(retval, thread.stack_top - 4);
}

#[test]
fn native_unicorn_x86_seh_continue_execution_recovers_from_unmapped_read() {
    let mut engine = VirtualExecutionEngine::new(sample_config()).unwrap();
    engine.load().unwrap();

    if !engine.has_native_unicorn() {
        return;
    }
    let pointer_size = engine
        .entry_module()
        .or_else(|| engine.main_module())
        .map(|module| module.arch.eq_ignore_ascii_case("x64"))
        .unwrap_or(false);
    if pointer_size {
        return;
    }

    let code = engine.allocate_executable_test_page(0x6000_2000).unwrap();
    let fault_address = 0x5555_0000u32;
    let recovery = (code + 24) as u32;
    let handler = (code + 43) as u32;

    let mut bytes = Vec::new();
    bytes.push(0x68);
    bytes.extend_from_slice(&handler.to_le_bytes());
    bytes.extend_from_slice(&[0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00]);
    bytes.push(0xA1);
    bytes.extend_from_slice(&fault_address.to_le_bytes());
    bytes.push(0xB8);
    bytes.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    bytes.extend_from_slice(&[0x8B, 0x0C, 0x24]);
    bytes.extend_from_slice(&[0x64, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x83, 0xC4, 0x08, 0xC3]);
    bytes.extend_from_slice(&[0x8B, 0x44, 0x24, 0x0C]);
    bytes.extend_from_slice(&[0xC7, 0x80, 0xB8, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&recovery.to_le_bytes());
    bytes.extend_from_slice(&[0x31, 0xC0, 0xC3]);
    engine.write_test_bytes(code, &bytes).unwrap();

    assert_eq!(engine.call_native_for_test(code, &[]).unwrap(), 0x1234_5678);
}

#[test]
fn native_trace_logs_blocks_faults_and_seh_events() {
    let (config, trace_path) = trace_config("native-trace-seh");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    if !engine.has_native_unicorn() {
        return;
    }
    let pointer_size = engine
        .entry_module()
        .or_else(|| engine.main_module())
        .map(|module| module.arch.eq_ignore_ascii_case("x64"))
        .unwrap_or(false);
    if pointer_size {
        return;
    }

    let code = engine.allocate_executable_test_page(0x6000_3000).unwrap();
    let fault_address = 0x5555_1000u32;
    let recovery = (code + 24) as u32;
    let handler = (code + 43) as u32;

    let mut bytes = Vec::new();
    bytes.push(0x68);
    bytes.extend_from_slice(&handler.to_le_bytes());
    bytes.extend_from_slice(&[0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00]);
    bytes.push(0xA1);
    bytes.extend_from_slice(&fault_address.to_le_bytes());
    bytes.push(0xB8);
    bytes.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    bytes.extend_from_slice(&[0x8B, 0x0C, 0x24]);
    bytes.extend_from_slice(&[0x64, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&[0x83, 0xC4, 0x08, 0xC3]);
    bytes.extend_from_slice(&[0x8B, 0x44, 0x24, 0x0C]);
    bytes.extend_from_slice(&[0xC7, 0x80, 0xB8, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&recovery.to_le_bytes());
    bytes.extend_from_slice(&[0x31, 0xC0, 0xC3]);
    engine.write_test_bytes(code, &bytes).unwrap();

    assert_eq!(engine.call_native_for_test(code, &[]).unwrap(), 0x1234_5678);
    drop(engine);

    let markers = load_markers(&trace_path);
    assert!(markers.iter().any(|marker| marker == "NATIVE_BLOCK"));
    assert!(markers.iter().any(|marker| marker == "NATIVE_FAULT"));
    assert!(markers.iter().any(|marker| marker == "SEH_DISPATCH"));
    assert!(markers.iter().any(|marker| marker == "SEH_HANDLER"));
    assert!(markers.iter().any(|marker| marker == "SEH_RESUME"));
}

#[test]
fn call_native_reports_budget_exhaustion_for_non_returning_standalone_code() {
    let mut config = sample_config();
    config.max_instructions = 16;
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    let address = engine.allocate_executable_test_page(0x6000_4000).unwrap();
    engine.write_test_bytes(address, &[0xEB, 0xFE]).unwrap();

    let error = engine.call_native_for_test(address, &[]).unwrap_err();
    assert!(error.to_string().contains("instruction budget exhausted"));
}

#[test]
fn native_trace_logs_repeating_loop_sequences() {
    let (mut config, trace_path) = trace_config("native-loop-sequence");
    config.max_instructions = 128;
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    engine.load().unwrap();

    if !engine.has_native_unicorn() {
        return;
    }
    if engine
        .entry_module()
        .or_else(|| engine.main_module())
        .map(|module| module.arch.eq_ignore_ascii_case("x64"))
        .unwrap_or(false)
    {
        return;
    }

    let address = engine.allocate_executable_test_page(0x6000_5000).unwrap();
    let mut bytes = vec![0x41, 0xEB, 0x0D];
    bytes.extend_from_slice(&[0x90; 13]);
    bytes.extend_from_slice(&[0xEB, 0xEE]);
    engine.write_test_bytes(address, &bytes).unwrap();

    let error = engine.call_native_for_test(address, &[]).unwrap_err();
    assert!(error.to_string().contains("instruction budget exhausted"));
    drop(engine);

    let records = load_records(&trace_path);
    let loop_record = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("NATIVE_LOOP"))
        .unwrap();
    let loop_info = loop_record.get("loop").unwrap();
    assert_eq!(loop_info.get("period").and_then(Value::as_u64), Some(2));
    assert!(
        loop_info
            .get("repeats")
            .and_then(Value::as_u64)
            .unwrap_or_default()
            >= 3
    );
    let registers = loop_info
        .get("state_delta")
        .and_then(|value| value.get("registers"))
        .unwrap();
    let ecx = registers.get("ecx").unwrap();
    assert_eq!(ecx.get("delta").and_then(Value::as_str), Some("+0x1"));
    let phase_deltas = loop_info
        .get("phase_deltas")
        .and_then(Value::as_array)
        .unwrap();
    assert!(!phase_deltas.is_empty());
    let first_phase = &phase_deltas[0];
    assert!(first_phase.get("phase").and_then(Value::as_u64).is_some());
    assert!(first_phase
        .get("state_delta")
        .and_then(|value| value.get("registers"))
        .and_then(|value| value.get("ecx"))
        .is_some());
    let phase_sequence = loop_info
        .get("phase_sequence")
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(phase_sequence.len(), 2);
    assert_eq!(
        phase_sequence
            .iter()
            .filter_map(|entry| entry.get("phase").and_then(Value::as_u64))
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    let ecx_phase = phase_sequence
        .iter()
        .find_map(|entry| {
            let changed_registers = entry.get("changed_registers")?.as_array()?;
            changed_registers
                .iter()
                .filter_map(Value::as_str)
                .any(|name| name == "ecx")
                .then(|| entry.get("phase").and_then(Value::as_u64))
                .flatten()
        })
        .unwrap();
    let register_hotspots = loop_info
        .get("register_hotspots")
        .and_then(Value::as_array)
        .unwrap();
    let ecx_hotspot = register_hotspots
        .iter()
        .find(|entry| entry.get("name").and_then(Value::as_str) == Some("ecx"))
        .unwrap();
    let ecx_phases = ecx_hotspot
        .get("phases")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(Value::as_u64)
        .collect::<Vec<_>>();
    assert!(
        ecx_hotspot
            .get("phase_hits")
            .and_then(Value::as_u64)
            .unwrap_or_default()
            >= 1
    );
    assert!(ecx_phases.contains(&ecx_phase));
    assert_eq!(
        ecx_hotspot
            .get("loop_start_delta")
            .and_then(|value| value.get("delta"))
            .and_then(Value::as_str),
        Some("+0x1")
    );
}

#[test]
fn run_trace_logs_stop_reason_and_native_summary() {
    let (config, trace_path) = trace_config("run-stop-summary");
    let mut engine = VirtualExecutionEngine::new(config).unwrap();
    let native_unicorn = engine.has_native_unicorn();

    let result = engine.run().unwrap();
    drop(engine);

    let markers = load_markers(&trace_path);
    assert!(markers.iter().any(|marker| marker == "RUN_STOP"));
    assert!(markers.iter().any(|marker| marker == "PROCESS_EXIT"));
    if native_unicorn {
        assert!(markers.iter().any(|marker| marker == "NATIVE_SUMMARY"));
    }

    let records = load_records(&trace_path);
    let run_stop = records
        .iter()
        .find(|record| record.get("marker").and_then(Value::as_str) == Some("RUN_STOP"))
        .unwrap();
    assert_eq!(
        run_stop.get("reason").and_then(Value::as_str),
        Some(result.stop_reason.as_str())
    );
}
