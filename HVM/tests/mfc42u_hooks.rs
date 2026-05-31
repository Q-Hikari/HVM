use std::path::Path;

use hvm::config::load_config;
use hvm::runtime::engine::VirtualExecutionEngine;

fn sample_config_x64() -> hvm::config::EngineConfig {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_42c4b1eaeba9de5a873970687b4abc34_trace.json");
    load_config(config_path).unwrap()
}

fn sample_config_939() -> hvm::config::EngineConfig {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../configs/sample_939c031f8152e9f16b8edffd70d647c1_trace.json");
    load_config(config_path).unwrap()
}

#[test]
fn ordinal_3997_returns_callable_stub_and_clears_state_blocks() {
    let mut engine = VirtualExecutionEngine::new(sample_config_x64()).unwrap();
    engine.load().unwrap();

    let ordinal = engine.bind_hook_for_test("mfc42u.dll", "ordinal_3997");
    let callback_state = engine.allocate_executable_test_page(0x6350_0000).unwrap();
    let status_state = engine.allocate_executable_test_page(0x6350_1000).unwrap();
    engine
        .write_test_bytes(callback_state, &[0xAA; 0x20])
        .unwrap();
    engine
        .write_test_bytes(status_state, &[0xBB; 0x20])
        .unwrap();

    let callback = engine
        .dispatch_bound_stub(ordinal, &[callback_state, status_state])
        .unwrap();

    assert_ne!(callback, 0);
    assert_eq!(
        engine
            .modules()
            .memory()
            .read(callback_state, 0x20)
            .unwrap(),
        vec![0; 0x20]
    );
    assert_eq!(
        engine.modules().memory().read(status_state, 0x20).unwrap(),
        vec![0; 0x20]
    );
    assert_eq!(engine.dispatch_bound_stub(callback, &[1, 2, 3]).unwrap(), 0);
}

#[test]
fn sample_939_binds_mfc42u_ordinal_3997_iat_to_registered_stub() {
    let mut engine = VirtualExecutionEngine::new(sample_config_939()).unwrap();
    let main_module = engine.load().unwrap().clone();
    let iat_target = u64::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(main_module.base + 0x9FD68, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    assert_ne!(
        iat_target, 0,
        "sample 939 ordinal_3997 IAT should be resolved"
    );
    assert_eq!(
        engine.hooks().binding_for_address(iat_target),
        Some(("mfc42u.dll", "ordinal_3997"))
    );

    let mfc42u = engine.modules().get_loaded("mfc42u.dll").unwrap();
    assert_eq!(
        mfc42u.exports_by_name.get("ordinal_3997").copied(),
        Some(iat_target)
    );
    assert_eq!(
        mfc42u.exports_by_ordinal.get(&3997).copied(),
        Some(iat_target)
    );
    assert_eq!(
        engine.modules().memory().read(iat_target, 4).unwrap(),
        vec![0xC3, 0x00, 0x00, 0x00]
    );
}

#[test]
fn sample_939_native_call_to_ordinal_3997_iat_target_dispatches_runtime_hook() {
    let mut engine = VirtualExecutionEngine::new(sample_config_939()).unwrap();
    let main_module = engine.load().unwrap().clone();
    let iat_target = u64::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(main_module.base + 0x9FD68, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let callback_state = engine.allocate_executable_test_page(0x6360_0000).unwrap();
    let status_state = engine.allocate_executable_test_page(0x6360_1000).unwrap();
    let shim = engine.allocate_executable_test_page(0x6360_2000).unwrap();
    engine
        .write_test_bytes(callback_state, &[0xAA; 0x20])
        .unwrap();
    engine
        .write_test_bytes(status_state, &[0xBB; 0x20])
        .unwrap();

    let mut shim_bytes = vec![0x48, 0xB8];
    shim_bytes.extend_from_slice(&iat_target.to_le_bytes());
    shim_bytes.extend_from_slice(&[0xFF, 0xD0, 0xC3]);
    engine.write_test_bytes(shim, &shim_bytes).unwrap();

    let callback = engine
        .call_native_for_test(shim, &[callback_state, status_state])
        .unwrap();

    assert_ne!(callback, 0);
    assert_eq!(
        engine.hooks().binding_for_address(callback),
        Some(("mfc42u.dll", "__vm_mfc42u_ordinal_3997_callback"))
    );
}

#[test]
fn sample_939_rip_indirect_call_to_ordinal_3997_iat_target_dispatches_runtime_hook() {
    let mut engine = VirtualExecutionEngine::new(sample_config_939()).unwrap();
    let main_module = engine.load().unwrap().clone();
    let iat_target = u64::from_le_bytes(
        engine
            .modules()
            .memory()
            .read(main_module.base + 0x9FD68, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let callback_state = engine.allocate_executable_test_page(0x6370_0000).unwrap();
    let status_state = engine.allocate_executable_test_page(0x6370_1000).unwrap();
    let shim = engine.allocate_executable_test_page(0x6370_2000).unwrap();
    engine
        .write_test_bytes(callback_state, &[0xAA; 0x20])
        .unwrap();
    engine
        .write_test_bytes(status_state, &[0xBB; 0x20])
        .unwrap();

    let mut shim_bytes = vec![
        0x48, 0x8D, 0x54, 0x24, 0x60, // lea rdx, [rsp+0x60]
        0x48, 0x8D, 0x4C, 0x24, 0x38, // lea rcx, [rsp+0x38]
        0xFF, 0x15, 0x01, 0x00, 0x00, 0x00, // call qword ptr [rip+1]
        0xC3, // ret
    ];
    shim_bytes.extend_from_slice(&iat_target.to_le_bytes());
    engine.write_test_bytes(shim, &shim_bytes).unwrap();

    let callback = engine
        .call_native_for_test(shim, &[callback_state, status_state])
        .unwrap();

    assert_ne!(callback, 0);
    assert_eq!(
        engine.hooks().binding_for_address(callback),
        Some(("mfc42u.dll", "__vm_mfc42u_ordinal_3997_callback"))
    );
}

#[test]
fn sample_939_binds_additional_mfc42u_stateful_iats() {
    let mut engine = VirtualExecutionEngine::new(sample_config_939()).unwrap();
    let main_module = engine.load().unwrap().clone();

    for (rva, function) in [
        (0x9F3A8, "ordinal_6772"),
        (0x9F370, "ordinal_1126"),
        (0x9F378, "ordinal_620"),
        (0x9F388, "ordinal_624"),
        (0x9F3C8, "ordinal_1284"),
        (0x9F3D0, "ordinal_622"),
        (0x9F3D8, "ordinal_625"),
        (0x9F418, "ordinal_1287"),
        (0x9F440, "ordinal_4375"),
        (0x9F530, "ordinal_1838"),
        (0x9F5E0, "ordinal_966"),
        (0x9F710, "ordinal_6331"),
        (0x9F818, "ordinal_799"),
    ] {
        let target = u64::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(main_module.base + rva, 8)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_ne!(target, 0, "sample 939 {function} IAT should be resolved");
        assert_eq!(
            engine.hooks().binding_for_address(target),
            Some(("mfc42u.dll", function)),
            "sample 939 {function} IAT should bind to the runtime hook"
        );
    }
}

#[test]
fn ordinal_625_and_624_seed_and_consume_ascii_state() {
    let mut engine = VirtualExecutionEngine::new(sample_config_939()).unwrap();
    engine.load().unwrap();

    let ordinal_625 = engine.bind_hook_for_test("mfc42u.dll", "ordinal_625");
    let ordinal_624 = engine.bind_hook_for_test("mfc42u.dll", "ordinal_624");
    let state = engine.allocate_executable_test_page(0x6380_0000).unwrap();
    let mirror = engine.allocate_executable_test_page(0x6380_1000).unwrap();
    let text = engine.allocate_executable_test_page(0x6380_2000).unwrap();
    let shim = engine.allocate_executable_test_page(0x6380_3000).unwrap();

    engine.write_test_bytes(text, b"Ab\0").unwrap();
    engine
        .dispatch_bound_stub(ordinal_625, &[state, text, 0x1234])
        .unwrap();

    let mut shim_bytes = vec![0x48, 0xB8];
    shim_bytes.extend_from_slice(&ordinal_624.to_le_bytes());
    shim_bytes.extend_from_slice(&[0xFF, 0xD0, 0x89, 0xC8, 0xC3]);
    engine.write_test_bytes(shim, &shim_bytes).unwrap();

    let first = engine.call_native_for_test(shim, &[state, mirror]).unwrap();
    let second = engine.call_native_for_test(shim, &[state, mirror]).unwrap();
    let third = engine.call_native_for_test(shim, &[state, mirror]).unwrap();

    assert_eq!(first as u8, b'A');
    assert_eq!(second as u8, b'b');
    assert_eq!(third, 0);
    assert_eq!(
        u64::from_le_bytes(
            engine
                .modules()
                .memory()
                .read(state + 0x8, 8)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        text + 2
    );
}

#[test]
fn ordinal_6772_preserves_this_pointer_in_native_context() {
    let mut engine = VirtualExecutionEngine::new(sample_config_939()).unwrap();
    engine.load().unwrap();

    let ordinal = engine.bind_hook_for_test("mfc42u.dll", "ordinal_6772");
    let object = engine.allocate_executable_test_page(0x6381_0000).unwrap();
    let shim = engine.allocate_executable_test_page(0x6381_1000).unwrap();

    engine
        .write_test_bytes(object + 0x35, &0x1122_3344u32.to_le_bytes())
        .unwrap();

    let mut shim_bytes = vec![0x48, 0xB9];
    shim_bytes.extend_from_slice(&object.to_le_bytes());
    shim_bytes.extend_from_slice(&[0x48, 0xB8]);
    shim_bytes.extend_from_slice(&ordinal.to_le_bytes());
    shim_bytes.extend_from_slice(&[0xFF, 0xD0, 0x8B, 0x41, 0x35, 0xC3]);
    engine.write_test_bytes(shim, &shim_bytes).unwrap();

    let result = engine.call_native_for_test(shim, &[]).unwrap();
    assert_eq!(result as u32, 0x1122_3344);
}

#[test]
fn ordinal_966_returns_the_passed_state_pointer() {
    let mut engine = VirtualExecutionEngine::new(sample_config_939()).unwrap();
    engine.load().unwrap();

    let ordinal = engine.bind_hook_for_test("mfc42u.dll", "ordinal_966");
    let state = engine.allocate_executable_test_page(0x6381_2000).unwrap();
    let shim = engine.allocate_executable_test_page(0x6381_3000).unwrap();

    engine
        .write_test_bytes(state, &0x5566_7788u32.to_le_bytes())
        .unwrap();

    let mut shim_bytes = vec![0x48, 0xB9];
    shim_bytes.extend_from_slice(&state.to_le_bytes());
    shim_bytes.extend_from_slice(&[0x48, 0xB8]);
    shim_bytes.extend_from_slice(&ordinal.to_le_bytes());
    shim_bytes.extend_from_slice(&[0xFF, 0xD0, 0x8B, 0x00, 0xC3]);
    engine.write_test_bytes(shim, &shim_bytes).unwrap();

    let result = engine.call_native_for_test(shim, &[]).unwrap();
    assert_eq!(result as u32, 0x5566_7788);
}
