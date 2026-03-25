use std::time::Duration;

use hvm::managers::crypto_manager::CryptoManager;
use hvm::managers::device_manager::{DeviceManager, REG_MULTI_SZ, REG_SZ};
use hvm::managers::handle_table::HandleTable;
use hvm::managers::heap_manager::HeapManager;
use hvm::managers::network_manager::NetworkManager;

use hvm::managers::time_manager::TimeManager;
use hvm::managers::tls_manager::TlsManager;
use hvm::memory::manager::MemoryManager;

#[test]
fn handle_table_duplicates_alias_handles_and_shares_payload_mutations() {
    let mut table = HandleTable::new(0x8000);
    let first = table.allocate("event", String::from("alpha"));
    let alias = table.duplicate(first).expect("alias handle");

    assert_ne!(first, alias);
    assert_eq!(table.refcount(first), 2);

    let updated = table.with_payload_mut::<String, _, _>(first, |payload| {
        payload.push_str("-beta");
        payload.clone()
    });
    assert_eq!(updated.as_deref(), Some("alpha-beta"));
    assert_eq!(
        table.with_payload::<String, _, _>(alias, |payload| payload.clone()),
        Some(String::from("alpha-beta"))
    );

    let (entry, last) = table.close_ex(first);
    assert_eq!(entry.expect("closed entry").kind, "event");
    assert!(!last);
    assert_eq!(table.refcount(alias), 1);
}

#[test]
fn heap_manager_tracks_process_heap_blocks_and_sizes() {
    let mut memory = MemoryManager::for_tests();
    let mut heaps = HeapManager::new(&mut memory).expect("heap manager");

    let process_heap = heaps.process_heap();
    let block = heaps
        .alloc(&mut memory, process_heap, 0x40)
        .expect("heap alloc");

    assert_ne!(block, 0);
    assert_eq!(heaps.size(process_heap, block), 0x40);
    assert!(heaps.free(process_heap, block));
    assert_eq!(heaps.size(process_heap, block), u32::MAX as u64);
    assert!(!heaps.destroy(&mut memory, process_heap));
}

#[test]
fn heap_manager_reuses_freed_blocks_inside_existing_segment() {
    let mut memory = MemoryManager::for_tests();
    let mut heaps = HeapManager::new(&mut memory).expect("heap manager");

    let process_heap = heaps.process_heap();
    let first = heaps
        .alloc(&mut memory, process_heap, 0x20)
        .expect("first heap alloc");
    let second = heaps
        .alloc(&mut memory, process_heap, 0x30)
        .expect("second heap alloc");

    assert!(heaps.free(process_heap, first));
    let reused = heaps
        .alloc(&mut memory, process_heap, 0x18)
        .expect("reused heap alloc");

    assert_eq!(reused, first);
    assert_ne!(reused, second);
}

#[test]
fn heap_manager_batches_small_allocations_into_shared_segments() {
    let mut memory = MemoryManager::for_tests();
    let mut heaps = HeapManager::new(&mut memory).expect("heap manager");
    let process_heap = heaps.process_heap();

    for _ in 0..256 {
        heaps
            .alloc(&mut memory, process_heap, 0x20)
            .expect("small heap alloc");
    }

    assert!(
        memory.regions.len() <= 3,
        "expected process heap header plus a small number of shared segments, got {} regions",
        memory.regions.len()
    );
}

#[test]
fn device_manager_matches_python_seed_inventory_and_properties() {
    let manager = DeviceManager::new();
    let devices = manager.list_devices("", "", true);

    assert_eq!(devices.len(), 3);
    assert_eq!(devices[0].instance_id, "ROOT\\HTREE\\ROOT\\0");
    assert_eq!(
        manager.class_guids_from_name("net"),
        vec![String::from("{4D36E972-E325-11CE-BFC1-08002BE10318}")]
    );

    let disk = manager
        .find_by_instance_id("USBSTOR\\DISK&VEN_SANDBOX&PROD_VIRTUAL_DISK&REV_1.00\\0001")
        .expect("disk device");
    assert_eq!(manager.device_path(disk), "\\\\?\\USBSTOR#DISK&VEN_SANDBOX&PROD_VIRTUAL_DISK&REV_1.00#0001#{4D36E967-E325-11CE-BFC1-08002BE10318}");

    let (kind, payload) = manager
        .property_data(disk, "HardwareID", false)
        .expect("hardware ids");
    assert_eq!(kind, REG_MULTI_SZ);
    assert!(payload.starts_with(b"USBSTOR\\DISK&VEN_SANDBOX&PROD_VIRTUAL_DISK&REV_1.00"));

    let (kind, payload) = manager
        .property_data(disk, "FriendlyName", true)
        .expect("friendly name");
    assert_eq!(kind, REG_SZ);
    assert!(payload.ends_with(&[0, 0]));
}

#[test]
fn network_manager_allocates_socket_and_streams_request_bytes() {
    let handles = HandleTable::new(0x2000);
    let mut manager = NetworkManager::new(handles);
    let socket = manager.create_socket(2, 1, 6);
    let session = manager.internet_open("agent", 0, "", "");
    let connection = manager.internet_connect(session, "example.com", 443, 3, "", "");
    let request = manager.open_request(connection, "GET", "/index", "HTTP/1.1", "", "");

    assert!(manager.get_socket(socket).is_some());
    manager
        .with_request_mut(request, |record| {
            record.response_body = b"abcdef".to_vec();
        })
        .expect("request mutation");

    assert_eq!(manager.request_read(request, 4), b"abcd");
    assert_eq!(manager.request_remaining(request), 2);
    assert!(manager.close_socket(socket));
}

#[test]
fn crypto_manager_opens_store_and_exposes_default_certificate_chain_data() {
    let handles = HandleTable::new(0x3000);
    let mut manager = CryptoManager::new(handles);
    let store = manager.open_store("ROOT", false);
    let cert = manager.find_certificate(store, 0);
    let cert_context = manager.get_certificate(cert).expect("cert context");
    let message = manager.open_message();

    assert_eq!(cert_context.issuer, "CN=Sandbox Root");
    manager
        .with_message_mut(message, |record| {
            record.data.extend_from_slice(b"hello");
            record.r#final = true;
        })
        .expect("message mutation");

    let crypt_message = manager.get_message(message).expect("message");
    assert_eq!(crypt_message.data, b"hello");
    assert!(crypt_message.r#final);
}

#[test]
fn time_manager_advances_tick_counter() {
    let mut time = TimeManager::default();
    let before = time.current();

    std::thread::sleep(Duration::from_millis(2));
    let after_sleep = time.current();
    assert!(after_sleep.tick_ms >= before.tick_ms);

    time.advance(25);

    assert!(time.current().tick_ms >= after_sleep.tick_ms.saturating_add(25));
}

#[test]
fn tls_manager_stores_values_per_slot() {
    let mut tls = TlsManager::new();
    let slot = tls.alloc().unwrap();

    assert!(tls.set_value(slot, 0x1234_5678));
    assert_eq!(tls.get_value(slot), 0x1234_5678);
}
