use hvm::managers::registry_manager::{RegistryManager, HKEY_LOCAL_MACHINE};

#[test]
fn registry_manager_creates_sets_and_queries_values() {
    let mut registry = RegistryManager::new();
    let (handle, created) = registry.create_key(HKEY_LOCAL_MACHINE, "Software\\360Safe\\Liveup");
    let handle = handle.unwrap();

    assert!(created);
    assert!(registry.set_value(handle, "mid", 1, b"hello\0"));

    let queried = registry.query_value(handle, "mid").unwrap();
    assert_eq!(queried.value_type, 1);
    assert_eq!(queried.data, b"hello\0");
}

#[test]
fn registry_manager_reopens_created_keys() {
    let mut registry = RegistryManager::new();
    let (handle, _) = registry.create_key(HKEY_LOCAL_MACHINE, "Software\\360Safe\\Liveup");
    let handle = handle.unwrap();

    assert!(registry.set_value(handle, "m2", 1, b"value\0"));
    assert!(registry.close(handle));

    let reopened = registry
        .open_key(HKEY_LOCAL_MACHINE, "Software\\360Safe\\Liveup", false)
        .unwrap();
    assert_eq!(
        registry.query_value(reopened, "m2").unwrap().data,
        b"value\0"
    );
}
