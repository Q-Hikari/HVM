use hvm::memory::manager::{align_up, MemoryManager, PROT_EXEC, PROT_READ, PROT_WRITE};

#[test]
fn reserve_prefers_requested_base_when_free() {
    let mut memory = MemoryManager::for_tests();
    let base = memory
        .reserve(0x2000, Some(0x5000_0000), "image", false)
        .unwrap();

    assert_eq!(base, 0x5000_0000);
}

#[test]
fn write_and_read_round_trip_inside_reserved_region() {
    let mut memory = MemoryManager::for_tests();
    let base = memory
        .reserve(0x1000, Some(0x5001_0000), "buffer", false)
        .unwrap();

    memory.write(base + 4, b"ABCD").unwrap();

    assert_eq!(memory.read(base + 4, 4).unwrap(), b"ABCD");
}

#[test]
fn allocate_stack_uses_default_layout() {
    let mut memory = MemoryManager::for_tests();
    let (base, top) = memory.allocate_stack().unwrap();

    assert_eq!(base, 0x7000_0000);
    assert_eq!(top, base + 0x20_0000 - 0x1000);
    assert_eq!(align_up(base, 0x1000), base);
}

#[test]
fn unmap_removes_region_from_lookup() {
    let mut memory = MemoryManager::for_tests();
    let base = memory
        .map_region(
            0x5002_0000,
            0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            "code",
        )
        .unwrap();

    assert!(memory.find_region(base, 0x100).is_some());

    memory.unmap(base, 0x1000).unwrap();

    assert!(memory.find_region(base, 0x100).is_none());
}

#[test]
fn reserve_without_preferred_matches_python_sequence() {
    let mut memory = MemoryManager::for_tests();
    let expected = [0x6905_C000, 0x6964_C000, 0x5841_8000, 0x6D90_6000];

    for value in expected {
        let base = memory.reserve(0x1000, None, "alloc", true).unwrap();
        assert_eq!(base, value);
    }
}

#[test]
fn find_region_returns_none_on_overflowing_range_end() {
    let memory = MemoryManager::for_tests();

    assert!(memory.find_region(u64::MAX, 1).is_none());
    assert!(memory.find_region(u64::MAX - 1, 8).is_none());
}
