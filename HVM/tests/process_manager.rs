use hvm::managers::process_manager::ProcessManager;

#[test]
fn spawn_shell_execute_without_parameters_uses_image_as_command_line() {
    let mut manager = ProcessManager::for_tests();
    let handle = manager
        .spawn_shell_execute(r"C:\Windows\System32\notepad.exe", None, None)
        .unwrap();
    let process = manager.find_process_by_handle(handle).unwrap();

    assert_eq!(process.image_path, r"C:\Windows\System32\notepad.exe");
    assert_eq!(process.command_line, r"C:\Windows\System32\notepad.exe");
    assert_eq!(process.current_directory, "");
}
