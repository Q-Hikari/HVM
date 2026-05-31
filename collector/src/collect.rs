//! Collection logic — gathers real system information on Windows.
//!
//! On non-Windows platforms, all collectors return empty/default values.

use crate::profile::*;

/// Top-level entry point — runs all collectors and assembles the profile.
pub fn collect_all() -> EnvironmentProfile {
    let mut profile = EnvironmentProfile::default();

    profile.machine = collect_machine_identity();
    profile.os_version = collect_os_version();
    profile.locale = collect_locale();
    profile.display = collect_display();
    profile.volume = collect_volume();
    profile.shell_folders = collect_shell_folders();
    profile.network = collect_network();
    profile.environment_variables = collect_environment_variables();
    profile.processes = collect_processes();
    profile.users = collect_users();
    profile.local_groups = collect_local_groups();
    profile.services = collect_services();
    profile.registry = collect_registry();
    profile.system32_files = collect_system32_files();

    profile
}

// ==========================================================================
// Machine Identity
// ==========================================================================

fn collect_machine_identity() -> MachineIdentity {
    let mut m = MachineIdentity::default();
    m.computer_name = get_env_or("COMPUTERNAME", "");
    m.user_name = get_env_or("USERNAME", "");
    m.user_domain = get_env_or("USERDOMAIN", "WORKGROUP");
    m.dns_domain_name = get_env_or("USERDNSDOMAIN", "");
    m.system_root = get_env_or("SystemRoot", r"C:\Windows");
    m.system32 = format!("{}\\System32", m.system_root.trim_end_matches('\\'));
    m.temp_dir = get_env_or("TEMP", "");
    m.current_directory = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    m.command_line = std::env::args().collect::<Vec<_>>().join(" ");
    m.process_id = std::process::id();
    m.machine_guid = reg_read_string("HKLM", r"SOFTWARE\Microsoft\Cryptography", "MachineGuid")
        .unwrap_or_default();
    m
}

// ==========================================================================
// OS Version
// ==========================================================================

fn collect_os_version() -> OsVersion {
    let mut v = OsVersion::default();

    #[cfg(target_os = "windows")]
    {
        use std::mem;
        use windows::Win32::System::SystemInformation::*;
        let mut info: OSVERSIONINFOEXW = unsafe { mem::zeroed() };
        info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOEXW>() as u32;
        unsafe {
            let _ = RtlGetVersion(&mut info);
        }
        v.major = info.dwMajorVersion;
        v.minor = info.dwMinorVersion;
        v.build = info.dwBuildNumber;
        v.platform_id = info.dwPlatformId;
        v.suite_mask = info.wSuiteMask;
        v.product_type = info.wProductType as u8;
        v.service_pack_major = info.wServicePackMajor;
        v.service_pack_minor = info.wServicePackMinor;
        let sp_end = info.szCSDVersion.iter().position(|&c| c == 0).unwrap_or(0);
        v.csd_version = String::from_utf16_lossy(&info.szCSDVersion[..sp_end]);
    }

    v.product_name = reg_read_string(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "ProductName",
    )
    .unwrap_or_default();
    v.product_id = reg_read_string(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "ProductId",
    )
    .unwrap_or_default();
    v.build_lab_ex = reg_read_string(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "BuildLabEx",
    )
    .unwrap_or_default();

    v
}

// ==========================================================================
// Locale
// ==========================================================================

fn collect_locale() -> LocaleProfile {
    let mut l = LocaleProfile::default();

    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::SystemInformation::*;
        l.acp = unsafe { GetACP() };
        l.oemcp = unsafe { GetOEMCP() };
    }

    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::Console::*;
        l.console_cp = unsafe { GetConsoleCP() };
        l.console_output_cp = unsafe { GetConsoleOutputCP() };
    }

    #[cfg(not(target_os = "windows"))]
    {
        l.acp = 936;
        l.oemcp = 936;
        l.console_cp = 936;
        l.console_output_cp = 936;
    }

    l
}

// ==========================================================================
// Display
// ==========================================================================

fn collect_display() -> DisplayProfile {
    let mut d = DisplayProfile {
        desktop_window_handle: 0x0010_0000,
        active_window_handle: 0x0010_0010,
        shell_window_handle: 0x0010_0020,
        default_dc_handle: 0x0012_0000,
        remote_session: get_env_or("SESSIONNAME", "").starts_with("RDP"),
        ..DisplayProfile::default()
    };

    #[cfg(target_os = "windows")]
    {
        use windows::Win32::UI::WindowsAndMessaging::*;
        unsafe {
            d.screen_width = GetSystemMetrics(SM_CXSCREEN);
            d.screen_height = GetSystemMetrics(SM_CYSCREEN);
            let mut pt = POINT { x: 0, y: 0 };
            let _ = GetCursorPos(&mut pt);
            d.cursor_x = pt.x;
            d.cursor_y = pt.y;
            d.message_x = pt.x;
            d.message_y = pt.y;
        }
    }

    d
}

// ==========================================================================
// Volume
// ==========================================================================

fn collect_volume() -> VolumeProfile {
    let mut v = VolumeProfile {
        root_path: r"C:\".to_string(),
        ..VolumeProfile::default()
    };

    #[cfg(target_os = "windows")]
    {
        use windows::core::*;
        use windows::Win32::Storage::FileSystem::*;
        let root = HSTRING::from(r"C:\");
        let mut vol_name = [0u16; 256];
        let mut fs_name = [0u16; 256];
        let mut serial = 0u32;
        let mut max_comp = 0u32;
        let mut flags = 0u32;
        unsafe {
            let _ = GetVolumeInformationW(
                PCWSTR(root.as_ptr()),
                Some(&mut vol_name),
                Some(&mut serial),
                Some(&mut max_comp),
                Some(&mut flags),
                Some(&mut fs_name),
            );
            v.volume_name = wide_to_string(&vol_name);
            v.serial = serial;
            v.max_component_length = max_comp;
            v.flags = flags;
            v.fs_name = wide_to_string(&fs_name);
            v.drive_type = GetDriveTypeW(PCWSTR(root.as_ptr()));

            let mut total: u64 = 0;
            let mut free: u64 = 0;
            let mut avail: u64 = 0;
            let _ = GetDiskFreeSpaceExW(
                PCWSTR(root.as_ptr()),
                Some(&mut avail),
                Some(&mut total),
                Some(&mut free),
            );
            v.total_bytes = total;
            v.free_bytes = free;
            v.available_bytes = avail;
        }
    }

    v
}

// ==========================================================================
// Shell Folders
// ==========================================================================

fn collect_shell_folders() -> ShellFolderProfile {
    let up = get_env_or("USERPROFILE", r"C:\Users\Default");
    let app_data = get_env_or(
        "APPDATA",
        format!("{}\\AppData\\Roaming", up.trim_end_matches('\\')),
    );
    let prog_data = get_env_or("PROGRAMDATA", r"C:\ProgramData".to_string());
    let pf = get_env_or("PROGRAMFILES", r"C:\Program Files".to_string());
    let pfx = get_env_or("PROGRAMFILES(X86)", r"C:\Program Files (x86)".to_string());

    ShellFolderProfile {
        profile: up.clone(),
        desktop: format!("{}\\Desktop", up.trim_end_matches('\\')),
        app_data: app_data.clone(),
        local_app_data: get_env_or(
            "LOCALAPPDATA",
            format!("{}\\AppData\\Local", up.trim_end_matches('\\')),
        ),
        program_data: prog_data.clone(),
        startup: format!(
            "{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            app_data.trim_end_matches('\\')
        ),
        personal: format!("{}\\Documents", up.trim_end_matches('\\')),
        public: get_env_or("PUBLIC", r"C:\Users\Public".to_string()),
        program_files: pf.clone(),
        program_files_x86: pfx.clone(),
        common_files: format!("{}\\Common Files", pf.trim_end_matches('\\')),
        common_files_x86: format!("{}\\Common Files", pfx.trim_end_matches('\\')),
        common_startup: format!(
            "{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            prog_data.trim_end_matches('\\')
        ),
        common_desktop: r"C:\Users\Public\Desktop".to_string(),
    }
}

// ==========================================================================
// Network
// ==========================================================================

fn collect_network() -> NetworkProfile {
    let mut net = NetworkProfile {
        host_name: get_env_or("COMPUTERNAME", ""),
        enable_dns: true,
        ..NetworkProfile::default()
    };

    #[cfg(target_os = "windows")]
    {
        use windows::Win32::NetworkManagement::IpHelper::*;
        let mut buf_len = 0u32;
        unsafe {
            let _ = GetAdaptersInfo(None, &mut buf_len);
        }
        if buf_len > 0 {
            let mut buffer = vec![0u8; buf_len as usize];
            let ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;
            if unsafe { GetAdaptersInfo(Some(ptr), &mut buf_len) } == 0 {
                let mut cur = ptr;
                while !cur.is_null() {
                    let a = unsafe { &*cur };
                    let desc = cstr_to_string(a.Description.as_ptr() as *const i8);
                    let name = cstr_to_string(a.AdapterName.as_ptr() as *const i8);
                    let mac = format!(
                        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        a.Address[0],
                        a.Address[1],
                        a.Address[2],
                        a.Address[3],
                        a.Address[4],
                        a.Address[5],
                    );
                    let ip = cstr_to_string(a.IpAddressList.IpAddress.String.as_ptr() as *const i8);
                    let mask = cstr_to_string(a.IpAddressList.IpMask.String.as_ptr() as *const i8);
                    let gw = cstr_to_string(a.GatewayList.IpAddress.String.as_ptr() as *const i8);
                    let dhcp = cstr_to_string(a.DhcpServer.IpAddress.String.as_ptr() as *const i8);
                    if !ip.is_empty() && ip != "0.0.0.0" {
                        net.adapters.push(NetworkAdapter {
                            name: format!("{{{name}}}"),
                            description: desc,
                            if_index: a.Index,
                            adapter_type: a.Type,
                            mac_address: mac,
                            dhcp_enabled: a.DhcpEnabled != 0,
                            dhcp_server: dhcp,
                            ipv4_addresses: vec![IpAddress {
                                address: ip,
                                netmask: mask,
                            }],
                            gateways: if gw.is_empty() { vec![] } else { vec![gw] },
                            ..NetworkAdapter::default()
                        });
                    }
                    cur = a.Next;
                }
            }
        }
    }

    net
}

// ==========================================================================
// Environment Variables
// ==========================================================================

fn collect_environment_variables() -> Vec<EnvironmentVariable> {
    const NAMES: &[&str] = &[
        "APPDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "OS",
        "PATH",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERNAME",
        "USERPROFILE",
        "COMPUTERNAME",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMDATA",
        "PUBLIC",
        "LOCALAPPDATA",
        "WINDIR",
        "PATHEXT",
        "SYSTEMDRIVE",
        "NUMBER_OF_PROCESSORS",
    ];
    NAMES
        .iter()
        .filter_map(|&n| {
            std::env::var(n).ok().map(|v| EnvironmentVariable {
                name: n.to_string(),
                value: v,
            })
        })
        .collect()
}

// ==========================================================================
// Processes
// ==========================================================================

fn collect_processes() -> Vec<ProcessEntry> {
    let mut procs = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::mem;
        use windows::core::PWSTR;
        use windows::Win32::Foundation::*;
        use windows::Win32::System::Diagnostics::ToolHelp::*;
        use windows::Win32::System::Threading::*;

        unsafe {
            if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                let mut entry: PROCESSENTRY32W = mem::zeroed();
                entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32FirstW(snap, &mut entry).is_ok() {
                    loop {
                        let exe = wide_to_string(&entry.szExeFile);
                        let pid = entry.th32ProcessID;
                        let ppid = entry.th32ParentProcessID;
                        let img = if let Ok(h) =
                            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                        {
                            let mut buf = [0u16; 512];
                            let mut sz = buf.len() as u32;
                            let r =
                                if windows::Win32::System::Threading::QueryFullProcessImageNameW(
                                    h,
                                    PROCESS_NAME_FORMAT(0),
                                    PWSTR(buf.as_mut_ptr()),
                                    &mut sz,
                                )
                                .is_ok()
                                {
                                    wide_to_string(&buf[..sz as usize])
                                } else {
                                    exe.clone()
                                };
                            let _ = CloseHandle(h);
                            r
                        } else {
                            exe.clone()
                        };
                        procs.push(ProcessEntry {
                            pid,
                            parent_pid: ppid,
                            image_path: img,
                            ..ProcessEntry::default()
                        });
                        if Process32NextW(snap, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snap);
            }
        }
    }

    procs
}

// ==========================================================================
// Users
// ==========================================================================

fn collect_users() -> Vec<UserAccount> {
    let mut users = Vec::new();
    let profiles_dir = std::path::PathBuf::from(r"C:\Users");
    if let Ok(entries) = std::fs::read_dir(&profiles_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.')
                || name.eq_ignore_ascii_case("Default")
                || name.eq_ignore_ascii_case("Default User")
                || name.eq_ignore_ascii_case("All Users")
                || name.eq_ignore_ascii_case("Public")
            {
                continue;
            }
            users.push(UserAccount {
                name: name.clone(),
                home_dir: format!(r"C:\Users\{name}"),
                ..UserAccount::default()
            });
        }
    }
    users.push(UserAccount {
        name: "Administrator".to_string(),
        privilege_level: 2,
        rid: 500,
        ..UserAccount::default()
    });
    users.push(UserAccount {
        name: "Guest".to_string(),
        flags: 0x0083,
        privilege_level: 0,
        rid: 501,
        ..UserAccount::default()
    });
    users
}

// ==========================================================================
// Local Groups
// ==========================================================================

fn collect_local_groups() -> Vec<LocalGroup> {
    vec![
        LocalGroup {
            name: "Administrators".into(),
            comment: "Administrators have complete and unrestricted access".into(),
            domain: "BUILTIN".into(),
            rid: 544,
            members: vec![],
        },
        LocalGroup {
            name: "Users".into(),
            comment:
                "Users are prevented from making accidental or intentional system-wide changes"
                    .into(),
            domain: "BUILTIN".into(),
            rid: 545,
            members: vec![],
        },
        LocalGroup {
            name: "Guests".into(),
            comment: "Guests have the same access as members of the Users group".into(),
            domain: "BUILTIN".into(),
            rid: 546,
            members: vec![],
        },
    ]
}

// ==========================================================================
// Services
// ==========================================================================

fn collect_services() -> Vec<ServiceEntry> {
    let mut services = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::mem;
        use windows::core::*;
        use windows::Win32::System::Services::*;

        unsafe {
            if let Ok(mgr) = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) {
                let mut needed = 0u32;
                let mut returned = 0u32;
                let mut resume = 0u32;

                let _ = EnumServicesStatusW(
                    mgr,
                    SERVICE_TYPE(SERVICE_WIN32.0),
                    SERVICE_STATE(SERVICE_STATE_ALL.0),
                    None,
                    0,
                    &mut needed,
                    &mut returned,
                    Some(&mut resume),
                );

                let buf_size = needed as usize + 4096;
                let count = buf_size / mem::size_of::<ENUM_SERVICE_STATUSW>();
                let mut buf = vec![0u8; buf_size];
                let ptr = buf.as_mut_ptr() as *mut ENUM_SERVICE_STATUSW;

                if EnumServicesStatusW(
                    mgr,
                    SERVICE_TYPE(SERVICE_WIN32.0),
                    SERVICE_STATE(SERVICE_STATE_ALL.0),
                    Some(ptr),
                    buf_size as u32,
                    &mut needed,
                    &mut returned,
                    None,
                )
                .is_ok()
                {
                    for i in 0..returned as usize {
                        let svc = &*ptr.add(i);
                        let name = wide_to_string(&*svc.lpServiceName);
                        let display = wide_to_string(&*svc.lpDisplayName);
                        let mut entry = ServiceEntry {
                            name,
                            display_name: display,
                            current_state: svc.ServiceStatus.dwCurrentState,
                            process_id: svc.ServiceStatus.dwProcessId,
                            service_type: svc.ServiceStatus.dwServiceType,
                            ..ServiceEntry::default()
                        };

                        let svc_hstr = HSTRING::from(&entry.name);
                        if let Ok(hsvc) = OpenServiceW(mgr, &svc_hstr, SERVICE_QUERY_CONFIG) {
                            // Binary path + start type.
                            let mut cb = 0u32;
                            let _ = QueryServiceConfigW(hsvc, None, 0, &mut cb);
                            if cb > 0 {
                                let mut cfg_buf = vec![0u8; cb as usize];
                                let cfg_ptr = cfg_buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
                                if QueryServiceConfigW(hsvc, Some(cfg_ptr), cb, &mut cb).is_ok() {
                                    let cfg = cfg_buf.as_ptr() as *const QUERY_SERVICE_CONFIGW;
                                    entry.start_type = (*cfg).dwStartType;
                                    if !(*cfg).lpBinaryPathName.is_null() {
                                        entry.binary_path =
                                            wide_to_string(&*(*cfg).lpBinaryPathName);
                                    }
                                }
                            }
                            // Description.
                            let mut cb2 = 0u32;
                            let _ = QueryServiceConfig2W(
                                hsvc,
                                SERVICE_CONFIG_DESCRIPTION,
                                None,
                                &mut cb2,
                            );
                            if cb2 > 0 {
                                let mut desc_buf = vec![0u8; cb2 as usize];
                                if QueryServiceConfig2W(
                                    hsvc,
                                    SERVICE_CONFIG_DESCRIPTION,
                                    Some(desc_buf.as_mut_slice()),
                                    &mut cb2,
                                )
                                .is_ok()
                                {
                                    let desc = desc_buf.as_ptr() as *const SERVICE_DESCRIPTIONW;
                                    if !(*desc).lpDescription.is_null() {
                                        entry.description = wide_to_string(&*(*desc).lpDescription);
                                    }
                                }
                            }
                            let _ = CloseServiceHandle(hsvc);
                        }
                        services.push(entry);
                    }
                }
                let _ = CloseServiceHandle(mgr);
            }
        }
    }

    services
}

// ==========================================================================
// Registry
// ==========================================================================

fn collect_registry() -> RegistrySnapshot {
    let mut snap = RegistrySnapshot::default();

    let hklm_paths: &[&str] = &[
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        r"SOFTWARE\Microsoft\Cryptography",
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
        r"SOFTWARE\Microsoft\Windows Defender",
    ];
    for path in hklm_paths {
        if let Some(key) = collect_reg_key("HKLM", path) {
            snap.keys.push(key);
        }
    }

    let hkcu_paths: &[&str] = &[
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"Environment",
    ];
    for path in hkcu_paths {
        if let Some(key) = collect_reg_key("HKCU", path) {
            snap.keys.push(key);
        }
    }

    snap
}

fn collect_reg_key(_root: &str, _relative: &str) -> Option<RegistryKey> {
    #[cfg(target_os = "windows")]
    {
        use windows::core::*;
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::*;

        let root_key = if _root == "HKLM" {
            HKEY_LOCAL_MACHINE
        } else {
            HKEY_CURRENT_USER
        };
        let root_name = if _root == "HKLM" {
            "HKEY_LOCAL_MACHINE"
        } else {
            "HKEY_CURRENT_USER"
        };
        let full_path = format!("{root_name}\\{_relative}");

        let wpath = HSTRING::from(_relative);
        let mut handle: HKEY = HKEY::default();
        if unsafe { RegOpenKeyExW(root_key, PCWSTR(wpath.as_ptr()), 0, KEY_READ, &mut handle) }
            != ERROR_SUCCESS
        {
            return None;
        }

        let values = enum_reg_values(handle);
        unsafe {
            let _ = RegCloseKey(handle);
        }
        Some(RegistryKey {
            path: full_path,
            values,
        })
    }

    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

#[cfg(target_os = "windows")]
fn enum_reg_values(key: windows::Win32::System::Registry::HKEY) -> Vec<RegistryValue> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::*;
    let mut values = Vec::new();
    let mut idx = 0u32;
    loop {
        let mut name_buf = [0u16; 512];
        let mut name_len = name_buf.len() as u32;
        let mut vtype = 0u32;
        let mut data_len = 0u32;
        if unsafe {
            RegEnumValueW(
                key,
                idx,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                Some(&mut vtype),
                None,
                Some(&mut data_len),
            )
        } != ERROR_SUCCESS
        {
            break;
        }
        let name = wide_to_string(&name_buf[..name_len as usize]);
        let mut data = vec![0u8; data_len as usize];
        let _ = unsafe {
            RegEnumValueW(
                key,
                idx,
                PWSTR::null(),
                std::ptr::null_mut(),
                None,
                None,
                Some(data.as_mut_ptr()),
                Some(&mut data_len),
            )
        };

        let rv = match vtype {
            1 | 2 => RegistryValue {
                name,
                value_type: vtype,
                string: Some(wide_bytes_to_string(&data)),
                dword: None,
                qword: None,
                multi_string: None,
                binary_hex: None,
            },
            4 => RegistryValue {
                name,
                value_type: vtype,
                string: None,
                dword: Some(if data.len() >= 4 {
                    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                } else {
                    0
                }),
                qword: None,
                multi_string: None,
                binary_hex: None,
            },
            11 => RegistryValue {
                name,
                value_type: vtype,
                string: None,
                dword: None,
                qword: Some(if data.len() >= 8 {
                    u64::from_le_bytes(data[..8].try_into().unwrap_or([0; 8]))
                } else {
                    0
                }),
                multi_string: None,
                binary_hex: None,
            },
            7 => RegistryValue {
                name,
                value_type: vtype,
                string: None,
                dword: None,
                qword: None,
                multi_string: Some(wide_bytes_to_multi_string(&data)),
                binary_hex: None,
            },
            _ => RegistryValue {
                name,
                value_type: vtype,
                string: None,
                dword: None,
                qword: None,
                multi_string: None,
                binary_hex: Some(data.iter().map(|b| format!("{b:02X}")).collect()),
            },
        };
        values.push(rv);
        idx += 1;
    }
    values
}

// ==========================================================================
// System32 File Enumeration
// ==========================================================================

fn collect_system32_files() -> Vec<String> {
    let sys32 = get_env_or("SystemRoot", r"C:\Windows") + r"\System32";
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&sys32) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let lower = name.to_ascii_lowercase();
            if lower.ends_with(".dll") || lower.ends_with(".exe") || lower.ends_with(".sys") {
                files.push(name);
            }
        }
    }
    files.sort_by(|a, b| a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()));
    files
}

// ==========================================================================
// Helpers
// ==========================================================================

fn get_env_or(name: &str, default: impl Into<String>) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

fn reg_read_string(_root: &str, _path: &str, _name: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        use windows::core::*;
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::*;
        let root_key = if _root == "HKLM" {
            HKEY_LOCAL_MACHINE
        } else {
            HKEY_CURRENT_USER
        };
        let wpath = HSTRING::from(_path);
        let wname = HSTRING::from(_name);
        let mut handle: HKEY = HKEY::default();
        unsafe {
            if RegOpenKeyExW(root_key, PCWSTR(wpath.as_ptr()), 0, KEY_READ, &mut handle)
                != ERROR_SUCCESS
            {
                return None;
            }
            let mut buf_len = 0u32;
            let mut vtype = REG_VALUE_TYPE(0);
            let _ = RegQueryValueExW(
                handle,
                PCWSTR(wname.as_ptr()),
                None,
                Some(&mut vtype),
                None,
                Some(&mut buf_len),
            );
            if buf_len == 0 {
                let _ = RegCloseKey(handle);
                return Some(String::new());
            }
            let mut buf = vec![0u8; buf_len as usize];
            let ok = RegQueryValueExW(
                handle,
                PCWSTR(wname.as_ptr()),
                None,
                None,
                Some(buf.as_mut_ptr()),
                Some(&mut buf_len),
            );
            let _ = RegCloseKey(handle);
            if ok == ERROR_SUCCESS {
                Some(wide_bytes_to_string(&buf))
            } else {
                None
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(target_os = "windows")]
fn cstr_to_string(ptr: *const i8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string() }
}

fn wide_bytes_to_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn wide_bytes_to_multi_string(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let mut strings = Vec::new();
    let mut start = 0;
    for (i, &u) in units.iter().enumerate() {
        if u == 0 {
            if start < i {
                strings.push(String::from_utf16_lossy(&units[start..i]));
            }
            start = i + 1;
        }
    }
    strings
}
