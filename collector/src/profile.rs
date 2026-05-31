//! Output types matching the HVM EnvironmentProfile structure.

use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(default)]
pub struct EnvironmentProfile {
    pub machine: MachineIdentity,
    pub os_version: OsVersion,
    pub locale: LocaleProfile,
    pub display: DisplayProfile,
    pub volume: VolumeProfile,
    pub shell_folders: ShellFolderProfile,
    pub network: NetworkProfile,
    pub environment_variables: Vec<EnvironmentVariable>,
    pub processes: Vec<ProcessEntry>,
    pub users: Vec<UserAccount>,
    pub local_groups: Vec<LocalGroup>,
    pub services: Vec<ServiceEntry>,
    pub registry: RegistrySnapshot,
    pub system32_files: Vec<String>,
}

impl Default for EnvironmentProfile {
    fn default() -> Self {
        Self {
            machine: MachineIdentity::default(),
            os_version: OsVersion::default(),
            locale: LocaleProfile::default(),
            display: DisplayProfile::default(),
            volume: VolumeProfile::default(),
            shell_folders: ShellFolderProfile::default(),
            network: NetworkProfile::default(),
            environment_variables: Vec::new(),
            processes: Vec::new(),
            users: Vec::new(),
            local_groups: Vec::new(),
            services: Vec::new(),
            registry: RegistrySnapshot::default(),
            system32_files: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct MachineIdentity {
    pub computer_name: String,
    pub user_name: String,
    pub user_domain: String,
    pub dns_domain_name: String,
    pub forest_name: String,
    pub domain_controller: String,
    pub domain_guid: String,
    pub machine_guid: String,
    pub process_id: u32,
    pub image_path: String,
    pub parent_process_id: u32,
    pub parent_image_path: String,
    pub parent_command_line: String,
    pub system_root: String,
    pub system32: String,
    pub temp_dir: String,
    pub current_directory: String,
    pub command_line: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct OsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform_id: u32,
    pub suite_mask: u16,
    pub product_type: u8,
    pub service_pack_major: u16,
    pub service_pack_minor: u16,
    pub csd_version: String,
    pub product_name: String,
    pub product_id: String,
    pub build_lab_ex: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct LocaleProfile {
    pub acp: u32,
    pub oemcp: u32,
    pub console_cp: u32,
    pub console_output_cp: u32,
    pub user_default_lcid: u32,
    pub thread_locale: u32,
    pub system_default_ui_language: u32,
    pub user_default_ui_language: u32,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct DisplayProfile {
    pub desktop_window_handle: u32,
    pub active_window_handle: u32,
    pub shell_window_handle: u32,
    pub default_dc_handle: u32,
    pub screen_width: i32,
    pub screen_height: i32,
    pub cursor_x: i32,
    pub cursor_y: i32,
    pub message_x: i32,
    pub message_y: i32,
    pub message_step_x: i32,
    pub message_step_y: i32,
    pub remote_session: bool,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct VolumeProfile {
    pub root_path: String,
    pub volume_name: String,
    pub serial: u32,
    pub max_component_length: u32,
    pub flags: u32,
    pub fs_name: String,
    pub drive_type: u32,
    pub physical_drive_count: u32,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub volume_guid: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct ShellFolderProfile {
    pub profile: String,
    pub desktop: String,
    pub app_data: String,
    pub local_app_data: String,
    pub program_data: String,
    pub startup: String,
    pub personal: String,
    pub public: String,
    pub program_files: String,
    pub program_files_x86: String,
    pub common_files: String,
    pub common_files_x86: String,
    pub common_startup: String,
    pub common_desktop: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct NetworkProfile {
    pub host_name: String,
    pub domain_name: String,
    pub dns_suffix: String,
    pub dns_servers: Vec<String>,
    pub node_type: u32,
    pub scope_id: String,
    pub enable_routing: bool,
    pub enable_proxy: bool,
    pub enable_dns: bool,
    pub adapters: Vec<NetworkAdapter>,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct NetworkAdapter {
    pub name: String,
    pub description: String,
    pub friendly_name: String,
    pub dns_suffix: String,
    pub if_index: u32,
    pub adapter_type: u32,
    pub mac_address: String,
    pub mtu: u32,
    pub oper_status: u32,
    pub ipv4_addresses: Vec<IpAddress>,
    pub gateways: Vec<String>,
    pub dns_servers: Vec<String>,
    pub dhcp_enabled: bool,
    pub dhcp_server: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct IpAddress {
    pub address: String,
    pub netmask: String,
}

#[derive(Debug, Default, Serialize)]
pub struct EnvironmentVariable {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_path: String,
    pub command_line: String,
    pub current_directory: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct UserAccount {
    pub name: String,
    pub full_name: String,
    pub comment: String,
    pub flags: u32,
    pub privilege_level: u32,
    pub home_dir: String,
    pub script_path: String,
    pub rid: u32,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct LocalGroup {
    pub name: String,
    pub comment: String,
    pub domain: String,
    pub rid: u32,
    pub members: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct ServiceEntry {
    pub name: String,
    pub display_name: String,
    pub service_type: u32,
    pub start_type: u32,
    pub error_control: u32,
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub check_point: u32,
    pub wait_hint: u32,
    pub process_id: u32,
    pub binary_path: String,
    pub load_order_group: String,
    pub tag_id: u32,
    pub dependencies: Vec<String>,
    pub start_name: String,
    pub description: String,
    pub delayed_auto_start: bool,
}

#[derive(Debug, Default, Serialize)]
#[serde(default)]
pub struct RegistrySnapshot {
    pub keys: Vec<RegistryKey>,
}

#[derive(Debug, Default, Serialize)]
pub struct RegistryKey {
    pub path: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<RegistryValue>,
}

#[derive(Debug, Serialize)]
pub struct RegistryValue {
    pub name: String,
    pub value_type: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dword: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qword: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_string: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_hex: Option<String>,
}
