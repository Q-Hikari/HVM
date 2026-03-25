use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::VmError;
use crate::managers::registry_manager::RegistryManager;

const DEFAULT_PROCESS_ID: u32 = 0x1337;
const DEFAULT_PARENT_PROCESS_ID: u32 = 0x1200;
const CURRENT_VERSION_KEY: &str =
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
const CRYPTOGRAPHY_KEY: &str = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EnvironmentProfile {
    pub machine: MachineIdentity,
    pub os_version: OsVersion,
    pub locale: LocaleProfile,
    pub display: DisplayProfile,
    pub volume: VolumeProfile,
    pub shell_folders: ShellFolderProfile,
    pub network: NetworkProfile,
    pub module_search_paths: Vec<PathBuf>,
    pub environment_variables: Vec<EnvironmentVariableProfile>,
    pub processes: Vec<ProcessProfile>,
    pub users: Vec<UserAccountProfile>,
    pub local_groups: Vec<LocalGroupProfile>,
    pub shares: Vec<ShareProfile>,
    pub network_uses: Vec<NetworkUseProfile>,
    pub workstation_users: Vec<WorkstationUserProfile>,
    pub network_sessions: Vec<NetworkSessionProfile>,
    pub open_files: Vec<OpenFileProfile>,
    pub services: Vec<ServiceProfile>,
    pub registry: RegistrySnapshot,
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
            module_search_paths: Vec::new(),
            environment_variables: Vec::new(),
            processes: Vec::new(),
            users: default_users(),
            local_groups: default_local_groups(),
            shares: Vec::new(),
            network_uses: Vec::new(),
            workstation_users: Vec::new(),
            network_sessions: Vec::new(),
            open_files: Vec::new(),
            services: default_services(),
            registry: RegistrySnapshot::default(),
        }
    }
}

impl EnvironmentProfile {
    pub fn load(path: &Path) -> Result<Self, VmError> {
        let path = PathBuf::from(path);
        let raw = fs::read_to_string(&path).map_err(|source| VmError::ReadEnvironmentProfile {
            path: path.clone(),
            source,
        })?;
        let mut profile: Self =
            serde_json::from_str(&raw).map_err(|source| VmError::ParseEnvironmentProfile {
                path: path.clone(),
                source,
            })?;
        let base = path.parent().unwrap_or(Path::new("."));
        for search_path in &mut profile.module_search_paths {
            if search_path.is_relative() {
                *search_path = base.join(&search_path);
            }
        }
        Ok(profile)
    }

    pub fn has_parent_process(&self) -> bool {
        !self.machine.parent_image_path.is_empty() || !self.machine.parent_command_line.is_empty()
    }

    pub fn apply_to_registry(&self, registry: &mut RegistryManager) -> Result<(), VmError> {
        let current_version = [
            (
                "ProductName",
                1u32,
                encode_utf16_string(&self.os_version.product_name),
            ),
            (
                "CurrentBuild",
                1u32,
                encode_utf16_string(&self.os_version.build.to_string()),
            ),
            (
                "CurrentVersion",
                1u32,
                encode_utf16_string(&format!(
                    "{}.{}",
                    self.os_version.major, self.os_version.minor
                )),
            ),
        ];
        for (name, value_type, data) in current_version {
            registry.set_value_at_path(CURRENT_VERSION_KEY, name, value_type, &data);
        }
        if !self.os_version.build_lab_ex.is_empty() {
            registry.set_value_at_path(
                CURRENT_VERSION_KEY,
                "BuildLabEx",
                1,
                &encode_utf16_string(&self.os_version.build_lab_ex),
            );
        }
        if !self.os_version.csd_version.is_empty() {
            registry.set_value_at_path(
                CURRENT_VERSION_KEY,
                "CSDVersion",
                1,
                &encode_utf16_string(&self.os_version.csd_version),
            );
        }
        if !self.os_version.product_id.is_empty() {
            registry.set_value_at_path(
                CURRENT_VERSION_KEY,
                "ProductId",
                1,
                &encode_utf16_string(&self.os_version.product_id),
            );
        }
        if !self.machine.machine_guid.is_empty() {
            registry.set_value_at_path(
                CRYPTOGRAPHY_KEY,
                "MachineGuid",
                1,
                &encode_utf16_string(&self.machine.machine_guid),
            );
        }

        for key in &self.registry.keys {
            for value in &key.values {
                let data = value
                    .encoded_data()
                    .map_err(|detail| VmError::EnvironmentProfileData { detail })?;
                registry.set_value_at_path(&key.path, &value.name, value.value_type, &data);
            }
        }
        Ok(())
    }

    pub fn apply_overrides(&mut self, overrides: &EnvironmentOverrides) {
        if let Some(machine) = &overrides.machine {
            machine.apply_to(&mut self.machine);
        }
        if let Some(os_version) = &overrides.os_version {
            os_version.apply_to(&mut self.os_version);
        }
        if let Some(locale) = &overrides.locale {
            locale.apply_to(&mut self.locale);
        }
        if let Some(display) = &overrides.display {
            display.apply_to(&mut self.display);
        }
        if let Some(volume) = &overrides.volume {
            volume.apply_to(&mut self.volume);
        }
        if let Some(shell_folders) = &overrides.shell_folders {
            shell_folders.apply_to(&mut self.shell_folders);
        }
        if let Some(network) = &overrides.network {
            network.apply_to(&mut self.network);
        }
        if let Some(environment_variables) = &overrides.environment_variables {
            for variable in environment_variables {
                if let Some(existing) = self
                    .environment_variables
                    .iter_mut()
                    .find(|entry| entry.name.eq_ignore_ascii_case(&variable.name))
                {
                    *existing = variable.clone();
                } else {
                    self.environment_variables.push(variable.clone());
                }
            }
        }
        if let Some(processes) = &overrides.processes {
            self.processes = processes.clone();
        }
        if let Some(users) = &overrides.users {
            self.users = users.clone();
        }
        if let Some(local_groups) = &overrides.local_groups {
            self.local_groups = local_groups.clone();
        }
        if let Some(shares) = &overrides.shares {
            self.shares = shares.clone();
        }
        if let Some(network_uses) = &overrides.network_uses {
            self.network_uses = network_uses.clone();
        }
        if let Some(workstation_users) = &overrides.workstation_users {
            self.workstation_users = workstation_users.clone();
        }
        if let Some(network_sessions) = &overrides.network_sessions {
            self.network_sessions = network_sessions.clone();
        }
        if let Some(open_files) = &overrides.open_files {
            self.open_files = open_files.clone();
        }
        if let Some(services) = &overrides.services {
            self.services = services.clone();
        }
        if let Some(registry) = &overrides.registry {
            self.registry = registry.clone();
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct EnvironmentOverrides {
    pub machine: Option<MachineIdentityOverrides>,
    pub os_version: Option<OsVersionOverrides>,
    pub locale: Option<LocaleProfileOverrides>,
    pub display: Option<DisplayProfileOverrides>,
    pub volume: Option<VolumeProfileOverrides>,
    pub shell_folders: Option<ShellFolderOverrides>,
    pub network: Option<NetworkProfileOverrides>,
    pub environment_variables: Option<Vec<EnvironmentVariableProfile>>,
    pub processes: Option<Vec<ProcessProfile>>,
    pub users: Option<Vec<UserAccountProfile>>,
    pub local_groups: Option<Vec<LocalGroupProfile>>,
    pub shares: Option<Vec<ShareProfile>>,
    pub network_uses: Option<Vec<NetworkUseProfile>>,
    pub workstation_users: Option<Vec<WorkstationUserProfile>>,
    pub network_sessions: Option<Vec<NetworkSessionProfile>>,
    pub open_files: Option<Vec<OpenFileProfile>>,
    pub services: Option<Vec<ServiceProfile>>,
    pub registry: Option<RegistrySnapshot>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct MachineIdentityOverrides {
    pub computer_name: Option<String>,
    pub user_name: Option<String>,
    pub user_domain: Option<String>,
    pub dns_domain_name: Option<String>,
    pub forest_name: Option<String>,
    pub domain_controller: Option<String>,
    pub domain_guid: Option<String>,
    pub machine_guid: Option<String>,
    pub process_id: Option<u32>,
    pub image_path: Option<String>,
    pub parent_process_id: Option<u32>,
    pub parent_image_path: Option<String>,
    pub parent_command_line: Option<String>,
    pub system_root: Option<String>,
    pub system32: Option<String>,
    pub temp_dir: Option<String>,
    pub current_directory: Option<String>,
    pub command_line: Option<String>,
}

impl MachineIdentityOverrides {
    fn apply_to(&self, target: &mut MachineIdentity) {
        if let Some(value) = &self.computer_name {
            target.computer_name = value.clone();
        }
        if let Some(value) = &self.user_name {
            target.user_name = value.clone();
        }
        if let Some(value) = &self.user_domain {
            target.user_domain = value.clone();
        }
        if let Some(value) = &self.dns_domain_name {
            target.dns_domain_name = value.clone();
        }
        if let Some(value) = &self.forest_name {
            target.forest_name = value.clone();
        }
        if let Some(value) = &self.domain_controller {
            target.domain_controller = value.clone();
        }
        if let Some(value) = &self.domain_guid {
            target.domain_guid = value.clone();
        }
        if let Some(value) = &self.machine_guid {
            target.machine_guid = value.clone();
        }
        if let Some(value) = self.process_id {
            target.process_id = value;
        }
        if let Some(value) = &self.image_path {
            target.image_path = value.clone();
        }
        if let Some(value) = self.parent_process_id {
            target.parent_process_id = value;
        }
        if let Some(value) = &self.parent_image_path {
            target.parent_image_path = value.clone();
        }
        if let Some(value) = &self.parent_command_line {
            target.parent_command_line = value.clone();
        }
        if let Some(value) = &self.system_root {
            target.system_root = value.clone();
        }
        if let Some(value) = &self.system32 {
            target.system32 = value.clone();
        }
        if let Some(value) = &self.temp_dir {
            target.temp_dir = value.clone();
        }
        if let Some(value) = &self.current_directory {
            target.current_directory = value.clone();
        }
        if let Some(value) = &self.command_line {
            target.command_line = value.clone();
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct OsVersionOverrides {
    pub major: Option<u32>,
    pub minor: Option<u32>,
    pub build: Option<u32>,
    pub platform_id: Option<u32>,
    pub suite_mask: Option<u16>,
    pub product_type: Option<u8>,
    pub service_pack_major: Option<u16>,
    pub service_pack_minor: Option<u16>,
    pub csd_version: Option<String>,
    pub product_name: Option<String>,
    pub product_id: Option<String>,
    pub build_lab_ex: Option<String>,
}

impl OsVersionOverrides {
    fn apply_to(&self, target: &mut OsVersion) {
        if let Some(value) = self.major {
            target.major = value;
        }
        if let Some(value) = self.minor {
            target.minor = value;
        }
        if let Some(value) = self.build {
            target.build = value;
        }
        if let Some(value) = self.platform_id {
            target.platform_id = value;
        }
        if let Some(value) = self.suite_mask {
            target.suite_mask = value;
        }
        if let Some(value) = self.product_type {
            target.product_type = value;
        }
        if let Some(value) = self.service_pack_major {
            target.service_pack_major = value;
        }
        if let Some(value) = self.service_pack_minor {
            target.service_pack_minor = value;
        }
        if let Some(value) = &self.csd_version {
            target.csd_version = value.clone();
        }
        if let Some(value) = &self.product_name {
            target.product_name = value.clone();
        }
        if let Some(value) = &self.product_id {
            target.product_id = value.clone();
        }
        if let Some(value) = &self.build_lab_ex {
            target.build_lab_ex = value.clone();
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct LocaleProfileOverrides {
    pub acp: Option<u32>,
    pub oemcp: Option<u32>,
    pub console_cp: Option<u32>,
    pub console_output_cp: Option<u32>,
    pub user_default_lcid: Option<u32>,
    pub thread_locale: Option<u32>,
    pub system_default_ui_language: Option<u32>,
    pub user_default_ui_language: Option<u32>,
}

impl LocaleProfileOverrides {
    fn apply_to(&self, target: &mut LocaleProfile) {
        if let Some(value) = self.acp {
            target.acp = value;
        }
        if let Some(value) = self.oemcp {
            target.oemcp = value;
        }
        if let Some(value) = self.console_cp {
            target.console_cp = value;
        }
        if let Some(value) = self.console_output_cp {
            target.console_output_cp = value;
        }
        if let Some(value) = self.user_default_lcid {
            target.user_default_lcid = value;
        }
        if let Some(value) = self.thread_locale {
            target.thread_locale = value;
        }
        if let Some(value) = self.system_default_ui_language {
            target.system_default_ui_language = value;
        }
        if let Some(value) = self.user_default_ui_language {
            target.user_default_ui_language = value;
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct DisplayProfileOverrides {
    pub desktop_window_handle: Option<u32>,
    pub active_window_handle: Option<u32>,
    pub shell_window_handle: Option<u32>,
    pub default_dc_handle: Option<u32>,
    pub screen_width: Option<i32>,
    pub screen_height: Option<i32>,
    pub cursor_x: Option<i32>,
    pub cursor_y: Option<i32>,
    pub message_x: Option<i32>,
    pub message_y: Option<i32>,
    pub message_step_x: Option<i32>,
    pub message_step_y: Option<i32>,
    pub remote_session: Option<bool>,
}

impl DisplayProfileOverrides {
    fn apply_to(&self, target: &mut DisplayProfile) {
        if let Some(value) = self.desktop_window_handle {
            target.desktop_window_handle = value;
        }
        if let Some(value) = self.active_window_handle {
            target.active_window_handle = value;
        }
        if let Some(value) = self.shell_window_handle {
            target.shell_window_handle = value;
        }
        if let Some(value) = self.default_dc_handle {
            target.default_dc_handle = value;
        }
        if let Some(value) = self.screen_width {
            target.screen_width = value;
        }
        if let Some(value) = self.screen_height {
            target.screen_height = value;
        }
        if let Some(value) = self.cursor_x {
            target.cursor_x = value;
        }
        if let Some(value) = self.cursor_y {
            target.cursor_y = value;
        }
        if let Some(value) = self.message_x {
            target.message_x = value;
        }
        if let Some(value) = self.message_y {
            target.message_y = value;
        }
        if let Some(value) = self.message_step_x {
            target.message_step_x = value;
        }
        if let Some(value) = self.message_step_y {
            target.message_step_y = value;
        }
        if let Some(value) = self.remote_session {
            target.remote_session = value;
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct VolumeProfileOverrides {
    pub root_path: Option<String>,
    pub volume_name: Option<String>,
    pub serial: Option<u32>,
    pub max_component_length: Option<u32>,
    pub flags: Option<u32>,
    pub fs_name: Option<String>,
    pub drive_type: Option<u32>,
    pub physical_drive_count: Option<u32>,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub volume_guid: Option<String>,
}

impl VolumeProfileOverrides {
    fn apply_to(&self, target: &mut VolumeProfile) {
        if let Some(value) = &self.root_path {
            target.root_path = value.clone();
        }
        if let Some(value) = &self.volume_name {
            target.volume_name = value.clone();
        }
        if let Some(value) = self.serial {
            target.serial = value;
        }
        if let Some(value) = self.max_component_length {
            target.max_component_length = value;
        }
        if let Some(value) = self.flags {
            target.flags = value;
        }
        if let Some(value) = &self.fs_name {
            target.fs_name = value.clone();
        }
        if let Some(value) = self.drive_type {
            target.drive_type = value;
        }
        if let Some(value) = self.physical_drive_count {
            target.physical_drive_count = value.max(1);
        }
        if let Some(value) = self.total_bytes {
            target.total_bytes = value;
        }
        if let Some(value) = self.free_bytes {
            target.free_bytes = value;
        }
        if let Some(value) = self.available_bytes {
            target.available_bytes = value;
        }
        if let Some(value) = &self.volume_guid {
            target.volume_guid = value.clone();
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ShellFolderOverrides {
    pub profile: Option<String>,
    pub desktop: Option<String>,
    pub app_data: Option<String>,
    pub local_app_data: Option<String>,
    pub program_data: Option<String>,
    pub startup: Option<String>,
    pub personal: Option<String>,
    pub public: Option<String>,
    pub program_files: Option<String>,
    pub program_files_x86: Option<String>,
    pub common_files: Option<String>,
    pub common_files_x86: Option<String>,
    pub common_startup: Option<String>,
    pub common_desktop: Option<String>,
}

impl ShellFolderOverrides {
    fn apply_to(&self, target: &mut ShellFolderProfile) {
        if let Some(value) = &self.profile {
            target.profile = value.clone();
        }
        if let Some(value) = &self.desktop {
            target.desktop = value.clone();
        }
        if let Some(value) = &self.app_data {
            target.app_data = value.clone();
        }
        if let Some(value) = &self.local_app_data {
            target.local_app_data = value.clone();
        }
        if let Some(value) = &self.program_data {
            target.program_data = value.clone();
        }
        if let Some(value) = &self.startup {
            target.startup = value.clone();
        }
        if let Some(value) = &self.personal {
            target.personal = value.clone();
        }
        if let Some(value) = &self.public {
            target.public = value.clone();
        }
        if let Some(value) = &self.program_files {
            target.program_files = value.clone();
        }
        if let Some(value) = &self.program_files_x86 {
            target.program_files_x86 = value.clone();
        }
        if let Some(value) = &self.common_files {
            target.common_files = value.clone();
        }
        if let Some(value) = &self.common_files_x86 {
            target.common_files_x86 = value.clone();
        }
        if let Some(value) = &self.common_startup {
            target.common_startup = value.clone();
        }
        if let Some(value) = &self.common_desktop {
            target.common_desktop = value.clone();
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct NetworkProfileOverrides {
    pub host_name: Option<String>,
    pub domain_name: Option<String>,
    pub dns_suffix: Option<String>,
    pub dns_servers: Option<Vec<String>>,
    pub node_type: Option<u32>,
    pub scope_id: Option<String>,
    pub enable_routing: Option<bool>,
    pub enable_proxy: Option<bool>,
    pub enable_dns: Option<bool>,
    pub adapters: Option<Vec<NetworkAdapterProfile>>,
}

impl NetworkProfileOverrides {
    fn apply_to(&self, target: &mut NetworkProfile) {
        if let Some(value) = &self.host_name {
            target.host_name = value.clone();
        }
        if let Some(value) = &self.domain_name {
            target.domain_name = value.clone();
        }
        if let Some(value) = &self.dns_suffix {
            target.dns_suffix = value.clone();
        }
        if let Some(value) = &self.dns_servers {
            target.dns_servers = value.clone();
        }
        if let Some(value) = self.node_type {
            target.node_type = value;
        }
        if let Some(value) = &self.scope_id {
            target.scope_id = value.clone();
        }
        if let Some(value) = self.enable_routing {
            target.enable_routing = value;
        }
        if let Some(value) = self.enable_proxy {
            target.enable_proxy = value;
        }
        if let Some(value) = self.enable_dns {
            target.enable_dns = value;
        }
        if let Some(value) = &self.adapters {
            target.adapters = value.clone();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for MachineIdentity {
    fn default() -> Self {
        Self {
            computer_name: "DESKTOP-9F4A8D2".to_string(),
            user_name: "Admin".to_string(),
            user_domain: "WORKGROUP".to_string(),
            dns_domain_name: String::new(),
            forest_name: String::new(),
            domain_controller: String::new(),
            domain_guid: String::new(),
            machine_guid: "8f2c1e53-9d5a-4c16-9a6e-1e4c2a9f7b31".to_string(),
            process_id: DEFAULT_PROCESS_ID,
            image_path: String::new(),
            parent_process_id: DEFAULT_PARENT_PROCESS_ID,
            parent_image_path: String::new(),
            parent_command_line: String::new(),
            system_root: r"C:\Windows".to_string(),
            system32: r"C:\Windows\System32".to_string(),
            temp_dir: r"C:\Users\Admin\AppData\Local\Temp".to_string(),
            current_directory: String::new(),
            command_line: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for OsVersion {
    fn default() -> Self {
        Self {
            major: 10,
            minor: 0,
            build: 19045,
            platform_id: 2,
            suite_mask: 0,
            product_type: 1,
            service_pack_major: 0,
            service_pack_minor: 0,
            csd_version: String::new(),
            product_name: "Windows 10 Pro".to_string(),
            product_id: "00330-80000-00000-AAOEM".to_string(),
            build_lab_ex: "19041.1.amd64fre.vb_release.191206-1406".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for LocaleProfile {
    fn default() -> Self {
        Self {
            acp: 936,
            oemcp: 936,
            console_cp: 936,
            console_output_cp: 936,
            user_default_lcid: 0x0804,
            thread_locale: 0x0804,
            system_default_ui_language: 0x0804,
            user_default_ui_language: 0x0804,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for DisplayProfile {
    fn default() -> Self {
        Self {
            desktop_window_handle: 0x0010_0000,
            active_window_handle: 0x0010_0010,
            shell_window_handle: 0x0010_0020,
            default_dc_handle: 0x0012_0000,
            screen_width: 1920,
            screen_height: 1080,
            cursor_x: 317,
            cursor_y: 31,
            message_x: 317,
            message_y: 31,
            message_step_x: 0,
            message_step_y: 0,
            remote_session: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for VolumeProfile {
    fn default() -> Self {
        Self {
            root_path: r"C:\".to_string(),
            volume_name: "System".to_string(),
            serial: 0x54A1_F3C2,
            max_component_length: 255,
            flags: 0x0007_03FF,
            fs_name: "NTFS".to_string(),
            drive_type: 3,
            physical_drive_count: 1,
            total_bytes: 256 * 1024 * 1024 * 1024,
            free_bytes: 128 * 1024 * 1024 * 1024,
            available_bytes: 96 * 1024 * 1024 * 1024,
            volume_guid: r"\\?\Volume{54a1f3c2-9f4a-48d2-8c71-112233445566}\".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for ShellFolderProfile {
    fn default() -> Self {
        Self {
            profile: r"C:\Users\Admin".to_string(),
            desktop: r"C:\Users\Admin\Desktop".to_string(),
            app_data: r"C:\Users\Admin\AppData\Roaming".to_string(),
            local_app_data: r"C:\Users\Admin\AppData\Local".to_string(),
            program_data: r"C:\ProgramData".to_string(),
            startup:
                r"C:\Users\Admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
                    .to_string(),
            personal: r"C:\Users\Admin\Documents".to_string(),
            public: r"C:\Users\Public".to_string(),
            program_files: r"C:\Program Files".to_string(),
            program_files_x86: r"C:\Program Files (x86)".to_string(),
            common_files: r"C:\Program Files\Common Files".to_string(),
            common_files_x86: r"C:\Program Files (x86)\Common Files".to_string(),
            common_startup: r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
                .to_string(),
            common_desktop: r"C:\Users\Public\Desktop".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub adapters: Vec<NetworkAdapterProfile>,
}

impl Default for NetworkProfile {
    fn default() -> Self {
        Self {
            host_name: "DESKTOP-9F4A8D2".to_string(),
            domain_name: "lan".to_string(),
            dns_suffix: "lan".to_string(),
            dns_servers: vec!["192.168.56.1".to_string(), "8.8.8.8".to_string()],
            node_type: 1,
            scope_id: String::new(),
            enable_routing: false,
            enable_proxy: false,
            enable_dns: true,
            adapters: default_network_adapters(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkAdapterProfile {
    pub name: String,
    pub description: String,
    pub friendly_name: String,
    pub dns_suffix: String,
    pub if_index: u32,
    pub adapter_type: u32,
    pub mac_address: String,
    pub mtu: u32,
    pub oper_status: u32,
    pub ipv4_addresses: Vec<NetworkAddressProfile>,
    pub gateways: Vec<String>,
    pub dns_servers: Vec<String>,
    pub dhcp_enabled: bool,
    pub dhcp_server: String,
}

impl Default for NetworkAdapterProfile {
    fn default() -> Self {
        Self {
            name: "{D4C9F4A8-8D2A-4A1F-B7C3-00155D010203}".to_string(),
            description: "Intel(R) Ethernet Connection (7) I219-V".to_string(),
            friendly_name: "Ethernet".to_string(),
            dns_suffix: "lan".to_string(),
            if_index: 7,
            adapter_type: 6,
            mac_address: "00:0C:29:5B:7A:31".to_string(),
            mtu: 1500,
            oper_status: 1,
            ipv4_addresses: vec![NetworkAddressProfile::default()],
            gateways: vec!["192.168.56.1".to_string()],
            dns_servers: vec!["192.168.56.1".to_string(), "8.8.8.8".to_string()],
            dhcp_enabled: true,
            dhcp_server: "192.168.56.1".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkAddressProfile {
    pub address: String,
    pub netmask: String,
}

impl Default for NetworkAddressProfile {
    fn default() -> Self {
        Self {
            address: "192.168.56.101".to_string(),
            netmask: "255.255.255.0".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentVariableProfile {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessProfile {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_path: String,
    pub command_line: String,
    pub current_directory: String,
}

impl Default for ProcessProfile {
    fn default() -> Self {
        Self {
            pid: 0,
            parent_pid: 0,
            image_path: String::new(),
            command_line: String::new(),
            current_directory: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserAccountProfile {
    pub name: String,
    pub full_name: String,
    pub comment: String,
    pub flags: u32,
    pub privilege_level: u32,
    pub home_dir: String,
    pub script_path: String,
    pub rid: u32,
}

impl Default for UserAccountProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            full_name: String::new(),
            comment: String::new(),
            flags: 0x0001 | 0x0200 | 0x10000,
            privilege_level: 1,
            home_dir: String::new(),
            script_path: String::new(),
            rid: 1001,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalGroupProfile {
    pub name: String,
    pub comment: String,
    pub domain: String,
    pub rid: u32,
    pub members: Vec<String>,
}

impl Default for LocalGroupProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            comment: String::new(),
            domain: "BUILTIN".to_string(),
            rid: 544,
            members: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShareProfile {
    pub name: String,
    pub share_type: u32,
    pub remark: String,
    pub path: String,
    pub permissions: u32,
    pub max_uses: u32,
    pub current_uses: u32,
    pub password: String,
}

impl Default for ShareProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            share_type: 0,
            remark: String::new(),
            path: String::new(),
            permissions: 0,
            max_uses: u32::MAX,
            current_uses: 0,
            password: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkUseProfile {
    pub local_name: String,
    pub remote_name: String,
    pub password: String,
    pub status: u32,
    pub assignment_type: u32,
    pub ref_count: u32,
    pub use_count: u32,
    pub user_name: String,
    pub domain_name: String,
    pub provider: String,
    pub comment: String,
}

impl Default for NetworkUseProfile {
    fn default() -> Self {
        Self {
            local_name: String::new(),
            remote_name: String::new(),
            password: String::new(),
            status: 0,
            assignment_type: 0,
            ref_count: 1,
            use_count: 1,
            user_name: String::new(),
            domain_name: String::new(),
            provider: "Microsoft Windows Network".to_string(),
            comment: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkstationUserProfile {
    pub user_name: String,
    pub logon_domain: String,
    pub other_domains: String,
    pub logon_server: String,
}

impl Default for WorkstationUserProfile {
    fn default() -> Self {
        Self {
            user_name: String::new(),
            logon_domain: String::new(),
            other_domains: String::new(),
            logon_server: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkSessionProfile {
    pub client_name: String,
    pub user_name: String,
    pub active_time_secs: u32,
    pub idle_time_secs: u32,
}

impl Default for NetworkSessionProfile {
    fn default() -> Self {
        Self {
            client_name: String::new(),
            user_name: String::new(),
            active_time_secs: 0,
            idle_time_secs: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenFileProfile {
    pub id: u32,
    pub permissions: u32,
    pub num_locks: u32,
    pub path_name: String,
    pub user_name: String,
    pub client_name: String,
}

impl Default for OpenFileProfile {
    fn default() -> Self {
        Self {
            id: 0,
            permissions: 0,
            num_locks: 0,
            path_name: String::new(),
            user_name: String::new(),
            client_name: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceProfile {
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
    pub failure_actions_on_non_crash_failures: bool,
    pub service_sid_type: u32,
    pub required_privileges: Vec<String>,
    pub pre_shutdown_timeout_ms: u32,
    pub failure_reset_period_secs: u32,
    pub failure_reboot_message: String,
    pub failure_command: String,
}

impl Default for ServiceProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            display_name: String::new(),
            service_type: 0x20,
            start_type: 2,
            error_control: 1,
            current_state: 4,
            controls_accepted: 0x0000_0001,
            win32_exit_code: 0,
            service_specific_exit_code: 0,
            check_point: 0,
            wait_hint: 0,
            process_id: 0,
            binary_path: "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p".to_string(),
            load_order_group: String::new(),
            tag_id: 0,
            dependencies: Vec::new(),
            start_name: "LocalSystem".to_string(),
            description: String::new(),
            delayed_auto_start: false,
            failure_actions_on_non_crash_failures: true,
            service_sid_type: 1,
            required_privileges: vec!["SeChangeNotifyPrivilege".to_string()],
            pre_shutdown_timeout_ms: 180_000,
            failure_reset_period_secs: 86_400,
            failure_reboot_message: String::new(),
            failure_command: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistrySnapshot {
    pub keys: Vec<RegistryKeyProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryKeyProfile {
    pub path: String,
    #[serde(default)]
    pub values: Vec<RegistryValueProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValueProfile {
    pub name: String,
    pub value_type: u32,
    #[serde(default)]
    pub string: Option<String>,
    #[serde(default)]
    pub dword: Option<u32>,
    #[serde(default)]
    pub qword: Option<u64>,
    #[serde(default)]
    pub multi_string: Vec<String>,
    #[serde(default)]
    pub binary_hex: Option<String>,
}

impl RegistryValueProfile {
    fn encoded_data(&self) -> Result<Vec<u8>, String> {
        if let Some(value) = &self.string {
            return Ok(encode_utf16_string(value));
        }
        if let Some(value) = self.dword {
            return Ok(value.to_le_bytes().to_vec());
        }
        if let Some(value) = self.qword {
            return Ok(value.to_le_bytes().to_vec());
        }
        if !self.multi_string.is_empty() {
            return Ok(encode_utf16_multi_string(&self.multi_string));
        }
        if let Some(value) = &self.binary_hex {
            return parse_hex_bytes(value);
        }
        Ok(Vec::new())
    }
}

fn encode_utf16_string(value: &str) -> Vec<u8> {
    let mut bytes = value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

fn encode_utf16_multi_string(values: &[String]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend(value.encode_utf16().flat_map(u16::to_le_bytes));
        bytes.extend_from_slice(&[0, 0]);
    }
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

fn default_network_adapters() -> Vec<NetworkAdapterProfile> {
    vec![NetworkAdapterProfile::default()]
}

fn default_users() -> Vec<UserAccountProfile> {
    vec![
        UserAccountProfile {
            name: "Admin".to_string(),
            full_name: "Local Administrator".to_string(),
            comment: "Primary local analyst account".to_string(),
            privilege_level: 2,
            home_dir: r"C:\Users\Admin".to_string(),
            rid: 1001,
            ..UserAccountProfile::default()
        },
        UserAccountProfile {
            name: "Administrator".to_string(),
            comment: "Built-in account for administering the computer/domain".to_string(),
            privilege_level: 2,
            rid: 500,
            ..UserAccountProfile::default()
        },
        UserAccountProfile {
            name: "Guest".to_string(),
            comment: "Built-in account for guest access to the computer/domain".to_string(),
            flags: 0x0001 | 0x0002 | 0x0080,
            privilege_level: 0,
            rid: 501,
            ..UserAccountProfile::default()
        },
        UserAccountProfile {
            name: "WDAGUtilityAccount".to_string(),
            comment: "A user account managed and used by the system for Windows Defender Application Guard scenarios.".to_string(),
            flags: 0x0001 | 0x0002 | 0x0200,
            privilege_level: 1,
            rid: 504,
            ..UserAccountProfile::default()
        },
    ]
}

fn default_local_groups() -> Vec<LocalGroupProfile> {
    vec![
        LocalGroupProfile {
            name: "Administrators".to_string(),
            comment: "Administrators have complete and unrestricted access to the computer/domain"
                .to_string(),
            domain: "BUILTIN".to_string(),
            rid: 544,
            members: vec!["Admin".to_string(), "Administrator".to_string()],
        },
        LocalGroupProfile {
            name: "Users".to_string(),
            comment:
                "Users are prevented from making accidental or intentional system-wide changes"
                    .to_string(),
            domain: "BUILTIN".to_string(),
            rid: 545,
            members: vec!["Admin".to_string()],
        },
        LocalGroupProfile {
            name: "Guests".to_string(),
            comment: "Guests have the same access as members of the Users group by default"
                .to_string(),
            domain: "BUILTIN".to_string(),
            rid: 546,
            members: vec!["Guest".to_string()],
        },
        LocalGroupProfile {
            name: "Remote Desktop Users".to_string(),
            comment: "Members in this group are granted the right to log on remotely".to_string(),
            domain: "BUILTIN".to_string(),
            rid: 555,
            members: vec!["Admin".to_string()],
        },
    ]
}

fn default_services() -> Vec<ServiceProfile> {
    vec![
        ServiceProfile {
            name: "Dnscache".to_string(),
            display_name: "DNS Client".to_string(),
            process_id: 2800,
            binary_path: "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p".to_string(),
            start_name: "NT AUTHORITY\\NetworkService".to_string(),
            description: "Caches Domain Name System (DNS) names and registers the full computer name for this computer.".to_string(),
            ..ServiceProfile::default()
        },
        ServiceProfile {
            name: "EventLog".to_string(),
            display_name: "Windows Event Log".to_string(),
            process_id: 2800,
            binary_path:
                "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p"
                    .to_string(),
            start_name: "NT AUTHORITY\\LocalService".to_string(),
            description: "This service manages events and event logs.".to_string(),
            ..ServiceProfile::default()
        },
        ServiceProfile {
            name: "wuauserv".to_string(),
            display_name: "Windows Update".to_string(),
            process_id: 2800,
            description: "Enables the detection, download, and installation of updates for Windows and other programs.".to_string(),
            delayed_auto_start: true,
            ..ServiceProfile::default()
        },
        ServiceProfile {
            name: "WinDefend".to_string(),
            display_name: "Microsoft Defender Antivirus Service".to_string(),
            process_id: 3540,
            binary_path: "%ProgramFiles%\\Windows Defender\\MsMpEng.exe".to_string(),
            description: "Helps protect users from malware and other potentially unwanted software.".to_string(),
            required_privileges: vec![
                "SeChangeNotifyPrivilege".to_string(),
                "SeImpersonatePrivilege".to_string(),
            ],
            ..ServiceProfile::default()
        },
    ]
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let compact = raw
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != ',' && *ch != ';')
        .collect::<String>();
    if compact.is_empty() {
        return Ok(Vec::new());
    }
    if compact.len() % 2 != 0 {
        return Err(format!("registry binary hex length must be even: {raw}"));
    }
    let mut bytes = Vec::with_capacity(compact.len() / 2);
    let chars = compact.as_bytes();
    let mut index = 0usize;
    while index < chars.len() {
        let slice = std::str::from_utf8(&chars[index..index + 2])
            .map_err(|_| format!("invalid registry binary hex: {raw}"))?;
        let byte = u8::from_str_radix(slice, 16)
            .map_err(|_| format!("invalid registry binary hex byte `{slice}`"))?;
        bytes.push(byte);
        index += 2;
    }
    Ok(bytes)
}
