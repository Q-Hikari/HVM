use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn current_directory_display_text(&self) -> String {
        self.current_directory.to_string_lossy().to_string()
    }

    pub(in crate::runtime::engine) fn current_process_id(&self) -> u32 {
        self.environment_profile.machine.process_id.max(1)
    }

    pub(in crate::runtime::engine) fn active_computer_name(&self) -> &str {
        self.environment_profile.machine.computer_name.as_str()
    }

    pub(in crate::runtime::engine) fn active_user_name(&self) -> &str {
        self.environment_profile.machine.user_name.as_str()
    }

    pub(in crate::runtime::engine) fn ansi_code_page(&self) -> u64 {
        u64::from(self.environment_profile.locale.acp.max(1))
    }

    pub(in crate::runtime::engine) fn oem_code_page(&self) -> u64 {
        u64::from(self.environment_profile.locale.oemcp.max(1))
    }

    pub(in crate::runtime::engine) fn console_code_page(&self) -> u64 {
        u64::from(self.environment_profile.locale.console_cp.max(1))
    }

    pub(in crate::runtime::engine) fn console_output_code_page(&self) -> u64 {
        u64::from(self.environment_profile.locale.console_output_cp.max(1))
    }

    pub(in crate::runtime::engine) fn user_default_lcid(&self) -> u64 {
        u64::from(self.environment_profile.locale.user_default_lcid.max(1))
    }

    pub(in crate::runtime::engine) fn thread_locale(&self) -> u64 {
        u64::from(self.environment_profile.locale.thread_locale.max(1))
    }

    pub(in crate::runtime::engine) fn system_default_ui_language(&self) -> u64 {
        u64::from(
            self.environment_profile
                .locale
                .system_default_ui_language
                .max(1),
        )
    }

    pub(in crate::runtime::engine) fn user_default_ui_language(&self) -> u64 {
        u64::from(
            self.environment_profile
                .locale
                .user_default_ui_language
                .max(1),
        )
    }

    pub(in crate::runtime::engine) fn version_return_value(&self) -> u64 {
        let version = &self.environment_profile.os_version;
        ((u64::from(version.build.min(0x7FFF))) << 16)
            | ((u64::from(version.minor & 0xFF)) << 8)
            | u64::from(version.major & 0xFF)
    }

    pub(in crate::runtime::engine) fn volume_profile(
        &self,
    ) -> &crate::environment_profile::VolumeProfile {
        &self.environment_profile.volume
    }

    pub(in crate::runtime::engine) fn shell_folder_profile(
        &self,
    ) -> &crate::environment_profile::ShellFolderProfile {
        &self.environment_profile.shell_folders
    }

    pub(in crate::runtime::engine) fn initialize_runtime_environment_variables(
        &mut self,
        dll_path: &str,
        tmp_directory: &str,
    ) -> Result<(), VmError> {
        self.environment_variables.clear();

        for (name, value) in self.derived_runtime_environment_entries(dll_path, tmp_directory) {
            self.set_runtime_environment_variable_internal(&name, Some(value));
        }

        let profile_variables = self.environment_profile.environment_variables.clone();
        for variable in &profile_variables {
            self.set_runtime_environment_variable_internal(
                &variable.name,
                Some(variable.value.clone()),
            );
        }

        self.sync_runtime_environment_blocks()
    }

    pub(in crate::runtime::engine) fn runtime_environment_entries(&self) -> Vec<(String, String)> {
        const RESERVED_ORDER: &[&str] = &["path", "tmp", "temp", "systemroot", "windir"];

        let mut entries = Vec::new();
        for key in RESERVED_ORDER {
            if let Some(variable) = self.environment_variables.get(*key) {
                entries.push((variable.name.clone(), variable.value.clone()));
            }
        }

        let mut remaining = self
            .environment_variables
            .iter()
            .filter(|(key, _)| {
                !RESERVED_ORDER
                    .iter()
                    .any(|reserved| key.as_str() == *reserved)
            })
            .map(|(_, variable)| (variable.name.clone(), variable.value.clone()))
            .collect::<Vec<_>>();
        remaining.sort_by_key(|entry| entry.0.to_ascii_lowercase());
        entries.extend(remaining);
        entries
    }

    pub(in crate::runtime::engine) fn runtime_environment_value(
        &self,
        name: &str,
    ) -> Option<String> {
        if compare_ci(name, "cd") == 0 {
            return Some(self.current_directory_display_text());
        }
        let normalized = name.to_ascii_lowercase();
        if let Some(variable) = self.environment_variables.get(&normalized) {
            return Some(variable.value.clone());
        }
        match normalized.as_str() {
            "systemroot" | "windir" => Some(self.windows_directory_path()),
            "temp" | "tmp" => Some(self.temporary_directory_path()),
            "path" => Some(self.build_process_dll_path()),
            _ => None,
        }
    }

    pub(in crate::runtime::engine) fn expand_environment_strings(&self, input: &str) -> String {
        let chars = input.chars().collect::<Vec<_>>();
        let mut output = String::new();
        let mut index = 0usize;
        while index < chars.len() {
            if chars[index] == '%' {
                let mut end = index + 1;
                while end < chars.len() && chars[end] != '%' {
                    end += 1;
                }
                if end < chars.len() {
                    let key = chars[index + 1..end]
                        .iter()
                        .collect::<String>()
                        .to_ascii_lowercase();
                    if let Some(value) = self.runtime_environment_value(&key) {
                        output.push_str(&value);
                        index = end + 1;
                        continue;
                    }
                }
            }
            output.push(chars[index]);
            index += 1;
        }
        output
    }

    fn derived_runtime_environment_entries(
        &self,
        dll_path: &str,
        tmp_directory: &str,
    ) -> Vec<(String, String)> {
        let windows_root = self.windows_directory_path();
        let system_directory = self.system_directory_path();
        let temp_directory = if tmp_directory.trim().is_empty() {
            self.temporary_directory_path()
        } else {
            Self::normalize_windows_display_path(tmp_directory)
        };
        let user_profile = self.user_profile_path();
        let app_data = self.app_data_path();
        let local_app_data = self.local_app_data_path();
        let program_data = self.program_data_path();
        let public = self.public_directory_path();
        let program_files = self.program_files_directory_path();
        let program_files_x86 = self.program_files_x86_directory_path();
        let common_files = self.common_files_directory_path();
        let common_files_x86 = self.common_files_x86_directory_path();
        let dll_path = if dll_path.trim().is_empty() {
            self.build_process_dll_path()
        } else {
            dll_path.replace('/', "\\")
        };
        let (home_drive, home_path) = Self::split_windows_drive_and_tail(&user_profile)
            .unwrap_or_else(|| ("C:".to_string(), r"\Users".to_string()));

        vec![
            ("PATH".to_string(), dll_path),
            ("SystemRoot".to_string(), windows_root.clone()),
            ("windir".to_string(), windows_root),
            ("TMP".to_string(), temp_directory.clone()),
            ("TEMP".to_string(), temp_directory),
            (
                "COMSPEC".to_string(),
                Self::join_windows_display_path(&system_directory, "cmd.exe"),
            ),
            ("USERPROFILE".to_string(), user_profile),
            ("HOMEDRIVE".to_string(), home_drive),
            ("HOMEPATH".to_string(), home_path),
            ("APPDATA".to_string(), app_data),
            ("LOCALAPPDATA".to_string(), local_app_data),
            ("ProgramData".to_string(), program_data.clone()),
            ("ALLUSERSPROFILE".to_string(), program_data),
            ("PUBLIC".to_string(), public),
            ("USERNAME".to_string(), self.active_user_name().to_string()),
            (
                "USERDOMAIN".to_string(),
                self.environment_profile.machine.user_domain.clone(),
            ),
            (
                "COMPUTERNAME".to_string(),
                self.active_computer_name().to_string(),
            ),
            ("ProgramFiles".to_string(), program_files),
            ("ProgramFiles(x86)".to_string(), program_files_x86),
            ("CommonProgramFiles".to_string(), common_files),
            ("CommonProgramFiles(x86)".to_string(), common_files_x86),
            (
                "PATHEXT".to_string(),
                ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC".to_string(),
            ),
        ]
    }

    pub(in crate::runtime::engine) fn set_runtime_environment_variable(
        &mut self,
        name: &str,
        value: Option<String>,
    ) -> Result<(), VmError> {
        self.set_runtime_environment_variable_internal(name, value);
        self.sync_runtime_environment_blocks()
    }

    pub(in crate::runtime::engine) fn sync_runtime_environment_blocks(
        &mut self,
    ) -> Result<(), VmError> {
        let entries = self.runtime_environment_entries();
        self.process_env
            .write_environment_blocks_from_entries(&entries)
            .map_err(VmError::from)
    }

    fn set_runtime_environment_variable_internal(&mut self, name: &str, value: Option<String>) {
        let normalized = name.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return;
        }

        if let Some(value) = value {
            self.environment_variables.insert(
                normalized,
                RuntimeEnvironmentVariable {
                    name: name.to_string(),
                    value,
                },
            );
        } else {
            self.environment_variables.remove(&normalized);
        }
    }
}
