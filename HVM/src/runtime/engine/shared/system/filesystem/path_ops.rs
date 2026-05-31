use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn ensure_runtime_path_backing(
        &mut self,
        raw: &str,
    ) -> Result<(), VmError> {
        let trimmed = raw.trim();
        let Some(mapped) = self.map_windows_runtime_path(trimmed) else {
            return Ok(());
        };
        let normalized = Self::normalize_windows_path(trimmed);

        if let Some(parent) = mapped.parent() {
            std::fs::create_dir_all(parent).map_err(|source| VmError::OutputIo {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        if self.is_virtual_windows_system_path(trimmed) {
            let is_exact_system_directory = self
                .virtual_windows_system_prefixes()
                .into_iter()
                .any(|prefix| normalized == prefix);
            let seed_dir = if Self::path_contains_wildcards(trimmed) {
                mapped.parent().map(std::path::Path::to_path_buf)
            } else if is_exact_system_directory {
                Some(mapped.clone())
            } else if mapped.extension().is_some() {
                mapped.parent().map(std::path::Path::to_path_buf)
            } else {
                None
            };
            if let Some(directory) = seed_dir {
                self.seed_virtual_windows_system_directory(&directory)?;
            }
        }

        Ok(())
    }

    pub(in crate::runtime::engine) fn wildcard_match(pattern: &str, text: &str) -> bool {
        if pattern.eq_ignore_ascii_case("*.*") {
            return true;
        }
        let pattern = pattern.as_bytes();
        let text = text.as_bytes();
        let mut text_index = 0usize;
        let mut pattern_index = 0usize;
        let mut star_index = None;
        let mut match_index = 0usize;

        while text_index < text.len() {
            let pattern_matches = pattern
                .get(pattern_index)
                .copied()
                .map(|byte| byte == b'?' || byte.eq_ignore_ascii_case(&text[text_index]));
            if pattern_matches == Some(true) {
                pattern_index += 1;
                text_index += 1;
                continue;
            }
            if pattern.get(pattern_index) == Some(&b'*') {
                star_index = Some(pattern_index);
                pattern_index += 1;
                match_index = text_index;
                continue;
            }
            if let Some(star_index) = star_index {
                pattern_index = star_index + 1;
                match_index += 1;
                text_index = match_index;
                continue;
            }
            return false;
        }

        while pattern.get(pattern_index) == Some(&b'*') {
            pattern_index += 1;
        }
        pattern_index == pattern.len()
    }

    pub(in crate::runtime::engine) fn find_file_entry_from_path(
        path: &std::path::Path,
    ) -> Option<FindFileEntry> {
        let metadata = std::fs::metadata(path).ok()?;
        let file_name = path.file_name()?.to_string_lossy().to_string();
        let attributes = if metadata.is_dir() {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        Some(FindFileEntry {
            file_name,
            attributes,
            size: metadata.len(),
        })
    }

    pub(in crate::runtime::engine) fn enumerate_find_file_entries(
        &mut self,
        raw_path: &str,
    ) -> Result<Vec<FindFileEntry>, VmError> {
        self.ensure_runtime_path_backing(raw_path)?;
        let resolved = self.resolve_runtime_path(raw_path);
        let mut entries = if Self::path_contains_wildcards(raw_path) {
            let pattern = resolved
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| "*".to_string());
            let Some(directory) = resolved.parent() else {
                return Ok(Vec::new());
            };
            let mut entries = std::fs::read_dir(directory)
                .map_err(|source| VmError::OutputIo {
                    path: directory.to_path_buf(),
                    source,
                })?
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    Self::wildcard_match(&pattern, &file_name)
                        .then(|| Self::find_file_entry_from_path(&entry.path()))
                        .flatten()
                })
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| {
                left.file_name
                    .to_ascii_lowercase()
                    .cmp(&right.file_name.to_ascii_lowercase())
            });
            entries
        } else {
            Self::find_file_entry_from_path(&resolved)
                .into_iter()
                .collect::<Vec<_>>()
        };
        entries.retain(|entry| !entry.file_name.is_empty());
        Ok(entries)
    }

    pub(in crate::runtime::engine) fn write_find_file_data(
        &mut self,
        entry: &FindFileEntry,
        buffer: u64,
        wide: bool,
    ) -> Result<(), VmError> {
        const FIND_DATA_A_SIZE: usize = 0x140;
        const FIND_DATA_W_SIZE: usize = 0x250;
        const FIND_DATA_NAME_OFFSET: usize = 0x2C;

        let mut payload = vec![
            0u8;
            if wide {
                FIND_DATA_W_SIZE
            } else {
                FIND_DATA_A_SIZE
            }
        ];
        payload[0..4].copy_from_slice(&entry.attributes.to_le_bytes());
        payload[28..32].copy_from_slice(&((entry.size >> 32) as u32).to_le_bytes());
        payload[32..36].copy_from_slice(&(entry.size as u32).to_le_bytes());
        if wide {
            let encoded = entry
                .file_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            let length = encoded
                .len()
                .min(payload.len().saturating_sub(FIND_DATA_NAME_OFFSET));
            payload[FIND_DATA_NAME_OFFSET..FIND_DATA_NAME_OFFSET + length]
                .copy_from_slice(&encoded[..length]);
        } else {
            let mut encoded = entry.file_name.as_bytes().to_vec();
            encoded.push(0);
            let length = encoded
                .len()
                .min(payload.len().saturating_sub(FIND_DATA_NAME_OFFSET));
            payload[FIND_DATA_NAME_OFFSET..FIND_DATA_NAME_OFFSET + length]
                .copy_from_slice(&encoded[..length]);
        }
        self.core.modules.memory_mut().write(buffer, &payload)?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn find_first_file(
        &mut self,
        path: &str,
        buffer: u64,
        wide: bool,
    ) -> Result<u64, VmError> {
        if path.trim().is_empty() || buffer == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(self.invalid_handle_value_for_arch());
        }
        if !self.ensure_runtime_read_allowed(path, "FindFirstFile")? {
            return Ok(self.invalid_handle_value_for_arch());
        }

        let entries = self.enumerate_find_file_entries(path)?;
        let Some(first) = entries.first().cloned() else {
            self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
            return Ok(self.invalid_handle_value_for_arch());
        };

        let handle = self.allocate_object_handle();
        self.handles
            .find_handles
            .insert(handle, FindHandleState { entries, cursor: 1 });
        self.write_find_file_data(&first, buffer, wide)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(handle as u64)
    }

    pub(in crate::runtime::engine) fn find_next_file(
        &mut self,
        handle: u32,
        buffer: u64,
        wide: bool,
    ) -> Result<u64, VmError> {
        if buffer == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let Some(state) = self.handles.find_handles.get_mut(&handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let Some(entry) = state.entries.get(state.cursor).cloned() else {
            self.set_last_error(ERROR_NO_MORE_FILES as u32);
            return Ok(0);
        };
        state.cursor += 1;
        self.write_find_file_data(&entry, buffer, wide)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn close_find_handle(&mut self, handle: u32) -> u64 {
        if self.handles.find_handles.remove(&handle).is_some() {
            self.set_last_error(ERROR_SUCCESS as u32);
            1
        } else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            0
        }
    }

    pub(in crate::runtime::engine) fn resolve_runtime_path(&self, raw: &str) -> std::path::PathBuf {
        if let Some(mapped) = self.resolve_absolute_runtime_path(raw) {
            return mapped;
        }
        let candidate = std::path::PathBuf::from(raw);
        if candidate.is_absolute() {
            candidate
        } else {
            self.core.current_directory_host.join(candidate)
        }
    }

    fn guest_system_subdirectory_for_current_arch(&self) -> &'static str {
        if let Some(module_directory) = self
            .core
            .config
            .module_directory_for_arch(self.core.arch.name)
        {
            if let Some(name) = module_directory.file_name() {
                let name = name.to_string_lossy();
                if name.eq_ignore_ascii_case("syswow64") {
                    return "SysWOW64";
                }
                if name.eq_ignore_ascii_case("system32") {
                    return "System32";
                }
            }
        }
        for search_path in &self.core.config.module_search_paths {
            if let Some(name) = search_path.file_name() {
                let name = name.to_string_lossy();
                if name.eq_ignore_ascii_case("syswow64") {
                    return "SysWOW64";
                }
                if name.eq_ignore_ascii_case("system32") {
                    return "System32";
                }
            }
        }
        let configured = self.core.environment_profile.machine.system32.trim();
        if !configured.is_empty() {
            let configured_path = std::path::PathBuf::from(configured);
            if let Some(name) = configured_path.file_name() {
                let name = name.to_string_lossy();
                if name.eq_ignore_ascii_case("syswow64") {
                    return "SysWOW64";
                }
            }
        }
        "System32"
    }

    pub(in crate::runtime::engine) fn system_directory_path(&self) -> String {
        let subdirectory = self.guest_system_subdirectory_for_current_arch();
        if !self.core.environment_profile.machine.system_root.is_empty() {
            return Self::join_windows_display_path(
                &self.core.environment_profile.machine.system_root,
                subdirectory,
            );
        }
        if !self.core.environment_profile.machine.system32.is_empty() {
            let configured = Self::normalize_windows_display_path(
                &self.core.environment_profile.machine.system32,
            );
            let configured_path = std::path::PathBuf::from(&configured);
            let configured_leaf = configured_path
                .file_name()
                .map(|name| name.to_string_lossy().to_ascii_lowercase());
            if matches!(configured_leaf.as_deref(), Some("system32" | "syswow64")) {
                let windows_root = configured_path
                    .parent()
                    .map(|path| path.to_string_lossy().to_string())
                    .unwrap_or_else(|| r"C:\Windows".to_string());
                return Self::join_windows_display_path(&windows_root, subdirectory);
            }
            return configured;
        }
        Self::join_windows_display_path(r"C:\Windows", subdirectory)
    }

    pub(in crate::runtime::engine) fn build_process_dll_path(&self) -> String {
        let mut paths = Vec::new();
        let system_directory = self.system_directory_path();
        if !system_directory.is_empty() {
            paths.push(system_directory);
        }
        for path in &self.core.config.module_search_paths {
            let path_text = path.to_string_lossy().to_string();
            if !path_text.is_empty() && !paths.iter().any(|existing| existing == &path_text) {
                paths.push(path_text);
            }
        }
        if paths.is_empty() {
            r"C:\Windows\System32".to_string()
        } else {
            paths.join(";")
        }
    }

    pub(in crate::runtime::engine) fn windows_directory_path(&self) -> String {
        if !self.core.environment_profile.machine.system_root.is_empty() {
            return self.core.environment_profile.machine.system_root.clone();
        }
        let system_dir = std::path::PathBuf::from(self.system_directory_path());
        match system_dir
            .file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase())
        {
            Some(name) if matches!(name.as_str(), "system32" | "syswow64") => system_dir
                .parent()
                .unwrap_or(system_dir.as_path())
                .to_string_lossy()
                .to_string(),
            _ => system_dir.to_string_lossy().to_string(),
        }
    }

    pub(in crate::runtime::engine) fn temporary_directory_path(&self) -> String {
        if !self.core.environment_profile.machine.temp_dir.is_empty() {
            self.core.environment_profile.machine.temp_dir.clone()
        } else {
            format!(
                "{}\\Temp",
                self.windows_directory_path().trim_end_matches(['\\', '/'])
            )
        }
    }

    pub(in crate::runtime::engine) fn configured_shell_folder_path(
        &self,
        configured: &str,
        fallback: String,
    ) -> String {
        if configured.trim().is_empty() {
            Self::normalize_windows_display_path(&fallback)
        } else {
            Self::normalize_windows_display_path(configured)
        }
    }

    pub(in crate::runtime::engine) fn user_profile_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().profile,
            format!(r"C:\Users\{}", self.active_user_name()),
        )
    }

    pub(in crate::runtime::engine) fn desktop_directory_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().desktop,
            Self::join_windows_display_path(&self.user_profile_path(), "Desktop"),
        )
    }

    pub(in crate::runtime::engine) fn app_data_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().app_data,
            Self::join_windows_display_path(&self.user_profile_path(), r"AppData\Roaming"),
        )
    }

    pub(in crate::runtime::engine) fn local_app_data_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().local_app_data,
            Self::join_windows_display_path(&self.user_profile_path(), r"AppData\Local"),
        )
    }

    pub(in crate::runtime::engine) fn program_data_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().program_data,
            r"C:\ProgramData".to_string(),
        )
    }

    pub(in crate::runtime::engine) fn startup_directory_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().startup,
            Self::join_windows_display_path(
                &self.app_data_path(),
                r"Microsoft\Windows\Start Menu\Programs\Startup",
            ),
        )
    }

    pub(in crate::runtime::engine) fn personal_directory_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().personal,
            Self::join_windows_display_path(&self.user_profile_path(), "Documents"),
        )
    }

    pub(in crate::runtime::engine) fn public_directory_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().public,
            r"C:\Users\Public".to_string(),
        )
    }

    pub(in crate::runtime::engine) fn program_files_directory_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().program_files,
            r"C:\Program Files".to_string(),
        )
    }

    pub(in crate::runtime::engine) fn program_files_x86_directory_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().program_files_x86,
            r"C:\Program Files (x86)".to_string(),
        )
    }

    pub(in crate::runtime::engine) fn common_files_directory_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().common_files,
            Self::join_windows_display_path(&self.program_files_directory_path(), "Common Files"),
        )
    }

    pub(in crate::runtime::engine) fn common_files_x86_directory_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().common_files_x86,
            Self::join_windows_display_path(
                &self.program_files_x86_directory_path(),
                "Common Files",
            ),
        )
    }

    pub(in crate::runtime::engine) fn common_desktop_directory_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().common_desktop,
            Self::join_windows_display_path(&self.public_directory_path(), "Desktop"),
        )
    }

    pub(in crate::runtime::engine) fn common_startup_directory_path(&self) -> String {
        self.configured_shell_folder_path(
            &self.shell_folder_profile().common_startup,
            Self::join_windows_display_path(
                &self.program_data_path(),
                r"Microsoft\Windows\Start Menu\Programs\Startup",
            ),
        )
    }

    pub(in crate::runtime::engine) fn shell_folder_path_from_csidl(
        &self,
        raw_csidl: u32,
    ) -> String {
        let csidl = raw_csidl & CSIDL_VALUE_MASK;
        match csidl {
            CSIDL_DESKTOP | CSIDL_DESKTOPDIRECTORY => self.desktop_directory_path(),
            CSIDL_PROGRAMS => Self::join_windows_display_path(
                &self.app_data_path(),
                r"Microsoft\Windows\Start Menu\Programs",
            ),
            CSIDL_PERSONAL => self.personal_directory_path(),
            CSIDL_STARTUP => self.startup_directory_path(),
            CSIDL_STARTMENU => Self::join_windows_display_path(
                &self.app_data_path(),
                r"Microsoft\Windows\Start Menu",
            ),
            CSIDL_FONTS => Self::join_windows_display_path(&self.windows_directory_path(), "Fonts"),
            CSIDL_COMMON_STARTMENU => Self::join_windows_display_path(
                &self.program_data_path(),
                r"Microsoft\Windows\Start Menu",
            ),
            CSIDL_COMMON_PROGRAMS => Self::join_windows_display_path(
                &self.program_data_path(),
                r"Microsoft\Windows\Start Menu\Programs",
            ),
            CSIDL_COMMON_STARTUP => self.common_startup_directory_path(),
            CSIDL_COMMON_DESKTOPDIRECTORY => self.common_desktop_directory_path(),
            CSIDL_APPDATA => self.app_data_path(),
            CSIDL_LOCAL_APPDATA => self.local_app_data_path(),
            CSIDL_COMMON_APPDATA => self.program_data_path(),
            CSIDL_WINDOWS => self.windows_directory_path(),
            CSIDL_SYSTEM => self.system_directory_path(),
            CSIDL_PROGRAM_FILES => self.program_files_directory_path(),
            CSIDL_MYPICTURES => {
                Self::join_windows_display_path(&self.personal_directory_path(), "Pictures")
            }
            CSIDL_PROFILE => self.user_profile_path(),
            CSIDL_SYSTEMX86 => self.system_directory_path(),
            CSIDL_PROGRAM_FILESX86 => self.program_files_x86_directory_path(),
            CSIDL_PROGRAM_FILES_COMMON => self.common_files_directory_path(),
            CSIDL_PROGRAM_FILES_COMMONX86 => self.common_files_x86_directory_path(),
            _ => self.windows_directory_path(),
        }
    }

    /// Maps a KNOWNFOLDERID GUID (16 bytes, standard GUID layout) to a folder path.
    /// Falls back to the Windows directory for unrecognized GUIDs.
    pub(in crate::runtime::engine) fn path_from_known_folder_guid(&self, guid: &[u8]) -> String {
        if guid.len() != 16 {
            return self.windows_directory_path();
        }
        let b = guid;
        // Standard GUID layout: Data1(u32LE) Data2(u16LE) Data3(u16LE) Data4(8 bytes BE)
        let key = format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            b[3], b[2], b[1], b[0],
            b[5], b[4],
            b[7], b[6],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
        );
        match key.as_str() {
            // FOLDERID_Desktop {B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
            "B4BFCC3A-DB2C-424C-B029-7FE99A87C641" => self.desktop_directory_path(),
            // FOLDERID_Documents {FDD39AD0-238F-46AF-ADB4-6C85480369C7}
            "FDD39AD0-238F-46AF-ADB4-6C85480369C7" => self.personal_directory_path(),
            // FOLDERID_Downloads {374DE290-123F-4565-9164-39C4925E467B}
            "374DE290-123F-4565-9164-39C4925E467B" => {
                Self::join_windows_display_path(&self.user_profile_path(), "Downloads")
            }
            // FOLDERID_RoamingAppData {3EB685DB-65F9-4CF6-A03A-E3EF65729F51}
            "3EB685DB-65F9-4CF6-A03A-E3EF65729F51" => self.app_data_path(),
            // FOLDERID_LocalAppData {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
            "F1B32785-6FBA-4FCF-9D55-7B8E7F157091" => self.local_app_data_path(),
            // FOLDERID_ProgramData {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}
            "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97" => self.program_data_path(),
            // FOLDERID_ProgramFiles {905e63b6-c1bf-494e-b29c-65b732d3d21a}
            "905E63B6-C1BF-494E-B29C-65B732D3D21A" => self.program_files_directory_path(),
            // FOLDERID_ProgramFilesX86 {7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}
            "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E" => self.program_files_x86_directory_path(),
            // FOLDERID_Windows {F38BF404-1D43-42F2-9305-67DE0B28FC23}
            "F38BF404-1D43-42F2-9305-67DE0B28FC23" => self.windows_directory_path(),
            // FOLDERID_System {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}
            "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7" => self.system_directory_path(),
            // FOLDERID_Profile {5E6C858F-0E22-4760-9AFE-EA3317B671CC}
            "5E6C858F-0E22-4760-9AFE-EA3317B671CC" => self.user_profile_path(),
            // FOLDERID_Fonts {FD228CB7-AE11-4AE3-864C-16F3910AB8FE}
            "FD228CB7-AE11-4AE3-864C-16F3910AB8FE" => {
                Self::join_windows_display_path(&self.windows_directory_path(), "Fonts")
            }
            // FOLDERID_Startup {82A5EA35-D9CD-47C5-9629-E15D2F714E6E}
            "82A5EA35-D9CD-47C5-9629-E15D2F714E6E" => self.startup_directory_path(),
            // FOLDERID_CommonStartup {82A74BEB-A44E-4ED4-A1C6-00A5B3BBA18B}
            "82A74BEB-A44E-4ED4-A1C6-00A5B3BBA18B" => self.common_startup_directory_path(),
            // FOLDERID_Temp {F5E09FD8-4F50-4F7F-9AE1-D3DED9E430C4}
            "F5E09FD8-4F50-4F7F-9AE1-D3DED9E430C4" => {
                Self::join_windows_display_path(&self.local_app_data_path(), "Temp")
            }
            _ => self.windows_directory_path(),
        }
    }

    pub(in crate::runtime::engine) fn split_windows_drive_and_tail(
        path: &str,
    ) -> Option<(String, String)> {
        let normalized = Self::normalize_windows_display_path(path);
        let bytes = normalized.as_bytes();
        if bytes.len() < 2 || bytes[1] != b':' {
            return None;
        }
        let drive = normalized[..2].to_string();
        let tail = normalized[2..].trim().to_string();
        Some((
            drive,
            if tail.is_empty() {
                "\\".to_string()
            } else if tail.starts_with('\\') {
                tail
            } else {
                format!("\\{tail}")
            },
        ))
    }

    pub(in crate::runtime::engine) fn logical_drive_roots(&self) -> Vec<String> {
        let mut roots = Vec::new();
        Self::push_logical_drive_root(&mut roots, &self.volume_profile().root_path);
        Self::push_logical_drive_root(&mut roots, &self.windows_directory_path());
        Self::push_logical_drive_root(&mut roots, &self.current_directory_display_text());
        for volume in &self.objects.mounted_volumes {
            Self::push_logical_drive_root(&mut roots, &volume.guest_path);
        }
        if roots.is_empty() {
            roots.push(r"C:\".to_string());
        }
        roots
    }

    pub(in crate::runtime::engine) fn push_logical_drive_root(roots: &mut Vec<String>, raw: &str) {
        let Some((drive, _)) = Self::split_windows_drive_and_tail(raw) else {
            return;
        };
        let root = format!("{drive}\\");
        if !roots
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&root))
        {
            roots.push(root);
        }
    }

    pub(in crate::runtime::engine) fn drive_type_for_path(&self, raw: &str) -> u64 {
        let profile = self.volume_profile();
        let Some((drive, _)) = Self::split_windows_drive_and_tail(raw) else {
            return u64::from(profile.drive_type.max(1));
        };
        if self
            .logical_drive_roots()
            .iter()
            .any(|root| root[..2].eq_ignore_ascii_case(&drive))
        {
            u64::from(profile.drive_type.max(1))
        } else {
            u64::from(profile.drive_type.max(1))
        }
    }

    pub(in crate::runtime::engine) fn disk_capacity_triplet(&self) -> (u64, u64, u64) {
        let profile = self.volume_profile();
        let total = profile.total_bytes.max(1);
        let free = profile.free_bytes.min(total);
        let available = profile.available_bytes.min(free);
        (available, total, free)
    }

    fn synthetic_volume_guid_for_root(root: &str) -> String {
        let drive = Self::split_windows_drive_and_tail(root)
            .map(|(drive, _)| drive)
            .unwrap_or_else(|| "C:".to_string());
        let seed = u32::from(
            drive
                .as_bytes()
                .first()
                .copied()
                .unwrap_or(b'C')
                .to_ascii_uppercase(),
        );
        format!(
            r"\\?\Volume{{{:08x}-{:04x}-{:04x}-{:04x}-{:012x}}}\",
            0x564F_0000 | seed,
            0x1100 | seed,
            0x2200 | seed,
            0x3300 | seed,
            0x4400_0000_0000u64 | u64::from(seed)
        )
    }

    pub(in crate::runtime::engine) fn volume_guid_path(&self) -> String {
        let raw = self.volume_profile().volume_guid.trim();
        if raw.is_empty() {
            r"\\?\Volume{00000000-0000-0000-0000-000000000000}\".to_string()
        } else {
            let mut normalized = raw.replace('/', "\\");
            if !normalized.ends_with('\\') {
                normalized.push('\\');
            }
            normalized
        }
    }

    pub(in crate::runtime::engine) fn volume_guid_path_for_root(&self, root: &str) -> String {
        if Self::normalize_windows_path(root)
            == Self::normalize_windows_path(&self.volume_profile().root_path)
        {
            self.volume_guid_path()
        } else {
            Self::synthetic_volume_guid_for_root(root)
        }
    }

    pub(in crate::runtime::engine) fn volume_guid_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = Vec::new();
        for root in self.logical_drive_roots() {
            let candidate = self.volume_guid_path_for_root(&root);
            if !paths
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&candidate))
            {
                paths.push(candidate);
            }
        }
        if paths.is_empty() {
            paths.push(self.volume_guid_path());
        }
        paths
    }

    pub(in crate::runtime::engine) fn resolve_volume_guid_path(
        &self,
        raw: &str,
    ) -> Option<(String, bool)> {
        let normalized = Self::normalize_windows_path(raw);
        for root in self.logical_drive_roots() {
            let volume_guid = self.volume_guid_path_for_root(&root);
            let guid_root = Self::normalize_windows_path(volume_guid.trim_end_matches('\\'));
            if normalized == guid_root {
                return Some((root, true));
            }
            let prefix = format!("{guid_root}\\");
            if let Some(tail) = normalized.strip_prefix(&prefix) {
                return Some((Self::join_windows_display_path(&root, tail), false));
            }
        }
        None
    }

    pub(in crate::runtime::engine) fn find_first_volume(
        &mut self,
        buffer: u64,
        buffer_chars: usize,
    ) -> Result<u64, VmError> {
        let entries = self.volume_guid_paths();
        let Some(first) = entries.first().cloned() else {
            self.set_last_error(ERROR_NO_MORE_FILES as u32);
            return Ok(0);
        };
        let required = first.encode_utf16().count() + 1;
        if buffer == 0 || buffer_chars < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(0);
        }
        let handle = self.allocate_object_handle();
        self.handles
            .volume_find_handles
            .insert(handle, VolumeFindHandleState { entries, cursor: 1 });
        let _ = self.write_wide_string_to_memory(buffer, buffer_chars, &first)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(handle as u64)
    }

    pub(in crate::runtime::engine) fn find_next_volume(
        &mut self,
        handle: u32,
        buffer: u64,
        buffer_chars: usize,
    ) -> Result<u64, VmError> {
        if buffer == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let Some(state) = self.handles.volume_find_handles.get_mut(&handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let Some(entry) = state.entries.get(state.cursor).cloned() else {
            self.set_last_error(ERROR_NO_MORE_FILES as u32);
            return Ok(0);
        };
        let required = entry.encode_utf16().count() + 1;
        if buffer_chars < required {
            self.set_last_error(ERROR_MORE_DATA as u32);
            return Ok(0);
        }
        state.cursor += 1;
        let _ = self.write_wide_string_to_memory(buffer, buffer_chars, &entry)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn close_find_volume_handle(&mut self, handle: u32) -> u64 {
        if self.handles.volume_find_handles.remove(&handle).is_some() {
            self.set_last_error(ERROR_SUCCESS as u32);
            1
        } else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            0
        }
    }

    pub(in crate::runtime::engine) fn query_dos_device_targets(&self, raw: &str) -> Vec<String> {
        let normalized = raw.trim().trim_end_matches('\\').replace('/', "\\");
        if normalized.is_empty() {
            return self.query_dos_device_names();
        }
        if normalized.len() == 2 && normalized.as_bytes()[1] == b':' {
            return vec![r"\Device\HarddiskVolume1".to_string()];
        }
        if let Some(index) = normalized
            .to_ascii_lowercase()
            .strip_prefix("physicaldrive")
            .and_then(|suffix| suffix.parse::<u32>().ok())
            .filter(|index| self.synthetic_physical_drive_exists(*index))
        {
            return vec![format!(r"\Device\Harddisk{index}\DR{index}")];
        }
        if normalized.eq_ignore_ascii_case("nul") {
            return vec![r"\Device\Null".to_string()];
        }
        if normalized.eq_ignore_ascii_case("con") {
            return vec![r"\Device\ConDrv\Console".to_string()];
        }
        Vec::new()
    }

    pub(in crate::runtime::engine) fn query_dos_device_names(&self) -> Vec<String> {
        let mut names = self
            .logical_drive_roots()
            .into_iter()
            .map(|root| root.trim_end_matches('\\').to_string())
            .collect::<Vec<_>>();
        for index in 0..self.synthetic_physical_drive_count() {
            let name = format!("PhysicalDrive{index}");
            if !names
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&name))
            {
                names.push(name);
            }
        }
        for extra in ["NUL", "CON"] {
            if !names
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(extra))
            {
                names.push(extra.to_string());
            }
        }
        names
    }

    pub(in crate::runtime::engine) fn write_ascii_path_result(
        &mut self,
        address: u64,
        max_chars: usize,
        path: &str,
    ) -> Result<u64, VmError> {
        if address != 0 && max_chars != 0 {
            let _ = self.write_c_string_to_memory(address, max_chars, path)?;
        }
        Ok(path.len() as u64)
    }

    pub(in crate::runtime::engine) fn write_wide_path_result(
        &mut self,
        address: u64,
        max_chars: usize,
        path: &str,
    ) -> Result<u64, VmError> {
        if address != 0 && max_chars != 0 {
            let _ = self.write_wide_string_to_memory(address, max_chars, path)?;
        }
        Ok(path.chars().count() as u64)
    }

    pub(in crate::runtime::engine) fn path_find_file_name_w(
        &self,
        address: u64,
    ) -> Result<u64, VmError> {
        if address == 0 {
            return Ok(0);
        }
        let mut cursor = address;
        let mut last = address;
        loop {
            let word = self.read_u16(cursor)?;
            if word == 0 {
                break;
            }
            if matches!(char::from_u32(word as u32), Some('\\' | '/')) {
                last = cursor + 2;
            }
            cursor += 2;
        }
        Ok(last)
    }

    pub(in crate::runtime::engine) fn write_file_attributes_ex(
        &mut self,
        path: &str,
        info_ptr: u64,
    ) -> Result<u64, VmError> {
        if info_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let Some(target) = self.prepare_runtime_read_target(path, "GetFileAttributesExW")? else {
            return Ok(0);
        };
        let metadata = match std::fs::metadata(&target) {
            Ok(metadata) => metadata,
            Err(_) => {
                self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                return Ok(0);
            }
        };
        let mut payload = [0u8; 36];
        let attributes = if metadata.is_dir() {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        payload[0..4].copy_from_slice(&attributes.to_le_bytes());
        payload[28..32].copy_from_slice(&((metadata.len() >> 32) as u32).to_le_bytes());
        payload[32..36].copy_from_slice(&(metadata.len() as u32).to_le_bytes());
        self.core.modules.memory_mut().write(info_ptr, &payload)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn set_end_of_file(
        &mut self,
        handle: u32,
    ) -> Result<u64, VmError> {
        let Some(state) = self.handles.file_handles.get_mut(&handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let position = state
            .file
            .stream_position()
            .map_err(|source| VmError::CommandIo {
                program: "file stream_position".to_string(),
                source,
            })?;
        let path = state.path.clone();
        let result = state.file.set_len(position).is_ok() as u64;
        if result != 0 {
            self.log_file_event("FILE_TRUNCATE", handle, &path, Some(position))?;
            self.set_last_error(ERROR_SUCCESS as u32);
        }
        Ok(result)
    }

    /// Creates a file handle backed by the interception rule's inline content.
    pub(super) fn create_intercepted_file_handle(
        &mut self,
        guest_path: &str,
        data: Vec<u8>,
        desired_access: u64,
    ) -> Result<u64, VmError> {
        self.log_interception("file", "CreateFile", guest_path, "return_content")?;
        // Write content to a temp file so standard file I/O works.
        let temp_dir = std::env::temp_dir().join("hvm-interception");
        std::fs::create_dir_all(&temp_dir).map_err(|source| VmError::OutputIo {
            path: temp_dir.clone(),
            source,
        })?;
        let temp_path = temp_dir.join(format!(
            "intercept_{}_{}",
            std::process::id(),
            self.handles.next_file_handle
        ));
        std::fs::write(&temp_path, &data).map_err(|source| VmError::OutputIo {
            path: temp_path.clone(),
            source,
        })?;
        let file = std::fs::File::open(&temp_path).map_err(|source| VmError::OutputIo {
            path: temp_path.clone(),
            source,
        })?;
        let handle = self.allocate_file_handle();
        self.handles.file_handles.insert(
            handle,
            FileHandleState {
                file,
                path: guest_path.to_string(),
                writable: desired_access & 0x4000_0000 != 0,
            },
        );
        self.set_last_error(ERROR_SUCCESS as u32);
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("path".to_string(), json!(guest_path));
        fields.insert("desired_access".to_string(), json!(desired_access));
        fields.insert("intercepted".to_string(), json!(true));
        self.log_runtime_event("FILE_OPEN", fields)?;
        Ok(handle as u64)
    }

    /// Creates a file handle that redirects to a host path.
    pub(super) fn create_redirected_file_handle(
        &mut self,
        guest_path: &str,
        host_path: &std::path::Path,
        desired_access: u64,
        creation_disposition: u64,
    ) -> Result<u64, VmError> {
        if !host_path.exists() {
            self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
            return Ok(self.invalid_handle_value_for_arch());
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        if desired_access & 0x4000_0000 != 0 {
            options.write(true);
        }
        match creation_disposition {
            2 => options.create(true).truncate(true),
            4 => options.create(true),
            5 => options.truncate(true),
            _ => &mut options,
        };
        let file = match options.open(host_path) {
            Ok(file) => file,
            Err(_) => {
                self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                return Ok(self.invalid_handle_value_for_arch());
            }
        };
        let handle = self.allocate_file_handle();
        self.handles.file_handles.insert(
            handle,
            FileHandleState {
                file,
                path: guest_path.to_string(),
                writable: desired_access & 0x4000_0000 != 0,
            },
        );
        self.set_last_error(ERROR_SUCCESS as u32);
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("path".to_string(), json!(guest_path));
        fields.insert(
            "host_path".to_string(),
            json!(host_path.to_string_lossy().to_string()),
        );
        fields.insert("desired_access".to_string(), json!(desired_access));
        fields.insert("redirected".to_string(), json!(true));
        self.log_runtime_event("FILE_OPEN", fields)?;
        Ok(handle as u64)
    }
}
