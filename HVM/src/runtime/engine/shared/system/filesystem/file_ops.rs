use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn create_file_handle(
        &mut self,
        path: &str,
        desired_access: u64,
        creation_disposition: u64,
    ) -> Result<u64, VmError> {
        let normalized = path.trim();
        if normalized.eq_ignore_ascii_case("CONOUT$") {
            return Ok(self.std_handle_value_for_arch(STD_OUTPUT_HANDLE));
        }
        if normalized.eq_ignore_ascii_case("CONIN$") {
            return Ok(self.std_handle_value_for_arch(STD_INPUT_HANDLE));
        }
        // Check file interception rules.
        let file_interception = self
            .core
            .config
            .interception_rule_for_file(normalized)
            .map(|rule| rule.action.clone());
        if let Some(action) = file_interception {
            match &action {
                FileInterceptionAction::NotFound => {
                    self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                    self.log_interception("file", "CreateFile", normalized, "not_found")?;
                    return Ok(self.invalid_handle_value_for_arch());
                }
                FileInterceptionAction::AccessDenied => {
                    self.set_last_error(ERROR_ACCESS_DENIED as u32);
                    self.log_interception("file", "CreateFile", normalized, "access_denied")?;
                    return Ok(self.invalid_handle_value_for_arch());
                }
                FileInterceptionAction::ReturnContent { data } => {
                    return self.create_intercepted_file_handle(
                        normalized,
                        data.clone(),
                        desired_access,
                    );
                }
                FileInterceptionAction::Redirect { host_path } => {
                    self.log_interception("file", "CreateFile", normalized, "redirect")?;
                    return self.create_redirected_file_handle(
                        normalized,
                        host_path,
                        desired_access,
                        creation_disposition,
                    );
                }
            }
        }
        if let Some(rule) = self
            .core
            .config
            .hidden_device_rule_for(normalized)
            .map(str::to_string)
        {
            self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
            self.log_artifact_hide("device_path", "CreateFile", normalized, &rule)?;
            return Ok(self.invalid_handle_value_for_arch());
        }
        if let Some(index) = Self::physical_drive_index(normalized) {
            if !self.synthetic_physical_drive_exists(index) {
                self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
                return Ok(self.invalid_handle_value_for_arch());
            }
            return self.create_synthetic_device_handle(
                normalized,
                Some(index),
                desired_access,
                creation_disposition,
            );
        }
        if let Some((_, is_root)) = self.resolve_volume_guid_path(normalized) {
            if is_root {
                return self.create_synthetic_device_handle(
                    normalized,
                    None,
                    desired_access,
                    creation_disposition,
                );
            }
        }
        if self.is_device_path(normalized) {
            return self.create_synthetic_device_handle(
                normalized,
                None,
                desired_access,
                creation_disposition,
            );
        }

        // Determine whether the open involves writing or file creation.
        let is_write = desired_access & 0x4000_0000 != 0;
        let creates_file = matches!(creation_disposition, 1 | 2 | 4 | 5);

        // For volume-mounted paths, redirect writes to sandbox/virtual_fs so
        // the host filesystem is never modified.  Reads prefer virtual_fs
        // (previously-written files) then fall back to the real host.
        let target = if let Some(vpath) = self.resolve_volume_virtual_fs_path(normalized) {
            if is_write || creates_file {
                // Write/create: always target virtual_fs.
                if let Some(parent) = vpath.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                // Dispositions that need the original file content (OPEN_EXISTING,
                // OPEN_ALWAYS, TRUNCATE_EXISTING): seed from host if virtual_fs
                // doesn't already have the file.
                if matches!(creation_disposition, 3 | 4 | 5) && !vpath.exists() {
                    if let Some(host_path) = self.resolve_absolute_runtime_path(normalized) {
                        if host_path.exists() {
                            let _ = std::fs::copy(&host_path, &vpath);
                        }
                    }
                }
                vpath
            } else if vpath.exists() {
                // Read-only: prefer previously-written virtual_fs copy.
                vpath
            } else {
                // Read-only: fall back to host resolution.
                let Some(t) = self.prepare_runtime_read_target(normalized, "CreateFile")? else {
                    return Ok(self.invalid_handle_value_for_arch());
                };
                t
            }
        } else {
            // Not a volume-mounted path — normal resolution.
            let Some(t) = self.prepare_runtime_read_target(normalized, "CreateFile")? else {
                return Ok(self.invalid_handle_value_for_arch());
            };
            t
        };

        let mut options = std::fs::OpenOptions::new();
        if desired_access == 0 || desired_access & 0x8000_0000 != 0 {
            options.read(true);
        }
        if desired_access & 0x4000_0000 != 0 {
            options.write(true);
        }
        match creation_disposition {
            1 => {
                options.create_new(true);
            }
            2 => {
                options.create(true).truncate(true);
            }
            4 => {
                options.create(true);
            }
            5 => {
                options.truncate(true);
            }
            _ => {}
        }

        let file = match options.open(&target) {
            Ok(file) => file,
            Err(source) => {
                self.set_last_error(match source.kind() {
                    std::io::ErrorKind::PermissionDenied => ERROR_ACCESS_DENIED as u32,
                    std::io::ErrorKind::AlreadyExists => ERROR_ALREADY_EXISTS as u32,
                    _ => ERROR_FILE_NOT_FOUND as u32,
                });
                return Ok(self.invalid_handle_value_for_arch());
            }
        };
        let handle = self.allocate_file_handle();
        let normalized_path = target.to_string_lossy().to_string();
        self.handles.file_handles.insert(
            handle,
            FileHandleState {
                file,
                path: normalized_path.clone(),
                writable: desired_access & 0x4000_0000 != 0,
            },
        );
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("path".to_string(), json!(normalized_path));
        fields.insert("desired_access".to_string(), json!(desired_access));
        fields.insert(
            "creation_disposition".to_string(),
            json!(creation_disposition),
        );
        self.log_runtime_event("FILE_OPEN", fields)?;
        self.record_file_operation("create", normalized, None);
        Ok(handle as u64)
    }

    pub(in crate::runtime::engine) fn create_synthetic_device_handle(
        &mut self,
        path: &str,
        physical_drive_index: Option<u32>,
        desired_access: u64,
        creation_disposition: u64,
    ) -> Result<u64, VmError> {
        let handle = self.allocate_file_handle();
        self.handles.device_handles.insert(
            handle,
            DeviceHandleState {
                path: path.to_string(),
                physical_drive_index,
                position: 0,
            },
        );
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("path".to_string(), json!(path));
        fields.insert("desired_access".to_string(), json!(desired_access));
        fields.insert(
            "creation_disposition".to_string(),
            json!(creation_disposition),
        );
        fields.insert("device".to_string(), json!(true));
        if let Some(index) = physical_drive_index {
            fields.insert("physical_drive_index".to_string(), json!(index));
        }
        self.log_runtime_event("FILE_OPEN", fields)?;
        Ok(handle as u64)
    }

    pub(in crate::runtime::engine) fn allocate_file_handle(&mut self) -> u32 {
        let handle = self.handles.next_file_handle;
        self.handles.next_file_handle = self.handles.next_file_handle.saturating_add(4);
        handle
    }

    pub(in crate::runtime::engine) fn allocate_object_handle(&mut self) -> u32 {
        let handle = self.handles.next_object_handle;
        self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
        handle
    }

    pub(in crate::runtime::engine) fn is_device_path(&self, path: &str) -> bool {
        let normalized = path.trim().to_ascii_lowercase();
        normalized.starts_with(r"\\.\")
    }

    pub(in crate::runtime::engine) fn synthetic_physical_drive_count(&self) -> u32 {
        self.volume_profile().physical_drive_count.max(1)
    }

    pub(in crate::runtime::engine) fn physical_drive_index(path: &str) -> Option<u32> {
        let normalized = path.trim().to_ascii_lowercase();
        let suffix = normalized.strip_prefix(r"\\.\physicaldrive")?;
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        suffix.parse::<u32>().ok()
    }

    pub(in crate::runtime::engine) fn synthetic_physical_drive_exists(&self, index: u32) -> bool {
        index < self.synthetic_physical_drive_count()
    }

    fn synthetic_disk_geometry(&self) -> (u64, u32, u32, u32, u64) {
        let cylinders = 16_383u64;
        let tracks_per_cylinder = 255u32;
        let sectors_per_track = 63u32;
        let bytes_per_sector = 512u32;
        let disk_size = cylinders
            .saturating_mul(u64::from(tracks_per_cylinder))
            .saturating_mul(u64::from(sectors_per_track))
            .saturating_mul(u64::from(bytes_per_sector));
        (
            cylinders,
            tracks_per_cylinder,
            sectors_per_track,
            bytes_per_sector,
            disk_size,
        )
    }

    pub(in crate::runtime::engine) fn set_device_file_pointer(
        &mut self,
        handle: u32,
        distance: u64,
        method: u64,
    ) -> Option<u64> {
        let disk_size = self.synthetic_disk_geometry().4;
        let state = self.handles.device_handles.get_mut(&handle)?;
        state.physical_drive_index?;
        let position = match method {
            1 => state.position.saturating_add(distance),
            2 => disk_size.saturating_add(distance),
            _ => distance,
        };
        state.position = position;
        Some(position)
    }

    pub(in crate::runtime::engine) fn flush_device_handle(&self, handle: u32) -> Option<u64> {
        self.handles
            .device_handles
            .get(&handle)
            .and_then(|state| state.physical_drive_index.map(|_| 1))
    }

    pub(in crate::runtime::engine) fn write_device_handle(
        &mut self,
        handle: u32,
        data: &[u8],
    ) -> Result<Option<usize>, VmError> {
        let Some((path, offset, physical_drive_index)) = ({
            let state = self.handles.device_handles.get_mut(&handle);
            state.and_then(|state| {
                let physical_drive_index = state.physical_drive_index?;
                let path = state.path.clone();
                let offset = state.position;
                state.position = state.position.saturating_add(data.len() as u64);
                Some((path, offset, physical_drive_index))
            })
        }) else {
            return Ok(None);
        };

        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("path".to_string(), json!(path));
        fields.insert("bytes".to_string(), json!(data.len()));
        fields.insert("device".to_string(), json!(true));
        fields.insert("offset".to_string(), json!(offset));
        fields.insert(
            "physical_drive_index".to_string(),
            json!(physical_drive_index),
        );
        fields.insert(
            "all_zero".to_string(),
            json!(data.iter().all(|byte| *byte == 0)),
        );
        Self::add_payload_preview_field(&mut fields, data);
        self.log_runtime_event("FILE_WRITE", fields)?;
        Ok(Some(data.len()))
    }

    pub(in crate::runtime::engine) fn handle_device_io_control(
        &mut self,
        handle: u32,
        code: u64,
        args: &[u64],
    ) -> Result<Option<u64>, VmError> {
        let Some(device) = self.handles.device_handles.get(&handle).cloned() else {
            return Ok(None);
        };
        if device
            .physical_drive_index
            .is_some_and(|index| self.synthetic_physical_drive_exists(index))
            && code == 0x0007_00A0
        {
            let out_buffer = args.arg(4);
            let out_length = args.arg(5) as usize;
            let bytes_returned_ptr = args.arg(6);
            const GEOMETRY_EX_LEN: usize = 32;
            if out_buffer == 0 || out_length < GEOMETRY_EX_LEN {
                if bytes_returned_ptr != 0 {
                    self.write_u32(bytes_returned_ptr, 0)?;
                }
                self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
                return Ok(Some(0));
            }

            let (cylinders, tracks_per_cylinder, sectors_per_track, bytes_per_sector, disk_size) =
                self.synthetic_disk_geometry();
            let mut payload = vec![0u8; GEOMETRY_EX_LEN];
            payload[0..8].copy_from_slice(&cylinders.to_le_bytes());
            payload[8..12].copy_from_slice(&(12u32).to_le_bytes());
            payload[12..16].copy_from_slice(&tracks_per_cylinder.to_le_bytes());
            payload[16..20].copy_from_slice(&sectors_per_track.to_le_bytes());
            payload[20..24].copy_from_slice(&bytes_per_sector.to_le_bytes());
            payload[24..32].copy_from_slice(&disk_size.to_le_bytes());
            self.core.modules.memory_mut().write(out_buffer, &payload)?;
            if bytes_returned_ptr != 0 {
                self.write_u32(bytes_returned_ptr, GEOMETRY_EX_LEN as u32)?;
            }
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(Some(1));
        }
        // For generic device paths (e.g. \\.\360SelfProtection), check
        // interception_rules.devices first for a configured response,
        // then fall back to a generic success with non-zero output.
        if device.physical_drive_index.is_none() {
            let out_buffer = args.arg(4);
            let bytes_returned_ptr = args.arg(6);

            // Check config interception rules for this device.
            if let Some(rule) = self
                .core
                .config
                .interception_rule_for_device(&device.path, code)
            {
                if out_buffer != 0 && !rule.output.is_empty() {
                    let write_len = rule.output.len().min(args.arg(5) as usize).min(4096);
                    self.core
                        .modules
                        .memory_mut()
                        .write(out_buffer, &rule.output[..write_len])?;
                }
                if bytes_returned_ptr != 0 && rule.bytes_returned > 0 {
                    self.write_u32(bytes_returned_ptr, rule.bytes_returned)?;
                }
                self.set_last_error(ERROR_SUCCESS as u32);
                return Ok(Some(1));
            }

            // Generic fallback: return success with non-zero output.
            if out_buffer != 0 {
                let out_length = args.arg(5) as usize;
                let len = out_length.min(4096);
                let mut data = vec![0u8; len];
                if len >= 4 {
                    data[0..4].copy_from_slice(&1u32.to_le_bytes());
                }
                self.core.modules.memory_mut().write(out_buffer, &data)?;
            }
            if bytes_returned_ptr != 0 {
                self.write_u32(bytes_returned_ptr, 4)?;
            }
            self.set_last_error(ERROR_SUCCESS as u32);
            return Ok(Some(1));
        }
        Ok(None)
    }

    pub(in crate::runtime::engine) fn write_netbios_lana_enum(
        &mut self,
        buffer: u64,
        length: usize,
    ) -> Result<(), VmError> {
        if buffer == 0 || length == 0 {
            return Ok(());
        }
        self.core
            .modules
            .memory_mut()
            .write(buffer, &vec![0u8; length])?;
        Ok(())
    }

    pub(in crate::runtime::engine) fn normalize_windows_path(value: &str) -> String {
        value
            .trim()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    }

    pub(in crate::runtime::engine) fn is_windows_absolute_path(raw: &str) -> bool {
        let bytes = raw.trim().as_bytes();
        bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/')
    }

    pub(in crate::runtime::engine) fn path_contains_wildcards(raw: &str) -> bool {
        raw.as_bytes()
            .iter()
            .any(|byte| matches!(*byte, b'*' | b'?'))
    }

    pub(in crate::runtime::engine) fn virtual_windows_root(&self) -> std::path::PathBuf {
        let configured = self.core.config.sandbox_output_dir.clone();
        if std::fs::create_dir_all(&configured).is_ok() {
            return configured.join("virtual_fs");
        }

        let fallback = std::env::temp_dir().join("hvm-hikari-virtual-engine-output");
        let _ = std::fs::create_dir_all(&fallback);
        fallback.join("virtual_fs")
    }

    pub(in crate::runtime::engine) fn windows_path_components(raw: &str) -> Vec<String> {
        raw.trim()
            .replace('/', "\\")
            .split('\\')
            .filter(|component| !component.is_empty())
            .map(str::to_string)
            .collect()
    }

    pub(in crate::runtime::engine) fn build_runtime_volume_mounts(
        config: &EngineConfig,
        environment_profile: &EnvironmentProfile,
    ) -> Vec<MountedVolume> {
        let mut specs = config
            .volumes
            .iter()
            .cloned()
            .map(|volume| (volume, 0u8))
            .collect::<Vec<_>>();
        if config.auto_mount_module_dirs {
            specs.extend(
                Self::derive_auto_mount_volumes(config, environment_profile)
                    .into_iter()
                    .map(|volume| (volume, 1u8)),
            );
        }
        Self::build_mounted_volumes(&specs)
    }

    pub(in crate::runtime::engine) fn build_mounted_volumes(
        specs: &[(VolumeMount, u8)],
    ) -> Vec<MountedVolume> {
        let mut mounted = specs
            .iter()
            .map(|(volume, priority)| MountedVolume {
                host_path: volume.host_path.clone(),
                guest_path: Self::normalize_windows_path(&volume.guest_path),
                guest_components: Self::windows_path_components(&volume.guest_path)
                    .into_iter()
                    .map(|component| component.to_ascii_lowercase())
                    .collect(),
                recursive: volume.recursive,
                host_is_dir: volume.host_path.is_dir(),
                priority: *priority,
            })
            .collect::<Vec<_>>();
        mounted.sort_by(|left, right| {
            right
                .guest_components
                .len()
                .cmp(&left.guest_components.len())
                .then_with(|| right.guest_path.len().cmp(&left.guest_path.len()))
                .then_with(|| left.priority.cmp(&right.priority))
        });
        mounted
    }

    pub(in crate::runtime::engine) fn derive_auto_mount_volumes(
        config: &EngineConfig,
        environment_profile: &EnvironmentProfile,
    ) -> Vec<VolumeMount> {
        let mut derived = Vec::new();
        let runtime_guest_directory =
            Self::normalize_windows_guest_directory(&environment_profile.machine.current_directory)
                .or_else(|| {
                    Self::windows_parent_display_path(&environment_profile.machine.image_path)
                });
        let image_guest_directory =
            Self::windows_parent_display_path(&environment_profile.machine.image_path);

        let effective_host_directory = config
            .entry_module_path()
            .parent()
            .map(std::path::Path::to_path_buf);
        if let (Some(host_path), Some(guest_path)) =
            (effective_host_directory, runtime_guest_directory)
        {
            Self::push_auto_mount_volume(&mut derived, &config.volumes, host_path, guest_path);
        }

        let process_host_directory = config
            .process_image_path()
            .parent()
            .map(std::path::Path::to_path_buf);
        if let (Some(host_path), Some(guest_path)) = (process_host_directory, image_guest_directory)
        {
            Self::push_auto_mount_volume(&mut derived, &config.volumes, host_path, guest_path);
        }

        derived
    }

    pub(in crate::runtime::engine) fn push_auto_mount_volume(
        derived: &mut Vec<VolumeMount>,
        explicit: &[VolumeMount],
        host_path: std::path::PathBuf,
        guest_path: String,
    ) {
        if !host_path.exists() {
            return;
        }
        if explicit
            .iter()
            .any(|volume| volume.guest_path.eq_ignore_ascii_case(&guest_path))
        {
            return;
        }
        if derived
            .iter()
            .any(|volume| volume.guest_path.eq_ignore_ascii_case(&guest_path))
        {
            return;
        }
        derived.push(VolumeMount {
            host_path,
            guest_path,
            recursive: true,
        });
    }

    pub(in crate::runtime::engine) fn normalize_windows_guest_directory(
        raw: &str,
    ) -> Option<String> {
        let normalized = Self::normalize_windows_display_path(raw);
        Self::is_windows_absolute_path(&normalized).then_some(normalized)
    }

    pub(in crate::runtime::engine) fn windows_parent_display_path(raw: &str) -> Option<String> {
        let normalized = Self::normalize_windows_display_path(raw);
        if !Self::is_windows_absolute_path(&normalized) {
            return None;
        }
        let mut trimmed = normalized.trim_end_matches('\\').to_string();
        if trimmed.len() <= 3 {
            return Some(format!("{}\\", &trimmed[..2]));
        }
        let split = trimmed.rfind('\\')?;
        if split <= 2 {
            trimmed.truncate(2);
            trimmed.push('\\');
            Some(trimmed)
        } else {
            trimmed.truncate(split);
            Some(trimmed)
        }
    }

    pub(in crate::runtime::engine) fn map_volume_runtime_path(
        &self,
        raw: &str,
    ) -> Option<std::path::PathBuf> {
        if !Self::is_windows_absolute_path(raw.trim()) {
            return None;
        }
        let raw_components = Self::windows_path_components(raw);
        for volume in &self.objects.mounted_volumes {
            if raw_components.len() < volume.guest_components.len() {
                continue;
            }
            let matches = raw_components
                .iter()
                .zip(&volume.guest_components)
                .all(|(left, right)| left.eq_ignore_ascii_case(right));
            if !matches {
                continue;
            }

            let remainder = &raw_components[volume.guest_components.len()..];
            if remainder.is_empty() {
                return Some(volume.host_path.clone());
            }
            if !volume.host_is_dir || !volume.recursive {
                continue;
            }

            let mut mapped = volume.host_path.clone();
            for component in remainder {
                if component == ".." {
                    mapped.pop();
                } else if component != "." {
                    mapped.push(component);
                }
            }
            // Windows is case-insensitive; if the exact path doesn't exist,
            // try a case-insensitive lookup in the parent directory.
            if !mapped.exists() {
                if let Some(fallback) = Self::resolve_case_insensitive(&mapped) {
                    return Some(fallback);
                }
            }
            return Some(mapped);
        }
        None
    }

    pub(in crate::runtime::engine) fn resolve_absolute_runtime_path(
        &self,
        raw: &str,
    ) -> Option<std::path::PathBuf> {
        // Process image path mapping takes highest priority: when the sample
        // opens its own executable (by the configured image_path name), always
        // redirect to the real host file regardless of volume mounts.
        if let Some(mapped) = self.resolve_process_image_host_path(raw) {
            return Some(mapped);
        }
        if let Some((guest_path, _)) = self.resolve_volume_guid_path(raw) {
            if let Some(mapped) = self.map_volume_runtime_path(&guest_path) {
                return Some(mapped);
            }
            if let Some(mapped) = self.map_windows_runtime_path(&guest_path) {
                return Some(mapped);
            }
        }
        if let Some(mapped) = self.map_volume_runtime_path(raw) {
            return Some(mapped);
        }
        if let Some(mapped) = self.map_windows_runtime_path(raw) {
            return Some(mapped);
        }
        let candidate = std::path::PathBuf::from(raw);
        candidate.is_absolute().then_some(candidate)
    }

    /// Maps the profile's configured image_path (e.g. "F:\._winrar-x86-611.exe")
    /// to the actual process image on the host filesystem.
    pub(in crate::runtime::engine) fn resolve_process_image_host_path(
        &self,
        raw: &str,
    ) -> Option<std::path::PathBuf> {
        let configured = &self.core.environment_profile.machine.image_path;
        if configured.is_empty() {
            return None;
        }
        let normalized = Self::normalize_windows_path(raw.trim());
        let configured_normalized = Self::normalize_windows_path(configured);
        if normalized != configured_normalized {
            return None;
        }
        let process_image = self.core.config.process_image_path();
        if process_image.exists() {
            return Some(process_image.to_path_buf());
        }
        None
    }

    /// For volume-mounted paths (e.g., F:\file.exe), compute the sandbox
    /// virtual_fs equivalent (e.g., sandbox/virtual_fs/F/file.exe).
    /// Returns None if the path is not volume-mounted or is the process image.
    pub(in crate::runtime::engine) fn resolve_volume_virtual_fs_path(
        &self,
        raw: &str,
    ) -> Option<std::path::PathBuf> {
        let trimmed = raw.trim();
        if !Self::is_windows_absolute_path(trimmed) {
            return None;
        }
        // Never redirect the process image path — it must always resolve to
        // the real host file so the engine can read the PE correctly.
        if self.resolve_process_image_host_path(trimmed).is_some() {
            return None;
        }
        // Only redirect paths that would be resolved via volume mapping.
        if self.map_volume_runtime_path(trimmed).is_none() {
            return None;
        }
        let drive = (trimmed.as_bytes()[0] as char)
            .to_ascii_uppercase()
            .to_string();
        let mut vpath = self.virtual_windows_root().join(drive);
        for component in trimmed[3..].split(['\\', '/']).filter(|c| !c.is_empty()) {
            if component == ".." {
                vpath.pop();
            } else if component != "." {
                vpath.push(component);
            }
        }
        Some(vpath)
    }

    pub(in crate::runtime::engine) fn runtime_path_is_volume_backed(
        &self,
        path: &std::path::Path,
    ) -> Result<bool, VmError> {
        let normalized_path = Self::normalize_host_policy_path(path)?;
        for volume in &self.objects.mounted_volumes {
            let host_root = Self::normalize_host_policy_path(&volume.host_path)?;
            if normalized_path == host_root {
                return Ok(true);
            }
            if volume.host_is_dir
                && volume.recursive
                && Self::path_is_within(&host_root, &normalized_path)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(in crate::runtime::engine) fn normalize_windows_display_path(raw: &str) -> String {
        raw.trim().replace('/', "\\")
    }

    pub(in crate::runtime::engine) fn join_windows_display_path(base: &str, child: &str) -> String {
        if child.trim().is_empty() {
            return Self::normalize_windows_display_path(base);
        }
        if Self::is_windows_absolute_path(child) {
            return Self::normalize_windows_display_path(child);
        }
        let mut joined = Self::normalize_windows_display_path(base);
        if !joined.ends_with('\\') {
            joined.push('\\');
        }
        joined.push_str(child.trim().trim_start_matches(['\\', '/']));
        joined
    }

    pub(in crate::runtime::engine) fn resolve_runtime_display_path(&self, raw: &str) -> String {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return self.current_directory_display_text();
        }
        if Self::is_windows_absolute_path(trimmed) {
            return Self::normalize_windows_display_path(trimmed);
        }
        let candidate = std::path::PathBuf::from(trimmed);
        if candidate.is_absolute() {
            return candidate.to_string_lossy().to_string();
        }
        let current_directory = self.current_directory_display_text();
        if Self::is_windows_absolute_path(&current_directory) {
            return Self::join_windows_display_path(&current_directory, trimmed);
        }
        self.core
            .current_directory_host
            .join(candidate)
            .to_string_lossy()
            .to_string()
    }

    pub(in crate::runtime::engine) fn ensure_virtual_windows_layout(
        &mut self,
    ) -> Result<(), VmError> {
        let user_name = self.active_user_name().trim();
        let user_name = if user_name.is_empty() {
            "User"
        } else {
            user_name
        };
        let windows_root = self.windows_directory_path();
        let temp_dir = self.temporary_directory_path();
        let directories = [
            windows_root.clone(),
            self.system_directory_path(),
            format!("{}\\SysWOW64", windows_root.trim_end_matches(['\\', '/'])),
            r"C:\ProgramData".to_string(),
            format!(r"C:\Users\{user_name}"),
            format!(r"C:\Users\{user_name}\AppData\Roaming"),
            format!(r"C:\Users\{user_name}\AppData\Local"),
            temp_dir.clone(),
            r"C:\Temp".to_string(),
        ];
        for directory in directories {
            let target = self.resolve_runtime_path(&directory);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|source| VmError::OutputIo {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            std::fs::create_dir_all(&target).map_err(|source| VmError::OutputIo {
                path: target.clone(),
                source,
            })?;
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn normalize_host_policy_path(
        path: &std::path::Path,
    ) -> Result<std::path::PathBuf, VmError> {
        match path.canonicalize() {
            Ok(resolved) => Ok(resolved),
            Err(_) => std::path::absolute(path).map_err(|source| VmError::ReadFile {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    pub(in crate::runtime::engine) fn path_is_within(
        root: &std::path::Path,
        candidate: &std::path::Path,
    ) -> bool {
        candidate == root || candidate.starts_with(root)
    }

    pub(in crate::runtime::engine) fn runtime_path_is_virtualized(
        &self,
        path: &std::path::Path,
    ) -> Result<bool, VmError> {
        let virtual_root = self.virtual_windows_root();
        if Self::path_is_within(&virtual_root, path) {
            return Ok(true);
        }

        let normalized_path = Self::normalize_host_policy_path(path)?;
        let virtual_root = Self::normalize_host_policy_path(&virtual_root)?;
        Ok(Self::path_is_within(&virtual_root, &normalized_path))
    }

    pub(in crate::runtime::engine) fn host_read_policy_denial_reason(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<&'static str>, VmError> {
        // The emulated Windows filesystem must stay visible even when host reads are restricted.
        if self.runtime_path_is_virtualized(path)? {
            return Ok(None);
        }
        if self.runtime_path_is_volume_backed(path)? {
            return Ok(None);
        }

        let normalized_path = Self::normalize_host_policy_path(path)?;

        for blocked_path in &self.core.config.blocked_read_dirs {
            let blocked_path = Self::normalize_host_policy_path(blocked_path)?;
            if Self::path_is_within(&blocked_path, &normalized_path) {
                return Ok(Some("blocked_read_dirs"));
            }
        }

        if self.core.config.allowed_read_dirs.is_empty() {
            return Ok(None);
        }

        for allowed_path in &self.core.config.allowed_read_dirs {
            let allowed_path = Self::normalize_host_policy_path(allowed_path)?;
            if Self::path_is_within(&allowed_path, &normalized_path) {
                return Ok(None);
            }
        }

        Ok(Some("allowed_read_dirs"))
    }

    pub(in crate::runtime::engine) fn ensure_runtime_read_allowed_path(
        &mut self,
        path: &std::path::Path,
        operation: &str,
    ) -> Result<bool, VmError> {
        let Some(policy) = self.host_read_policy_denial_reason(path)? else {
            return Ok(true);
        };

        self.set_last_error(ERROR_ACCESS_DENIED as u32);
        let mut fields = Map::new();
        fields.insert("operation".to_string(), json!(operation));
        fields.insert(
            "path".to_string(),
            json!(Self::normalize_host_policy_path(path)?
                .to_string_lossy()
                .to_string()),
        );
        fields.insert("policy".to_string(), json!(policy));
        self.log_runtime_event("FILE_ACCESS_DENIED", fields)?;
        Ok(false)
    }

    pub(in crate::runtime::engine) fn ensure_runtime_read_allowed(
        &mut self,
        raw: &str,
        operation: &str,
    ) -> Result<bool, VmError> {
        let target = self.resolve_runtime_path(raw);
        self.ensure_runtime_read_allowed_path(&target, operation)
    }

    pub(in crate::runtime::engine) fn prepare_runtime_read_target(
        &mut self,
        raw: &str,
        operation: &str,
    ) -> Result<Option<std::path::PathBuf>, VmError> {
        if !self.ensure_runtime_read_allowed(raw, operation)? {
            return Ok(None);
        }
        self.ensure_runtime_path_backing(raw)?;
        Ok(Some(self.resolve_runtime_path(raw)))
    }

    pub(in crate::runtime::engine) fn prepare_runtime_directory_target(
        &mut self,
        raw: &str,
        operation: &str,
    ) -> Result<Option<std::path::PathBuf>, VmError> {
        let trimmed = raw.trim();
        let target = self.resolve_runtime_path(trimmed);
        let host_absolute =
            !Self::is_windows_absolute_path(trimmed) && std::path::Path::new(trimmed).is_absolute();
        if !host_absolute {
            return self.prepare_runtime_read_target(trimmed, operation);
        }

        let normalized_target = Self::normalize_host_policy_path(&target)?;
        for blocked_path in &self.core.config.blocked_read_dirs {
            let blocked_path = Self::normalize_host_policy_path(blocked_path)?;
            if Self::path_is_within(&blocked_path, &normalized_target) {
                self.set_last_error(ERROR_ACCESS_DENIED as u32);
                let mut fields = Map::new();
                fields.insert("operation".to_string(), json!(operation));
                fields.insert(
                    "path".to_string(),
                    json!(normalized_target.to_string_lossy().to_string()),
                );
                fields.insert("policy".to_string(), json!("blocked_read_dirs"));
                self.log_runtime_event("FILE_ACCESS_DENIED", fields)?;
                return Ok(None);
            }
        }

        self.ensure_runtime_path_backing(trimmed)?;
        Ok(Some(target))
    }

    pub(in crate::runtime::engine) fn map_windows_runtime_path(
        &self,
        raw: &str,
    ) -> Option<std::path::PathBuf> {
        let trimmed = raw.trim();
        if !Self::is_windows_absolute_path(trimmed) {
            return None;
        }

        let drive = (trimmed.as_bytes()[0] as char)
            .to_ascii_uppercase()
            .to_string();
        let mut mapped = self.virtual_windows_root().join(drive);
        for component in trimmed[3..]
            .split(['\\', '/'])
            .filter(|component| !component.is_empty())
        {
            mapped.push(component);
        }
        Some(mapped)
    }

    pub(in crate::runtime::engine) fn virtual_windows_system_prefixes(&self) -> [String; 2] {
        let windows_root = self.windows_directory_path();
        [
            format!(
                "{}\\system32",
                Self::normalize_windows_path(&windows_root).trim_end_matches('\\')
            ),
            format!(
                "{}\\syswow64",
                Self::normalize_windows_path(&windows_root).trim_end_matches('\\')
            ),
        ]
    }

    pub(in crate::runtime::engine) fn is_virtual_windows_system_path(&self, raw: &str) -> bool {
        let normalized = Self::normalize_windows_path(raw);
        self.virtual_windows_system_prefixes()
            .into_iter()
            .any(|prefix| normalized == prefix || normalized.starts_with(&(prefix + "\\")))
    }

    pub(in crate::runtime::engine) fn ensure_parent_directory(
        path: &std::path::Path,
    ) -> Result<(), VmError> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        std::fs::create_dir_all(parent).map_err(|source| VmError::OutputIo {
            path: parent.to_path_buf(),
            source,
        })
    }

    // Seed a minimal set of executables under system directories to prevent
    // busy-wait loops when samples enumerate empty directories.
    pub(in crate::runtime::engine) fn ensure_virtual_console_executable(
        &self,
        path: &std::path::Path,
    ) -> Result<(), VmError> {
        if path.exists() {
            return Ok(());
        }
        Self::ensure_parent_directory(path)?;
        std::fs::write(path, Self::build_minimal_console_pe32()).map_err(|source| {
            VmError::OutputIo {
                path: path.to_path_buf(),
                source,
            }
        })
    }

    pub(in crate::runtime::engine) fn seed_virtual_windows_system_directory(
        &self,
        directory: &std::path::Path,
    ) -> Result<(), VmError> {
        const SYSTEM_EXECUTABLES: &[&str] = &[
            "cmd.exe",
            "notepad.exe",
            "tasklist.exe",
            "findstr.exe",
            "where.exe",
            "ping.exe",
        ];

        std::fs::create_dir_all(directory).map_err(|source| VmError::OutputIo {
            path: directory.to_path_buf(),
            source,
        })?;
        for name in SYSTEM_EXECUTABLES {
            self.ensure_virtual_console_executable(&directory.join(name))?;
        }
        Ok(())
    }

    pub(in crate::runtime::engine) fn build_minimal_console_pe32() -> Vec<u8> {
        let mut image = vec![0u8; 0x400];
        image[0] = b'M';
        image[1] = b'Z';
        image[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        let pe_offset = 0x80usize;
        image[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        image[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes());
        image[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());

        let optional = coff + 20;
        image[optional..optional + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        image[optional + 4..optional + 8].copy_from_slice(&0x200u32.to_le_bytes());
        image[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        image[optional + 20..optional + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        image[optional + 24..optional + 28].copy_from_slice(&0x2000u32.to_le_bytes());
        image[optional + 28..optional + 32].copy_from_slice(&0x400000u32.to_le_bytes());
        image[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        image[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        image[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        image[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        image[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        image[optional + 92..optional + 96].copy_from_slice(&16u32.to_le_bytes());

        let section = optional + 0xE0;
        image[section..section + 8].copy_from_slice(b".text\0\0\0");
        image[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes());
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        image[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        image[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        image[0x200] = 0xC3;
        image
    }

    /// Windows is case-insensitive: if `path` doesn't exist exactly, try to
    /// find it with case-insensitive matching in the parent directory.
    fn resolve_case_insensitive(path: &std::path::Path) -> Option<std::path::PathBuf> {
        let parent = path.parent()?;
        let file_name = path.file_name()?.to_str()?;
        let file_name_lower = file_name.to_ascii_lowercase();
        let entries = std::fs::read_dir(parent).ok()?;
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_str()
                .map(|s| s.to_ascii_lowercase() == file_name_lower)
                .unwrap_or(false)
            {
                return Some(entry.path());
            }
        }
        None
    }
}
