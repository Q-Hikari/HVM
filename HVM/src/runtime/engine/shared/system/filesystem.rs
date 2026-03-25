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
        if let Some(rule) = self
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

        let Some(target) = self.prepare_runtime_read_target(normalized, "CreateFile")? else {
            return Ok(self.invalid_handle_value_for_arch());
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
        self.file_handles.insert(
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
        self.device_handles.insert(
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
        let handle = self.next_file_handle;
        self.next_file_handle = self.next_file_handle.saturating_add(4);
        handle
    }

    pub(in crate::runtime::engine) fn allocate_object_handle(&mut self) -> u32 {
        let handle = self.next_object_handle;
        self.next_object_handle = self.next_object_handle.saturating_add(4);
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
        let state = self.device_handles.get_mut(&handle)?;
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
        self.device_handles
            .get(&handle)
            .and_then(|state| state.physical_drive_index.map(|_| 1))
    }

    pub(in crate::runtime::engine) fn write_device_handle(
        &mut self,
        handle: u32,
        data: &[u8],
    ) -> Result<Option<usize>, VmError> {
        let Some((path, offset, physical_drive_index)) = ({
            let state = self.device_handles.get_mut(&handle);
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
        let Some(device) = self.device_handles.get(&handle).cloned() else {
            return Ok(None);
        };
        if device
            .physical_drive_index
            .is_some_and(|index| self.synthetic_physical_drive_exists(index))
            && code == 0x0007_00A0
        {
            let out_buffer = arg(args, 4);
            let out_length = arg(args, 5) as usize;
            let bytes_returned_ptr = arg(args, 6);
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
            self.modules.memory_mut().write(out_buffer, &payload)?;
            if bytes_returned_ptr != 0 {
                self.write_u32(bytes_returned_ptr, GEOMETRY_EX_LEN as u32)?;
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
        self.modules
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
        let configured = self.config.sandbox_output_dir.clone();
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
        for volume in &self.mounted_volumes {
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
                mapped.push(component);
            }
            return Some(mapped);
        }
        None
    }

    pub(in crate::runtime::engine) fn resolve_absolute_runtime_path(
        &self,
        raw: &str,
    ) -> Option<std::path::PathBuf> {
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

    pub(in crate::runtime::engine) fn runtime_path_is_volume_backed(
        &self,
        path: &std::path::Path,
    ) -> Result<bool, VmError> {
        let normalized_path = Self::normalize_host_policy_path(path)?;
        for volume in &self.mounted_volumes {
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
        self.current_directory_host
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

        for blocked_path in &self.config.blocked_read_dirs {
            let blocked_path = Self::normalize_host_policy_path(blocked_path)?;
            if Self::path_is_within(&blocked_path, &normalized_path) {
                return Ok(Some("blocked_read_dirs"));
            }
        }

        if self.config.allowed_read_dirs.is_empty() {
            return Ok(None);
        }

        for allowed_path in &self.config.allowed_read_dirs {
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
        for blocked_path in &self.config.blocked_read_dirs {
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

    // 为系统目录补一组最小的可执行文件，避免样本因枚举空目录而一直忙等。
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
        self.modules.memory_mut().write(buffer, &payload)?;
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
        self.find_handles
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
        let Some(state) = self.find_handles.get_mut(&handle) else {
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
        if self.find_handles.remove(&handle).is_some() {
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
            self.current_directory_host.join(candidate)
        }
    }

    pub(in crate::runtime::engine) fn system_directory_path(&self) -> String {
        if !self.environment_profile.machine.system32.is_empty() {
            return self.environment_profile.machine.system32.clone();
        }
        self.config
            .module_search_paths
            .iter()
            .find(|path| {
                path.exists()
                    && path
                        .file_name()
                        .map(|name| {
                            matches!(
                                name.to_string_lossy().to_ascii_lowercase().as_str(),
                                "system32" | "syswow64"
                            )
                        })
                        .unwrap_or(false)
            })
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|| r"C:\Windows\System32".to_string())
    }

    pub(in crate::runtime::engine) fn build_process_dll_path(&self) -> String {
        let mut paths = Vec::new();
        let system_directory = self.system_directory_path();
        if !system_directory.is_empty() {
            paths.push(system_directory);
        }
        for path in &self.config.module_search_paths {
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
        if !self.environment_profile.machine.system_root.is_empty() {
            return self.environment_profile.machine.system_root.clone();
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
        if !self.environment_profile.machine.temp_dir.is_empty() {
            self.environment_profile.machine.temp_dir.clone()
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
        for volume in &self.mounted_volumes {
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
        self.volume_find_handles
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
        let Some(state) = self.volume_find_handles.get_mut(&handle) else {
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
        if self.volume_find_handles.remove(&handle).is_some() {
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
        self.modules.memory_mut().write(info_ptr, &payload)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    pub(in crate::runtime::engine) fn set_end_of_file(
        &mut self,
        handle: u32,
    ) -> Result<u64, VmError> {
        let Some(state) = self.file_handles.get_mut(&handle) else {
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
}
