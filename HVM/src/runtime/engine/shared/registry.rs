use super::*;
use crate::config::{InterceptionAction, InterceptionValue};

const RRF_RT_REG_NONE: u32 = 0x0000_0001;
const RRF_RT_REG_SZ: u32 = 0x0000_0002;
const RRF_RT_REG_EXPAND_SZ: u32 = 0x0000_0004;
const RRF_RT_REG_BINARY: u32 = 0x0000_0008;
const RRF_RT_REG_DWORD: u32 = 0x0000_0010;
const RRF_RT_REG_MULTI_SZ: u32 = 0x0000_0020;
const RRF_RT_REG_QWORD: u32 = 0x0000_0040;
const RRF_RT_DWORD: u32 = RRF_RT_REG_BINARY | RRF_RT_REG_DWORD;
const RRF_RT_QWORD: u32 = RRF_RT_REG_BINARY | RRF_RT_REG_QWORD;
const RRF_RT_ANY: u32 = 0x0000_FFFF;
const RRF_ZEROONFAILURE: u32 = 0x2000_0000;

impl VirtualExecutionEngine {
    fn registry_value_type_name(value_type: u32) -> &'static str {
        match value_type {
            0 => "REG_NONE",
            1 => "REG_SZ",
            2 => "REG_EXPAND_SZ",
            3 => "REG_BINARY",
            4 => "REG_DWORD",
            5 => "REG_DWORD_BIG_ENDIAN",
            6 => "REG_LINK",
            7 => "REG_MULTI_SZ",
            8 => "REG_RESOURCE_LIST",
            9 => "REG_FULL_RESOURCE_DESCRIPTOR",
            10 => "REG_RESOURCE_REQUIREMENTS_LIST",
            11 => "REG_QWORD",
            _ => "REG_UNKNOWN",
        }
    }

    fn log_registry_key_event(
        &mut self,
        marker: &str,
        path: &str,
        handle: Option<u32>,
        created: Option<bool>,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("path".to_string(), json!(path));
        if let Some(handle) = handle {
            fields.insert("handle".to_string(), json!(handle));
        }
        if let Some(created) = created {
            fields.insert("created".to_string(), json!(created));
        }
        self.log_runtime_event(marker, fields)
    }

    fn log_registry_value_event(
        &mut self,
        marker: &str,
        path: &str,
        value_name: &str,
        value_type: Option<u32>,
        data_len: Option<usize>,
        data: Option<&[u8]>,
    ) -> Result<(), VmError> {
        let mut fields = Map::new();
        fields.insert("path".to_string(), json!(path));
        fields.insert("value_name".to_string(), json!(value_name));
        if let Some(value_type) = value_type {
            fields.insert("value_type".to_string(), json!(value_type));
            fields.insert(
                "value_type_name".to_string(),
                json!(Self::registry_value_type_name(value_type)),
            );
        }
        if let Some(data_len) = data_len {
            fields.insert("data_len".to_string(), json!(data_len));
        }
        if let Some(data) = data {
            Self::add_payload_preview_field(&mut fields, data);
        }
        self.log_runtime_event(marker, fields)
    }

    pub(in crate::runtime::engine) fn reg_open_key(
        &mut self,
        root_handle: u32,
        subkey: String,
        out_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        if let Some(full_path) = self
            .core
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey)
        {
            // Interception rules take highest priority.
            let interception_action = self
                .core
                .config
                .interception_rule_for_registry(&full_path, None)
                .map(|rule| rule.action.clone());
            if let Some(action) = interception_action {
                match &action {
                    InterceptionAction::NotFound => {
                        if out_handle_ptr != 0 {
                            self.write_u32(out_handle_ptr, 0)?;
                        }
                        self.log_interception(
                            "registry_key",
                            "RegOpenKey",
                            &full_path,
                            "not_found",
                        )?;
                        return Ok(ERROR_FILE_NOT_FOUND);
                    }
                    InterceptionAction::AccessDenied => {
                        if out_handle_ptr != 0 {
                            self.write_u32(out_handle_ptr, 0)?;
                        }
                        self.log_interception(
                            "registry_key",
                            "RegOpenKey",
                            &full_path,
                            "access_denied",
                        )?;
                        return Ok(ERROR_ACCESS_DENIED);
                    }
                    InterceptionAction::ErrorCode(code) => {
                        if out_handle_ptr != 0 {
                            self.write_u32(out_handle_ptr, 0)?;
                        }
                        self.log_interception(
                            "registry_key",
                            "RegOpenKey",
                            &full_path,
                            &format!("error_{code}"),
                        )?;
                        return Ok(*code as u64);
                    }
                    InterceptionAction::ReturnData(_) => {
                        // ReturnData on key open means: allow the open to proceed normally
                        // so the key handle is valid; the fake data is returned on query.
                        // Fall through to normal handling below.
                    }
                }
            }
            if let Some(rule) = self
                .core
                .config
                .hidden_registry_rule_for(&full_path, &subkey)
                .map(str::to_string)
            {
                if out_handle_ptr != 0 {
                    self.write_u32(out_handle_ptr, 0)?;
                }
                self.log_artifact_hide("registry_key", "RegOpenKey", &full_path, &rule)?;
                return Ok(ERROR_FILE_NOT_FOUND);
            }
        }
        let handle = self.core.registry.open_key(root_handle, &subkey, false);
        if out_handle_ptr != 0 {
            self.write_u32(out_handle_ptr, handle.unwrap_or(0))?;
        }
        if let Some(handle) = handle {
            if let Some(full_path) = self
                .core
                .registry
                .full_path_for_handle_and_subkey(root_handle, &subkey)
            {
                self.log_registry_key_event("REG_OPEN_KEY", &full_path, Some(handle), None)?;
                self.record_registry_operation("open", &full_path, None, None);
            }
            Ok(ERROR_SUCCESS)
        } else {
            Ok(ERROR_FILE_NOT_FOUND)
        }
    }

    pub(in crate::runtime::engine) fn reg_create_key(
        &mut self,
        root_handle: u32,
        subkey: String,
        out_handle_ptr: u64,
        disposition_ptr: u64,
    ) -> Result<u64, VmError> {
        let (handle, created) = self.core.registry.create_key(root_handle, &subkey);
        let Some(handle) = handle else {
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        if out_handle_ptr != 0 {
            self.write_u32(out_handle_ptr, handle)?;
        }
        if disposition_ptr != 0 {
            self.write_u32(disposition_ptr, if created { 1 } else { 2 })?;
        }
        if let Some(full_path) = self
            .core
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey)
        {
            self.log_registry_key_event("REG_CREATE_KEY", &full_path, Some(handle), Some(created))?;
            self.record_registry_operation("create", &full_path, None, None);
        }
        Ok(ERROR_SUCCESS)
    }

    pub(in crate::runtime::engine) fn reg_create_key_simple(
        &mut self,
        root_handle: u32,
        subkey: String,
        out_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        let (handle, _) = self.core.registry.create_key(root_handle, &subkey);
        let Some(handle) = handle else {
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        if out_handle_ptr != 0 {
            self.write_u32(out_handle_ptr, handle)?;
        }
        if let Some(full_path) = self
            .core
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey)
        {
            self.log_registry_key_event("REG_CREATE_KEY", &full_path, Some(handle), None)?;
        }
        Ok(ERROR_SUCCESS)
    }

    pub(in crate::runtime::engine) fn reg_query_value(
        &mut self,
        handle: u32,
        value_name: String,
        wide: bool,
        type_ptr: u64,
        data_ptr: u64,
        size_ptr: u64,
    ) -> Result<u64, VmError> {
        // Check interception rules for this value query.
        if let Some(path) = self.core.registry.full_path_for_handle(handle) {
            if let Some(rule) = self
                .core
                .config
                .interception_rule_for_registry(&path, Some(&value_name))
                .cloned()
            {
                match &rule.action {
                    InterceptionAction::NotFound => {
                        self.log_interception(
                            "registry_value",
                            "RegQueryValue",
                            &path,
                            "not_found",
                        )?;
                        return Ok(ERROR_FILE_NOT_FOUND);
                    }
                    InterceptionAction::AccessDenied => {
                        self.log_interception(
                            "registry_value",
                            "RegQueryValue",
                            &path,
                            "access_denied",
                        )?;
                        return Ok(ERROR_ACCESS_DENIED);
                    }
                    InterceptionAction::ErrorCode(code) => {
                        self.log_interception(
                            "registry_value",
                            "RegQueryValue",
                            &path,
                            &format!("error_{code}"),
                        )?;
                        return Ok(*code as u64);
                    }
                    InterceptionAction::ReturnData(interception_value) => {
                        let (value_type, data) =
                            self.interception_value_to_registry_data(interception_value, wide);
                        self.log_interception(
                            "registry_value",
                            "RegQueryValue",
                            &path,
                            "return_data",
                        )?;
                        return self
                            .write_registry_value(value_type, &data, type_ptr, data_ptr, size_ptr);
                    }
                }
            }
        }
        let Some(value) = self.core.registry.query_value(handle, &value_name).cloned() else {
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        let data = self.registry_query_payload(&value, wide);
        if let Some(path) = self.core.registry.full_path_for_handle(handle) {
            self.log_registry_value_event(
                "REG_QUERY_VALUE",
                &path,
                &value_name,
                Some(value.value_type),
                Some(data.len()),
                None,
            )?;
            self.record_registry_operation("query", &path, Some(&value_name), None);
        }
        self.write_registry_value(value.value_type, &data, type_ptr, data_ptr, size_ptr)
    }

    pub(in crate::runtime::engine) fn sh_get_value(
        &mut self,
        root_handle: u32,
        subkey: String,
        value_name: String,
        wide: bool,
        type_ptr: u64,
        data_ptr: u64,
        size_ptr: u64,
    ) -> Result<u64, VmError> {
        self.registry_get_value_common(
            root_handle,
            subkey,
            value_name,
            wide,
            None,
            type_ptr,
            data_ptr,
            size_ptr,
            "SHGetValue",
        )
    }

    pub(in crate::runtime::engine) fn reg_get_value(
        &mut self,
        root_handle: u32,
        subkey: String,
        value_name: String,
        wide: bool,
        flags: u32,
        type_ptr: u64,
        data_ptr: u64,
        size_ptr: u64,
    ) -> Result<u64, VmError> {
        self.registry_get_value_common(
            root_handle,
            subkey,
            value_name,
            wide,
            Some(flags),
            type_ptr,
            data_ptr,
            size_ptr,
            "RegGetValue",
        )
    }

    fn registry_get_value_common(
        &mut self,
        root_handle: u32,
        subkey: String,
        value_name: String,
        wide: bool,
        flags: Option<u32>,
        type_ptr: u64,
        data_ptr: u64,
        size_ptr: u64,
        operation: &str,
    ) -> Result<u64, VmError> {
        if let Some(full_path) = self
            .core
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey)
        {
            // Interception rules take highest priority.
            if let Some(rule) = self
                .core
                .config
                .interception_rule_for_registry(&full_path, Some(&value_name))
                .cloned()
            {
                match &rule.action {
                    InterceptionAction::NotFound => {
                        self.log_interception(
                            "registry_value",
                            operation,
                            &full_path,
                            "not_found",
                        )?;
                        self.zero_registry_output_buffer(data_ptr, size_ptr, flags)?;
                        return Ok(ERROR_FILE_NOT_FOUND);
                    }
                    InterceptionAction::AccessDenied => {
                        self.log_interception(
                            "registry_value",
                            operation,
                            &full_path,
                            "access_denied",
                        )?;
                        self.zero_registry_output_buffer(data_ptr, size_ptr, flags)?;
                        return Ok(ERROR_ACCESS_DENIED);
                    }
                    InterceptionAction::ErrorCode(code) => {
                        self.log_interception(
                            "registry_value",
                            operation,
                            &full_path,
                            &format!("error_{code}"),
                        )?;
                        self.zero_registry_output_buffer(data_ptr, size_ptr, flags)?;
                        return Ok(*code as u64);
                    }
                    InterceptionAction::ReturnData(interception_value) => {
                        let (value_type, data) =
                            self.interception_value_to_registry_data(interception_value, wide);
                        if let Some(flag_bits) = flags {
                            if !Self::registry_type_matches_flags(value_type, flag_bits) {
                                self.log_interception(
                                    "registry_value",
                                    operation,
                                    &full_path,
                                    "unsupported_type",
                                )?;
                                self.zero_registry_output_buffer(data_ptr, size_ptr, flags)?;
                                return Ok(ERROR_UNSUPPORTED_TYPE);
                            }
                        }
                        self.log_interception(
                            "registry_value",
                            operation,
                            &full_path,
                            "return_data",
                        )?;
                        let status = self.write_registry_value(
                            value_type, &data, type_ptr, data_ptr, size_ptr,
                        )?;
                        if status != ERROR_SUCCESS {
                            self.zero_registry_output_buffer(data_ptr, size_ptr, flags)?;
                        }
                        return Ok(status);
                    }
                }
            }
            if let Some(rule) = self
                .core
                .config
                .hidden_registry_rule_for(&full_path, &subkey)
                .map(str::to_string)
            {
                self.log_artifact_hide("registry_key", operation, &full_path, &rule)?;
                self.zero_registry_output_buffer(data_ptr, size_ptr, flags)?;
                return Ok(ERROR_FILE_NOT_FOUND);
            }
        }
        let Some(handle) = self.core.registry.open_key(root_handle, &subkey, false) else {
            self.zero_registry_output_buffer(data_ptr, size_ptr, flags)?;
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        let value = self.core.registry.query_value(handle, &value_name).cloned();
        let _ = self.core.registry.close(handle);
        let Some(value) = value else {
            self.zero_registry_output_buffer(data_ptr, size_ptr, flags)?;
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        if let Some(flag_bits) = flags {
            if !Self::registry_type_matches_flags(value.value_type, flag_bits) {
                self.zero_registry_output_buffer(data_ptr, size_ptr, flags)?;
                return Ok(ERROR_UNSUPPORTED_TYPE);
            }
        }
        let data = self.registry_query_payload(&value, wide);
        if let Some(full_path) = self
            .core
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey)
        {
            self.log_registry_value_event(
                "REG_QUERY_VALUE",
                &full_path,
                &value_name,
                Some(value.value_type),
                Some(data.len()),
                None,
            )?;
        }
        let status =
            self.write_registry_value(value.value_type, &data, type_ptr, data_ptr, size_ptr)?;
        if status != ERROR_SUCCESS {
            self.zero_registry_output_buffer(data_ptr, size_ptr, flags)?;
        }
        Ok(status)
    }

    pub(in crate::runtime::engine) fn sh_set_value(
        &mut self,
        root_handle: u32,
        subkey: String,
        value_name: String,
        value_type: u32,
        data_ptr: u64,
        data_len: u64,
    ) -> Result<u64, VmError> {
        let (handle, _) = self.core.registry.create_key(root_handle, &subkey);
        let Some(handle) = handle else {
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        let data = if data_ptr != 0 && data_len != 0 {
            self.read_bytes_from_memory(data_ptr, data_len as usize)?
        } else {
            Vec::new()
        };
        let success = self
            .core
            .registry
            .set_value(handle, &value_name, value_type, &data);
        let _ = self.core.registry.close(handle);
        if success {
            if let Some(full_path) = self
                .core
                .registry
                .full_path_for_handle_and_subkey(root_handle, &subkey)
            {
                self.log_registry_value_event(
                    "REG_SET_VALUE",
                    &full_path,
                    &value_name,
                    Some(value_type),
                    Some(data.len()),
                    Some(&data),
                )?;
            }
            Ok(ERROR_SUCCESS)
        } else {
            Ok(ERROR_FILE_NOT_FOUND)
        }
    }

    pub(in crate::runtime::engine) fn reg_set_value(
        &mut self,
        handle: u32,
        value_name: String,
        value_type: u32,
        data: Vec<u8>,
    ) -> Result<u64, VmError> {
        let path = self.core.registry.full_path_for_handle(handle);
        if self
            .core
            .registry
            .set_value(handle, &value_name, value_type, &data)
        {
            if let Some(path) = path {
                self.log_registry_value_event(
                    "REG_SET_VALUE",
                    &path,
                    &value_name,
                    Some(value_type),
                    Some(data.len()),
                    Some(&data),
                )?;
            }
            Ok(ERROR_SUCCESS)
        } else {
            Ok(ERROR_FILE_NOT_FOUND)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::runtime::engine) fn reg_enum_value(
        &mut self,
        handle: u32,
        index: u32,
        wide: bool,
        value_name_ptr: u64,
        value_name_len_ptr: u64,
        type_ptr: u64,
        data_ptr: u64,
        data_len_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(value) = self.core.registry.enum_value(handle, index).cloned() else {
            return Ok(ERROR_NO_MORE_ITEMS);
        };

        let required_name_len = if wide {
            value.name.encode_utf16().count() as u32
        } else {
            value.name.len() as u32
        };
        let data = self.registry_query_payload(&value, wide);
        let required_data_len = data.len() as u32;

        if value_name_len_ptr != 0 {
            let available_name_len = self.read_u32(value_name_len_ptr)?;
            self.write_u32(value_name_len_ptr, required_name_len)?;
            if available_name_len != 0 && available_name_len <= required_name_len {
                return Ok(ERROR_MORE_DATA);
            }
        }
        if data_len_ptr != 0 {
            let available_data_len = self.read_u32(data_len_ptr)?;
            self.write_u32(data_len_ptr, required_data_len)?;
            if data_ptr != 0 && available_data_len < required_data_len {
                return Ok(ERROR_MORE_DATA);
            }
        }

        if type_ptr != 0 {
            self.write_u32(type_ptr, value.value_type)?;
        }
        if value_name_ptr != 0 {
            if wide {
                let _ = self.write_wide_string_to_memory(
                    value_name_ptr,
                    required_name_len as usize + 1,
                    &value.name,
                )?;
            } else {
                let _ = self.write_c_string_to_memory(
                    value_name_ptr,
                    required_name_len as usize + 1,
                    &value.name,
                )?;
            }
        }
        if data_ptr != 0 && required_data_len != 0 {
            self.core.modules.memory_mut().write(data_ptr, &data)?;
        }

        if let Some(path) = self.core.registry.full_path_for_handle(handle) {
            self.log_registry_value_event(
                "REG_QUERY_VALUE",
                &path,
                &value.name,
                Some(value.value_type),
                Some(data.len()),
                None,
            )?;
        }
        Ok(ERROR_SUCCESS)
    }

    pub(in crate::runtime::engine) fn reg_delete_value(
        &mut self,
        handle: u32,
        value_name: String,
    ) -> Result<u64, VmError> {
        let path = self.core.registry.full_path_for_handle(handle);
        if self.core.registry.delete_value(handle, &value_name) {
            if let Some(path) = path {
                self.log_registry_value_event(
                    "REG_DELETE_VALUE",
                    &path,
                    &value_name,
                    None,
                    None,
                    None,
                )?;
            }
            Ok(ERROR_SUCCESS)
        } else {
            Ok(ERROR_FILE_NOT_FOUND)
        }
    }

    pub(in crate::runtime::engine) fn reg_delete_key(
        &mut self,
        root_handle: u32,
        subkey: String,
    ) -> Result<u64, VmError> {
        let full_path = self
            .core
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey);
        if self.core.registry.delete_key(root_handle, &subkey) {
            if let Some(full_path) = full_path {
                self.log_registry_key_event("REG_DELETE_KEY", &full_path, None, None)?;
            }
            Ok(ERROR_SUCCESS)
        } else {
            Ok(ERROR_FILE_NOT_FOUND)
        }
    }

    fn registry_query_payload(
        &self,
        value: &crate::managers::registry_manager::RegistryValue,
        wide: bool,
    ) -> Vec<u8> {
        if wide {
            return value.data.clone();
        }
        match value.value_type {
            1 | 2 => self.registry_utf16_string_to_ansi_bytes(&value.data),
            7 => self.registry_utf16_multi_string_to_ansi_bytes(&value.data),
            _ => value.data.clone(),
        }
    }

    fn registry_utf16_units(bytes: &[u8]) -> Vec<u16> {
        bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect()
    }

    fn decode_registry_utf16_units(units: &[u16]) -> String {
        std::char::decode_utf16(units.iter().copied())
            .filter_map(Result::ok)
            .collect()
    }

    fn registry_utf16_string_to_ansi_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let mut units = Self::registry_utf16_units(bytes);
        while matches!(units.last(), Some(0)) {
            let _ = units.pop();
        }
        let text = Self::decode_registry_utf16_units(&units);
        let mut encoded = self.encode_code_page_string(0, &text);
        encoded.push(0);
        encoded
    }

    fn registry_utf16_multi_string_to_ansi_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let units = Self::registry_utf16_units(bytes);
        let mut strings = Vec::new();
        let mut start = 0usize;
        for (index, unit) in units.iter().enumerate() {
            if *unit == 0 {
                strings.push(Self::decode_registry_utf16_units(&units[start..index]));
                start = index + 1;
            }
        }
        if start < units.len() {
            strings.push(Self::decode_registry_utf16_units(&units[start..]));
        }

        let mut encoded = Vec::new();
        if strings.is_empty() {
            encoded.extend_from_slice(&[0, 0]);
            return encoded;
        }

        for text in strings {
            encoded.extend(self.encode_code_page_string(0, &text));
            encoded.push(0);
        }
        if encoded.len() == 1 || encoded[encoded.len() - 2] != 0 {
            encoded.push(0);
        }
        encoded
    }

    pub(in crate::runtime::engine) fn write_registry_value(
        &mut self,
        value_type: u32,
        data: &[u8],
        type_ptr: u64,
        data_ptr: u64,
        size_ptr: u64,
    ) -> Result<u64, VmError> {
        let data_len = data.len() as u32;
        let available = if size_ptr != 0 {
            let value = self.read_u32(size_ptr)?;
            self.write_u32(size_ptr, data_len)?;
            value
        } else {
            0
        };
        if data_ptr != 0 && size_ptr == 0 {
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if data_ptr != 0 && available < data_len {
            return Ok(ERROR_MORE_DATA);
        }
        if type_ptr != 0 {
            self.write_u32(type_ptr, value_type)?;
        }
        if data_ptr != 0 {
            self.core.modules.memory_mut().write(data_ptr, data)?;
        }
        Ok(ERROR_SUCCESS)
    }

    fn zero_registry_output_buffer(
        &mut self,
        data_ptr: u64,
        size_ptr: u64,
        flags: Option<u32>,
    ) -> Result<(), VmError> {
        if data_ptr == 0 {
            return Ok(());
        }
        let Some(flag_bits) = flags else {
            return Ok(());
        };
        if flag_bits & RRF_ZEROONFAILURE == 0 || size_ptr == 0 {
            return Ok(());
        }
        let available = self.read_u32(size_ptr)? as usize;
        if available == 0 {
            return Ok(());
        }
        self.core
            .modules
            .memory_mut()
            .write(data_ptr, &vec![0u8; available])?;
        Ok(())
    }

    fn registry_type_matches_flags(value_type: u32, flags: u32) -> bool {
        let type_mask = flags & RRF_RT_ANY;
        if type_mask == 0 || type_mask == RRF_RT_ANY {
            return true;
        }
        match value_type {
            0 => type_mask & RRF_RT_REG_NONE != 0,
            1 => type_mask & RRF_RT_REG_SZ != 0,
            2 => type_mask & RRF_RT_REG_EXPAND_SZ != 0 || type_mask & RRF_RT_REG_SZ != 0,
            3 => {
                type_mask & RRF_RT_REG_BINARY != 0
                    || type_mask & RRF_RT_DWORD != 0
                    || type_mask & RRF_RT_QWORD != 0
            }
            4 => type_mask & RRF_RT_REG_DWORD != 0 || type_mask & RRF_RT_DWORD == RRF_RT_DWORD,
            7 => type_mask & RRF_RT_REG_MULTI_SZ != 0,
            11 => type_mask & RRF_RT_REG_QWORD != 0 || type_mask & RRF_RT_QWORD == RRF_RT_QWORD,
            _ => false,
        }
    }

    /// Converts an `InterceptionValue` to `(value_type, data)` for registry writes.
    fn interception_value_to_registry_data(
        &self,
        value: &InterceptionValue,
        wide: bool,
    ) -> (u32, Vec<u8>) {
        match value {
            InterceptionValue::String(text) => {
                if wide {
                    (1u32, wide_string_with_null(text))
                } else {
                    let mut bytes = self.encode_code_page_string(0, text);
                    bytes.push(0);
                    (1u32, bytes)
                }
            }
            InterceptionValue::Dword(dword) => (4u32, dword.to_le_bytes().to_vec()),
            InterceptionValue::Qword(qword) => (11u32, qword.to_le_bytes().to_vec()),
            InterceptionValue::Bytes(data) => (3u32, data.clone()),
        }
    }
}

fn wide_string_with_null(value: &str) -> Vec<u8> {
    let mut bytes = value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    bytes.extend_from_slice(&[0, 0]);
    bytes
}
