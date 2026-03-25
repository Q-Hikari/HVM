use super::*;

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
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey)
        {
            if let Some(rule) = self
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
        let handle = self.registry.open_key(root_handle, &subkey, false);
        if out_handle_ptr != 0 {
            self.write_u32(out_handle_ptr, handle.unwrap_or(0))?;
        }
        if let Some(handle) = handle {
            if let Some(full_path) = self
                .registry
                .full_path_for_handle_and_subkey(root_handle, &subkey)
            {
                self.log_registry_key_event("REG_OPEN_KEY", &full_path, Some(handle), None)?;
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
        let (handle, created) = self.registry.create_key(root_handle, &subkey);
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
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey)
        {
            self.log_registry_key_event("REG_CREATE_KEY", &full_path, Some(handle), Some(created))?;
        }
        Ok(ERROR_SUCCESS)
    }

    pub(in crate::runtime::engine) fn reg_create_key_simple(
        &mut self,
        root_handle: u32,
        subkey: String,
        out_handle_ptr: u64,
    ) -> Result<u64, VmError> {
        let (handle, _) = self.registry.create_key(root_handle, &subkey);
        let Some(handle) = handle else {
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        if out_handle_ptr != 0 {
            self.write_u32(out_handle_ptr, handle)?;
        }
        if let Some(full_path) = self
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
        type_ptr: u64,
        data_ptr: u64,
        size_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(value) = self.registry.query_value(handle, &value_name).cloned() else {
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        if let Some(path) = self.registry.full_path_for_handle(handle) {
            self.log_registry_value_event(
                "REG_QUERY_VALUE",
                &path,
                &value_name,
                Some(value.value_type),
                Some(value.data.len()),
                None,
            )?;
        }
        self.write_registry_value(&value, type_ptr, data_ptr, size_ptr)
    }

    pub(in crate::runtime::engine) fn sh_get_value(
        &mut self,
        root_handle: u32,
        subkey: String,
        value_name: String,
        type_ptr: u64,
        data_ptr: u64,
        size_ptr: u64,
    ) -> Result<u64, VmError> {
        if let Some(full_path) = self
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey)
        {
            if let Some(rule) = self
                .config
                .hidden_registry_rule_for(&full_path, &subkey)
                .map(str::to_string)
            {
                self.log_artifact_hide("registry_key", "RegGetValue", &full_path, &rule)?;
                return Ok(ERROR_FILE_NOT_FOUND);
            }
        }
        let Some(handle) = self.registry.open_key(root_handle, &subkey, false) else {
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        let value = self.registry.query_value(handle, &value_name).cloned();
        let _ = self.registry.close(handle);
        let Some(value) = value else {
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        if let Some(full_path) = self
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey)
        {
            self.log_registry_value_event(
                "REG_QUERY_VALUE",
                &full_path,
                &value_name,
                Some(value.value_type),
                Some(value.data.len()),
                None,
            )?;
        }
        self.write_registry_value(&value, type_ptr, data_ptr, size_ptr)
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
        let (handle, _) = self.registry.create_key(root_handle, &subkey);
        let Some(handle) = handle else {
            return Ok(ERROR_FILE_NOT_FOUND);
        };
        let data = if data_ptr != 0 && data_len != 0 {
            self.read_bytes_from_memory(data_ptr, data_len as usize)?
        } else {
            Vec::new()
        };
        let success = self
            .registry
            .set_value(handle, &value_name, value_type, &data);
        let _ = self.registry.close(handle);
        if success {
            if let Some(full_path) = self
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
        let path = self.registry.full_path_for_handle(handle);
        if self
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

    pub(in crate::runtime::engine) fn reg_delete_value(
        &mut self,
        handle: u32,
        value_name: String,
    ) -> Result<u64, VmError> {
        let path = self.registry.full_path_for_handle(handle);
        if self.registry.delete_value(handle, &value_name) {
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
            .registry
            .full_path_for_handle_and_subkey(root_handle, &subkey);
        if self.registry.delete_key(root_handle, &subkey) {
            if let Some(full_path) = full_path {
                self.log_registry_key_event("REG_DELETE_KEY", &full_path, None, None)?;
            }
            Ok(ERROR_SUCCESS)
        } else {
            Ok(ERROR_FILE_NOT_FOUND)
        }
    }

    pub(in crate::runtime::engine) fn write_registry_value(
        &mut self,
        value: &crate::managers::registry_manager::RegistryValue,
        type_ptr: u64,
        data_ptr: u64,
        size_ptr: u64,
    ) -> Result<u64, VmError> {
        let data_len = value.data.len() as u32;
        let mut available = 0;
        if size_ptr != 0 {
            available = self.read_u32(size_ptr)?;
            self.write_u32(size_ptr, data_len)?;
        }
        if type_ptr != 0 {
            self.write_u32(type_ptr, value.value_type)?;
        }
        if data_ptr != 0 {
            if available != 0 && available < data_len {
                return Ok(ERROR_MORE_DATA);
            }
            self.modules.memory_mut().write(data_ptr, &value.data)?;
        }
        Ok(ERROR_SUCCESS)
    }
}
