use super::*;

const CR_SUCCESS: u64 = 0;
const CR_NO_SUCH_DEVINST: u64 = 0x0000_000D;
const CR_BUFFER_SMALL: u64 = 0x0000_001A;
const CR_INVALID_POINTER: u64 = 0x0000_001C;
const CM_DRP_DEVICEDESC: u32 = 1;
const CM_DRP_HARDWAREID: u32 = 2;
const CM_DRP_COMPATIBLEIDS: u32 = 3;
const CM_DRP_SERVICE: u32 = 5;
const CM_DRP_CLASS: u32 = 8;
const CM_DRP_CLASSGUID: u32 = 9;
const CM_DRP_CONFIGFLAGS: u32 = 0x0B;
const CM_DRP_MFG: u32 = 0x0D;
const CM_DRP_FRIENDLYNAME: u32 = 0x0E;
const CM_DRP_LOCATION_INFORMATION: u32 = 0x0F;
const CM_DRP_CAPABILITIES: u32 = 0x12;
const CM_DRP_ENUMERATOR_NAME: u32 = 0x16;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_cfgmgr32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("cfgmgr32.dll", "CM_Locate_DevNodeA") => true,
            ("cfgmgr32.dll", "CM_Locate_DevNodeW") => true,
            ("cfgmgr32.dll", "CM_Get_Device_IDA") => true,
            ("cfgmgr32.dll", "CM_Get_Device_IDW") => true,
            ("cfgmgr32.dll", "CM_Get_Device_ID_Size") => true,
            ("cfgmgr32.dll", "CM_Get_Parent") => true,
            ("cfgmgr32.dll", "CM_Get_Child") => true,
            ("cfgmgr32.dll", "CM_Get_Sibling") => true,
            ("cfgmgr32.dll", "CM_Get_DevNode_Status") => true,
            ("cfgmgr32.dll", "CM_Get_DevNode_Registry_PropertyA") => true,
            ("cfgmgr32.dll", "CM_Get_DevNode_Registry_PropertyW") => true,
            ("cfgmgr32.dll", "CM_MapCrToWin32Err") => true,
            ("cfgmgr32.dll", "CM_Get_Device_ID_List_SizeA") => true,
            ("cfgmgr32.dll", "CM_Get_Device_ID_List_SizeW") => true,
            ("cfgmgr32.dll", "CM_Get_Device_ID_ListA") => true,
            ("cfgmgr32.dll", "CM_Get_Device_ID_ListW") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("cfgmgr32.dll", "CM_Locate_DevNodeA") => self.cm_locate_devnode(
                    arg(args, 0),
                    &self.read_c_string_from_memory(arg(args, 1))?,
                ),
                ("cfgmgr32.dll", "CM_Locate_DevNodeW") => self.cm_locate_devnode(
                    arg(args, 0),
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                ),
                ("cfgmgr32.dll", "CM_Get_Device_IDA") => self.cm_get_device_id(
                    false,
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2) as usize,
                ),
                ("cfgmgr32.dll", "CM_Get_Device_IDW") => self.cm_get_device_id(
                    true,
                    arg(args, 0) as u32,
                    arg(args, 1),
                    arg(args, 2) as usize,
                ),
                ("cfgmgr32.dll", "CM_Get_Device_ID_Size") => {
                    self.cm_get_device_id_size(arg(args, 0), arg(args, 1) as u32)
                }
                ("cfgmgr32.dll", "CM_Get_Parent") => {
                    self.cm_get_parent(arg(args, 0), arg(args, 1) as u32)
                }
                ("cfgmgr32.dll", "CM_Get_Child") => {
                    self.cm_get_child(arg(args, 0), arg(args, 1) as u32)
                }
                ("cfgmgr32.dll", "CM_Get_Sibling") => {
                    self.cm_get_sibling(arg(args, 0), arg(args, 1) as u32)
                }
                ("cfgmgr32.dll", "CM_Get_DevNode_Status") => {
                    self.cm_get_devnode_status(arg(args, 0), arg(args, 1), arg(args, 2) as u32)
                }
                ("cfgmgr32.dll", "CM_Get_DevNode_Registry_PropertyA") => self
                    .cm_get_devnode_registry_property(
                        false,
                        arg(args, 0) as u32,
                        arg(args, 1) as u32,
                        arg(args, 2),
                        arg(args, 3),
                        arg(args, 4),
                    ),
                ("cfgmgr32.dll", "CM_Get_DevNode_Registry_PropertyW") => self
                    .cm_get_devnode_registry_property(
                        true,
                        arg(args, 0) as u32,
                        arg(args, 1) as u32,
                        arg(args, 2),
                        arg(args, 3),
                        arg(args, 4),
                    ),
                ("cfgmgr32.dll", "CM_MapCrToWin32Err") => {
                    Ok(self.cm_map_cr_to_win32_err(arg(args, 0), arg(args, 1)))
                }
                ("cfgmgr32.dll", "CM_Get_Device_ID_List_SizeA") => self.cm_get_device_id_list_size(
                    false,
                    arg(args, 0),
                    &self.read_c_string_from_memory(arg(args, 1))?,
                ),
                ("cfgmgr32.dll", "CM_Get_Device_ID_List_SizeW") => self.cm_get_device_id_list_size(
                    true,
                    arg(args, 0),
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                ),
                ("cfgmgr32.dll", "CM_Get_Device_ID_ListA") => self.cm_get_device_id_list(
                    false,
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2) as usize,
                ),
                ("cfgmgr32.dll", "CM_Get_Device_ID_ListW") => self.cm_get_device_id_list(
                    true,
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2) as usize,
                ),
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }

    fn cm_locate_devnode(&mut self, devinst_ptr: u64, instance_id: &str) -> Result<u64, VmError> {
        if devinst_ptr == 0 {
            return Ok(CR_INVALID_POINTER);
        }
        let device = if instance_id.trim().is_empty() {
            self.devices
                .list_devices("", "ROOT", false)
                .into_iter()
                .next()
        } else {
            self.devices.find_by_instance_id(instance_id).cloned()
        };
        let Some(device) = device else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        self.write_u32(devinst_ptr, device.devinst)?;
        Ok(CR_SUCCESS)
    }

    fn cm_get_device_id(
        &mut self,
        wide: bool,
        devinst: u32,
        buffer: u64,
        buffer_len: usize,
    ) -> Result<u64, VmError> {
        let Some(device) = self.devices.get(devinst).cloned() else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        let required = if wide {
            device.instance_id.encode_utf16().count() + 1
        } else {
            device.instance_id.len() + 1
        };
        if buffer == 0 || buffer_len < required {
            return Ok(CR_BUFFER_SMALL);
        }
        if wide {
            let _ = self.write_wide_string_to_memory(buffer, buffer_len, &device.instance_id)?;
        } else {
            let _ = self.write_c_string_to_memory(buffer, buffer_len, &device.instance_id)?;
        }
        Ok(CR_SUCCESS)
    }

    fn cm_get_device_id_size(&mut self, len_ptr: u64, devinst: u32) -> Result<u64, VmError> {
        if len_ptr == 0 {
            return Ok(CR_INVALID_POINTER);
        }
        let Some(device) = self.devices.get(devinst) else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        self.write_u32(
            len_ptr,
            device
                .instance_id
                .encode_utf16()
                .count()
                .min(u32::MAX as usize) as u32,
        )?;
        Ok(CR_SUCCESS)
    }

    fn cm_get_parent(&mut self, parent_ptr: u64, devinst: u32) -> Result<u64, VmError> {
        if parent_ptr == 0 {
            return Ok(CR_INVALID_POINTER);
        }
        let Some(device) = self.devices.get(devinst) else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        if device.parent == 0 {
            return Ok(CR_NO_SUCH_DEVINST);
        }
        self.write_u32(parent_ptr, device.parent)?;
        Ok(CR_SUCCESS)
    }

    fn cm_get_child(&mut self, child_ptr: u64, devinst: u32) -> Result<u64, VmError> {
        if child_ptr == 0 {
            return Ok(CR_INVALID_POINTER);
        }
        let Some(device) = self.devices.get(devinst) else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        let Some(&child) = device.children.first() else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        self.write_u32(child_ptr, child)?;
        Ok(CR_SUCCESS)
    }

    fn cm_get_sibling(&mut self, sibling_ptr: u64, devinst: u32) -> Result<u64, VmError> {
        if sibling_ptr == 0 {
            return Ok(CR_INVALID_POINTER);
        }
        let Some(device) = self.devices.get(devinst) else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        let Some(parent) = self.devices.get(device.parent) else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        let Some(index) = parent
            .children
            .iter()
            .position(|candidate| *candidate == devinst)
        else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        let Some(&sibling) = parent.children.get(index + 1) else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        self.write_u32(sibling_ptr, sibling)?;
        Ok(CR_SUCCESS)
    }

    fn cm_get_devnode_status(
        &mut self,
        status_ptr: u64,
        problem_ptr: u64,
        devinst: u32,
    ) -> Result<u64, VmError> {
        let Some(device) = self.devices.get(devinst) else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        let status = device.status;
        let problem = device.problem;
        if status_ptr != 0 {
            self.write_u32(status_ptr, status)?;
        }
        if problem_ptr != 0 {
            self.write_u32(problem_ptr, problem)?;
        }
        Ok(CR_SUCCESS)
    }

    fn cm_get_devnode_registry_property(
        &mut self,
        wide: bool,
        devinst: u32,
        property: u32,
        reg_type_ptr: u64,
        buffer: u64,
        buffer_size_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(device) = self.devices.get(devinst).cloned() else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        let Some(property_key) = cm_property_key(property) else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        let Some((value_type, data)) = self.devices.property_data(&device, property_key, wide)
        else {
            return Ok(CR_NO_SUCH_DEVINST);
        };
        let capacity = if buffer_size_ptr != 0 {
            self.read_u32(buffer_size_ptr).unwrap_or(0) as usize
        } else {
            0
        };
        if reg_type_ptr != 0 {
            self.write_u32(reg_type_ptr, value_type)?;
        }
        if buffer_size_ptr != 0 {
            self.write_u32(buffer_size_ptr, data.len().min(u32::MAX as usize) as u32)?;
        }
        if buffer == 0 || capacity < data.len() {
            return Ok(CR_BUFFER_SMALL);
        }
        self.modules.memory_mut().write(buffer, &data)?;
        Ok(CR_SUCCESS)
    }

    fn cm_map_cr_to_win32_err(&self, cr: u64, default_error: u64) -> u64 {
        match cr {
            CR_SUCCESS => ERROR_SUCCESS,
            CR_BUFFER_SMALL => ERROR_INSUFFICIENT_BUFFER,
            CR_NO_SUCH_DEVINST => default_error,
            _ => default_error,
        }
    }

    fn cm_get_device_id_list_size(
        &mut self,
        wide: bool,
        len_ptr: u64,
        filter: &str,
    ) -> Result<u64, VmError> {
        if len_ptr == 0 {
            return Ok(CR_INVALID_POINTER);
        }
        let (_, required_chars) = self.cm_device_id_list_payload(filter, wide);
        self.write_u32(len_ptr, required_chars.min(u32::MAX as usize) as u32)?;
        Ok(CR_SUCCESS)
    }

    fn cm_get_device_id_list(
        &mut self,
        wide: bool,
        filter: &str,
        buffer: u64,
        buffer_len: usize,
    ) -> Result<u64, VmError> {
        let (payload, required_chars) = self.cm_device_id_list_payload(filter, wide);
        if buffer == 0 || buffer_len < required_chars {
            return Ok(CR_BUFFER_SMALL);
        }
        self.modules.memory_mut().write(buffer, &payload)?;
        Ok(CR_SUCCESS)
    }

    fn cm_device_id_list_payload(&self, filter: &str, wide: bool) -> (Vec<u8>, usize) {
        let devices = filter_cm_devices(&self.devices, filter);
        if devices.is_empty() {
            if wide {
                return (vec![0, 0, 0, 0], 2);
            }
            return (vec![0, 0], 2);
        }
        if wide {
            let mut chars = 1usize;
            let mut bytes = Vec::new();
            for device in devices {
                chars += device.instance_id.encode_utf16().count() + 1;
                bytes.extend(device.instance_id.encode_utf16().flat_map(u16::to_le_bytes));
                bytes.extend_from_slice(&[0, 0]);
            }
            bytes.extend_from_slice(&[0, 0]);
            (bytes, chars)
        } else {
            let mut chars = 1usize;
            let mut bytes = Vec::new();
            for device in devices {
                chars += device.instance_id.len() + 1;
                bytes.extend(device.instance_id.as_bytes());
                bytes.push(0);
            }
            bytes.push(0);
            (bytes, chars)
        }
    }
}

fn cm_property_key(property: u32) -> Option<&'static str> {
    match property {
        CM_DRP_DEVICEDESC => Some("devicedesc"),
        CM_DRP_HARDWAREID => Some("hardwareid"),
        CM_DRP_COMPATIBLEIDS => Some("compatibleids"),
        CM_DRP_SERVICE => Some("service"),
        CM_DRP_CLASS => Some("class"),
        CM_DRP_CLASSGUID => Some("classguid"),
        CM_DRP_CONFIGFLAGS => Some("configflags"),
        CM_DRP_MFG => Some("mfg"),
        CM_DRP_FRIENDLYNAME => Some("friendlyname"),
        CM_DRP_LOCATION_INFORMATION => Some("location"),
        CM_DRP_CAPABILITIES => Some("capabilities"),
        CM_DRP_ENUMERATOR_NAME => Some("enumerator"),
        _ => None,
    }
}

fn filter_cm_devices(devices: &DeviceManager, filter: &str) -> Vec<DeviceRecord> {
    let trimmed = filter.trim();
    if trimmed.is_empty() {
        return devices.list_devices("", "", false);
    }
    if trimmed.starts_with('{') {
        return devices.list_devices(trimmed, "", false);
    }
    if let Some(device) = devices.find_by_instance_id(trimmed).cloned() {
        return vec![device];
    }
    let normalized = trimmed.to_ascii_lowercase();
    devices
        .list_devices("", "", false)
        .into_iter()
        .filter(|device| {
            device.class_name.eq_ignore_ascii_case(&normalized)
                || device.enumerator.eq_ignore_ascii_case(&normalized)
                || device
                    .instance_id
                    .to_ascii_lowercase()
                    .starts_with(&normalized)
        })
        .collect()
}
