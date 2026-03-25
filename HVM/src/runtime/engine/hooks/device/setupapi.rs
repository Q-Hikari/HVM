use super::*;

const DIGCF_PRESENT: u32 = 0x0000_0002;
const SPDRP_DEVICEDESC: u32 = 0;
const SPDRP_HARDWAREID: u32 = 1;
const SPDRP_COMPATIBLEIDS: u32 = 2;
const SPDRP_SERVICE: u32 = 4;
const SPDRP_CLASS: u32 = 7;
const SPDRP_CLASSGUID: u32 = 8;
const SPDRP_CONFIGFLAGS: u32 = 0x0A;
const SPDRP_MFG: u32 = 0x0B;
const SPDRP_FRIENDLYNAME: u32 = 0x0C;
const SPDRP_LOCATION_INFORMATION: u32 = 0x0D;
const SPDRP_CAPABILITIES: u32 = 0x0F;
const SPDRP_ENUMERATOR_NAME: u32 = 0x16;

#[derive(Debug, Clone, Copy)]
struct SetupDiInfoLayout {
    size: u64,
    class_guid_offset: u64,
    devinst_offset: u64,
    reserved_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct SetupDiInterfaceDetailLayout {
    cb_size: u32,
    path_offset: u64,
}

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_setupapi_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("setupapi.dll", "SetupDiGetClassDevsA") => true,
            ("setupapi.dll", "SetupDiGetClassDevsW") => true,
            ("setupapi.dll", "SetupDiDestroyDeviceInfoList") => true,
            ("setupapi.dll", "SetupDiEnumDeviceInfo") => true,
            ("setupapi.dll", "SetupDiGetDeviceRegistryPropertyA") => true,
            ("setupapi.dll", "SetupDiGetDeviceRegistryPropertyW") => true,
            ("setupapi.dll", "SetupDiGetDeviceInstanceIdA") => true,
            ("setupapi.dll", "SetupDiGetDeviceInstanceIdW") => true,
            ("setupapi.dll", "SetupDiOpenDevRegKey") => true,
            ("setupapi.dll", "SetupDiEnumDeviceInterfaces") => true,
            ("setupapi.dll", "SetupDiGetDeviceInterfaceDetailA") => true,
            ("setupapi.dll", "SetupDiGetDeviceInterfaceDetailW") => true,
            ("setupapi.dll", "SetupDiClassGuidsFromNameA") => true,
            ("setupapi.dll", "SetupDiClassGuidsFromNameW") => true,
            ("setupapi.dll", "SetupDiGetINFClassA") => true,
            ("setupapi.dll", "SetupDiGetINFClassW") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("setupapi.dll", "SetupDiGetClassDevsA") => self.setup_di_get_class_devs(
                    arg(args, 0),
                    &self.read_c_string_from_memory(arg(args, 1))?,
                    arg(args, 3) as u32,
                ),
                ("setupapi.dll", "SetupDiGetClassDevsW") => self.setup_di_get_class_devs(
                    arg(args, 0),
                    &self.read_wide_string_from_memory(arg(args, 1))?,
                    arg(args, 3) as u32,
                ),
                ("setupapi.dll", "SetupDiDestroyDeviceInfoList") => {
                    Ok(self.setup_di_destroy_device_info_list(arg(args, 0) as u32))
                }
                ("setupapi.dll", "SetupDiEnumDeviceInfo") => self.setup_di_enum_device_info(
                    arg(args, 0) as u32,
                    arg(args, 1) as u32,
                    arg(args, 2),
                ),
                ("setupapi.dll", "SetupDiGetDeviceRegistryPropertyA") => self
                    .setup_di_get_device_registry_property(
                        false,
                        arg(args, 0) as u32,
                        arg(args, 1),
                        arg(args, 2) as u32,
                        arg(args, 3),
                        arg(args, 4),
                        arg(args, 5) as usize,
                        arg(args, 6),
                    ),
                ("setupapi.dll", "SetupDiGetDeviceRegistryPropertyW") => self
                    .setup_di_get_device_registry_property(
                        true,
                        arg(args, 0) as u32,
                        arg(args, 1),
                        arg(args, 2) as u32,
                        arg(args, 3),
                        arg(args, 4),
                        arg(args, 5) as usize,
                        arg(args, 6),
                    ),
                ("setupapi.dll", "SetupDiGetDeviceInstanceIdA") => self
                    .setup_di_get_device_instance_id(
                        false,
                        arg(args, 0) as u32,
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3) as usize,
                        arg(args, 4),
                    ),
                ("setupapi.dll", "SetupDiGetDeviceInstanceIdW") => self
                    .setup_di_get_device_instance_id(
                        true,
                        arg(args, 0) as u32,
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3) as usize,
                        arg(args, 4),
                    ),
                ("setupapi.dll", "SetupDiOpenDevRegKey") => {
                    self.setup_di_open_dev_reg_key(arg(args, 0) as u32, arg(args, 1))
                }
                ("setupapi.dll", "SetupDiEnumDeviceInterfaces") => self
                    .setup_di_enum_device_interfaces(
                        arg(args, 0) as u32,
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3) as u32,
                        arg(args, 4),
                    ),
                ("setupapi.dll", "SetupDiGetDeviceInterfaceDetailA") => self
                    .setup_di_get_device_interface_detail(
                        false,
                        arg(args, 0) as u32,
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3) as usize,
                        arg(args, 4),
                        arg(args, 5),
                    ),
                ("setupapi.dll", "SetupDiGetDeviceInterfaceDetailW") => self
                    .setup_di_get_device_interface_detail(
                        true,
                        arg(args, 0) as u32,
                        arg(args, 1),
                        arg(args, 2),
                        arg(args, 3) as usize,
                        arg(args, 4),
                        arg(args, 5),
                    ),
                ("setupapi.dll", "SetupDiClassGuidsFromNameA") => self
                    .setup_di_class_guids_from_name(
                        &self.read_c_string_from_memory(arg(args, 0))?,
                        arg(args, 1),
                        arg(args, 2) as usize,
                        arg(args, 3),
                    ),
                ("setupapi.dll", "SetupDiClassGuidsFromNameW") => self
                    .setup_di_class_guids_from_name(
                        &self.read_wide_string_from_memory(arg(args, 0))?,
                        arg(args, 1),
                        arg(args, 2) as usize,
                        arg(args, 3),
                    ),
                ("setupapi.dll", "SetupDiGetINFClassA") => self.setup_di_get_inf_class(
                    &self.read_c_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2) as usize,
                    arg(args, 3),
                    arg(args, 4),
                    false,
                ),
                ("setupapi.dll", "SetupDiGetINFClassW") => self.setup_di_get_inf_class(
                    &self.read_wide_string_from_memory(arg(args, 0))?,
                    arg(args, 1),
                    arg(args, 2) as usize,
                    arg(args, 3),
                    arg(args, 4),
                    true,
                ),
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }

    fn setup_di_info_layout(&self) -> SetupDiInfoLayout {
        if self.arch.is_x86() {
            SetupDiInfoLayout {
                size: 28,
                class_guid_offset: 4,
                devinst_offset: 20,
                reserved_offset: 24,
            }
        } else {
            SetupDiInfoLayout {
                size: 32,
                class_guid_offset: 4,
                devinst_offset: 20,
                reserved_offset: 24,
            }
        }
    }

    fn setup_di_interface_detail_layout(&self, wide: bool) -> SetupDiInterfaceDetailLayout {
        if self.arch.is_x86() {
            SetupDiInterfaceDetailLayout {
                cb_size: if wide { 6 } else { 5 },
                path_offset: 4,
            }
        } else {
            SetupDiInterfaceDetailLayout {
                cb_size: 8,
                path_offset: 4,
            }
        }
    }

    fn setup_di_filter_guid(&self, guid_ptr: u64) -> Result<String, VmError> {
        if guid_ptr == 0 {
            return Ok(String::new());
        }
        let guid = self.read_guid_bytes_le_or_zero(guid_ptr)?;
        if guid == [0u8; 16] {
            Ok(String::new())
        } else {
            Ok(Self::format_guid_bytes_le(&guid))
        }
    }

    fn setup_di_open_set(&mut self, devices: Vec<u32>) -> u64 {
        let handle = self.allocate_object_handle();
        self.setup_device_sets
            .insert(handle, SetupDeviceInfoSetState { devices });
        self.set_last_error(ERROR_SUCCESS as u32);
        handle as u64
    }

    fn setup_di_get_set(&self, handle: u32) -> Option<&SetupDeviceInfoSetState> {
        self.setup_device_sets.get(&handle)
    }

    fn setup_di_get_device(
        &self,
        devinfo_handle: u32,
        devinfo_data_ptr: u64,
    ) -> Option<DeviceRecord> {
        let devinst = self.read_setup_di_devinst(devinfo_data_ptr).ok()?;
        self.setup_di_get_set(devinfo_handle)?;
        self.devices.get(devinst).cloned()
    }

    fn read_setup_di_devinst(&self, devinfo_data_ptr: u64) -> Result<u32, VmError> {
        let layout = self.setup_di_info_layout();
        self.read_u32(devinfo_data_ptr + layout.devinst_offset)
    }

    fn write_setup_di_data(
        &mut self,
        address: u64,
        class_guid: &str,
        devinst: u32,
        reserved: u64,
    ) -> Result<(), VmError> {
        let layout = self.setup_di_info_layout();
        self.fill_memory_pattern(address, layout.size, 0)?;
        self.write_u32(address, layout.size as u32)?;
        if let Some(bytes) = parse_guid_string_le(class_guid) {
            self.modules
                .memory_mut()
                .write(address + layout.class_guid_offset, &bytes)?;
        }
        self.write_u32(address + layout.devinst_offset, devinst)?;
        self.write_pointer_value(address + layout.reserved_offset, reserved)?;
        Ok(())
    }

    fn setup_di_get_class_devs(
        &mut self,
        class_guid_ptr: u64,
        enumerator: &str,
        flags: u32,
    ) -> Result<u64, VmError> {
        let class_guid = self.setup_di_filter_guid(class_guid_ptr)?;
        let present_only = flags & DIGCF_PRESENT != 0;
        let devices = self
            .devices
            .list_devices(&class_guid, enumerator, present_only)
            .into_iter()
            .map(|device| device.devinst)
            .collect::<Vec<_>>();
        Ok(self.setup_di_open_set(devices))
    }

    fn setup_di_destroy_device_info_list(&mut self, handle: u32) -> u64 {
        let ok = self.setup_device_sets.remove(&handle).is_some();
        self.set_last_error(if ok {
            ERROR_SUCCESS as u32
        } else {
            ERROR_INVALID_HANDLE as u32
        });
        ok as u64
    }

    fn setup_di_enum_device_info(
        &mut self,
        handle: u32,
        member_index: u32,
        devinfo_data_ptr: u64,
    ) -> Result<u64, VmError> {
        if devinfo_data_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let Some(set) = self.setup_di_get_set(handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let Some(&devinst) = set.devices.get(member_index as usize) else {
            self.set_last_error(ERROR_NO_MORE_ITEMS as u32);
            return Ok(0);
        };
        let Some(device) = self.devices.get(devinst).cloned() else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        self.write_setup_di_data(devinfo_data_ptr, &device.class_guid, device.devinst, 0)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn setup_di_get_device_registry_property(
        &mut self,
        wide: bool,
        handle: u32,
        devinfo_data_ptr: u64,
        property: u32,
        reg_type_ptr: u64,
        buffer: u64,
        buffer_size: usize,
        required_size_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(device) = self.setup_di_get_device(handle, devinfo_data_ptr) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let Some(property_key) = setup_di_property_key(property) else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        };
        let Some((value_type, data)) = self.devices.property_data(&device, property_key, wide)
        else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        };
        self.write_property_buffer(
            value_type,
            &data,
            reg_type_ptr,
            buffer,
            buffer_size,
            required_size_ptr,
        )
    }

    fn setup_di_get_device_instance_id(
        &mut self,
        wide: bool,
        handle: u32,
        devinfo_data_ptr: u64,
        buffer: u64,
        buffer_size: usize,
        required_size_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(device) = self.setup_di_get_device(handle, devinfo_data_ptr) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let required_chars = if wide {
            device.instance_id.encode_utf16().count() + 1
        } else {
            device.instance_id.len() + 1
        };
        if required_size_ptr != 0 {
            self.write_u32(required_size_ptr, required_chars as u32)?;
        }
        if buffer == 0 || buffer_size < required_chars {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }
        if wide {
            let _ = self.write_wide_string_to_memory(buffer, buffer_size, &device.instance_id)?;
        } else {
            let _ = self.write_c_string_to_memory(buffer, buffer_size, &device.instance_id)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn setup_di_open_dev_reg_key(
        &mut self,
        handle: u32,
        devinfo_data_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(device) = self.setup_di_get_device(handle, devinfo_data_ptr) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(self.invalid_handle_value_for_arch());
        };
        let subkey = format!(
            "SYSTEM\\CurrentControlSet\\Enum\\{}",
            device.instance_id.replace('/', "\\")
        );
        let path = format!("HKEY_LOCAL_MACHINE\\{subkey}");
        seed_device_registry_snapshot(&mut self.registry, &self.devices, &device, &path);
        let Some(key) = self.registry.open_key(HKEY_LOCAL_MACHINE, &subkey, false) else {
            self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
            return Ok(self.invalid_handle_value_for_arch());
        };
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(key as u64)
    }

    fn setup_di_class_guids_from_name(
        &mut self,
        class_name: &str,
        guid_list_ptr: u64,
        guid_capacity: usize,
        required_size_ptr: u64,
    ) -> Result<u64, VmError> {
        let guids = self.devices.class_guids_from_name(class_name);
        if required_size_ptr != 0 {
            self.write_u32(required_size_ptr, guids.len().min(u32::MAX as usize) as u32)?;
        }
        if guids.is_empty() {
            self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
            return Ok(0);
        }
        if guid_list_ptr == 0 || guid_capacity < guids.len() {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }
        let writable = guid_capacity.min(guids.len());
        for (index, guid) in guids.iter().take(writable).enumerate() {
            if let Some(bytes) = parse_guid_string_le(guid) {
                self.modules
                    .memory_mut()
                    .write(guid_list_ptr + index as u64 * 16, &bytes)?;
            }
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn setup_di_get_inf_class(
        &mut self,
        inf_path: &str,
        class_name_buffer: u64,
        class_name_capacity: usize,
        required_size_ptr: u64,
        class_guid_ptr: u64,
        wide: bool,
    ) -> Result<u64, VmError> {
        let (class_name, class_guid) = infer_setup_class(&self.devices, inf_path);
        if class_guid_ptr != 0 {
            if let Some(bytes) = parse_guid_string_le(&class_guid) {
                self.modules.memory_mut().write(class_guid_ptr, &bytes)?;
            }
        }
        let required_chars = if wide {
            class_name.encode_utf16().count() + 1
        } else {
            class_name.len() + 1
        };
        if required_size_ptr != 0 {
            self.write_u32(required_size_ptr, required_chars as u32)?;
        }
        if class_name_buffer == 0 || class_name_capacity < required_chars {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }
        if wide {
            let _ = self.write_wide_string_to_memory(
                class_name_buffer,
                class_name_capacity,
                &class_name,
            )?;
        } else {
            let _ =
                self.write_c_string_to_memory(class_name_buffer, class_name_capacity, &class_name)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn setup_di_enum_device_interfaces(
        &mut self,
        handle: u32,
        devinfo_data_ptr: u64,
        interface_class_guid_ptr: u64,
        member_index: u32,
        interface_data_ptr: u64,
    ) -> Result<u64, VmError> {
        if interface_data_ptr == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }
        let Some(set) = self.setup_di_get_set(handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let devices = if devinfo_data_ptr != 0 {
            let devinst = self.read_setup_di_devinst(devinfo_data_ptr)?;
            vec![devinst]
        } else {
            set.devices.clone()
        };
        let Some(&devinst) = devices.get(member_index as usize) else {
            self.set_last_error(ERROR_NO_MORE_ITEMS as u32);
            return Ok(0);
        };
        let Some(device) = self.devices.get(devinst).cloned() else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let interface_guid = {
            let filter = self.setup_di_filter_guid(interface_class_guid_ptr)?;
            if filter.is_empty() {
                device.class_guid.clone()
            } else {
                filter
            }
        };
        self.write_setup_di_data(
            interface_data_ptr,
            &interface_guid,
            0,
            device.devinst as u64,
        )?;
        let layout = self.setup_di_info_layout();
        self.write_u32(interface_data_ptr + layout.devinst_offset, 1)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn setup_di_get_device_interface_detail(
        &mut self,
        wide: bool,
        handle: u32,
        interface_data_ptr: u64,
        detail_buffer_ptr: u64,
        detail_buffer_size: usize,
        required_size_ptr: u64,
        devinfo_data_ptr: u64,
    ) -> Result<u64, VmError> {
        let Some(_) = self.setup_di_get_set(handle) else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        };
        let layout = self.setup_di_info_layout();
        let devinst = self.read_pointer_value(interface_data_ptr + layout.reserved_offset)? as u32;
        let Some(device) = self.devices.get(devinst).cloned() else {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        };
        let path = self.devices.device_path(&device);
        let detail_layout = self.setup_di_interface_detail_layout(wide);
        let string_bytes = if wide {
            wide_storage_size(&path)
        } else {
            ansi_storage_size(&path)
        };
        let required = detail_layout.path_offset + string_bytes;
        if required_size_ptr != 0 {
            self.write_u32(required_size_ptr, required.min(u32::MAX as u64) as u32)?;
        }
        if detail_buffer_ptr == 0 || detail_buffer_size < required as usize {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }
        self.fill_memory_pattern(detail_buffer_ptr, required, 0)?;
        self.write_u32(detail_buffer_ptr, detail_layout.cb_size)?;
        if wide {
            let capacity = (string_bytes / 2) as usize;
            let _ = self.write_wide_string_to_memory(
                detail_buffer_ptr + detail_layout.path_offset,
                capacity,
                &path,
            )?;
        } else {
            let _ = self.write_c_string_to_memory(
                detail_buffer_ptr + detail_layout.path_offset,
                string_bytes as usize,
                &path,
            )?;
        }
        if devinfo_data_ptr != 0 {
            self.write_setup_di_data(devinfo_data_ptr, &device.class_guid, device.devinst, 0)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn write_property_buffer(
        &mut self,
        value_type: u32,
        data: &[u8],
        reg_type_ptr: u64,
        buffer: u64,
        buffer_size: usize,
        required_size_ptr: u64,
    ) -> Result<u64, VmError> {
        if reg_type_ptr != 0 {
            self.write_u32(reg_type_ptr, value_type)?;
        }
        if required_size_ptr != 0 {
            self.write_u32(required_size_ptr, data.len().min(u32::MAX as usize) as u32)?;
        }
        if buffer == 0 || buffer_size < data.len() {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }
        self.modules.memory_mut().write(buffer, data)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }
}

fn setup_di_property_key(property: u32) -> Option<&'static str> {
    match property {
        SPDRP_DEVICEDESC => Some("devicedesc"),
        SPDRP_HARDWAREID => Some("hardwareid"),
        SPDRP_COMPATIBLEIDS => Some("compatibleids"),
        SPDRP_SERVICE => Some("service"),
        SPDRP_CLASS => Some("class"),
        SPDRP_CLASSGUID => Some("classguid"),
        SPDRP_CONFIGFLAGS => Some("configflags"),
        SPDRP_MFG => Some("mfg"),
        SPDRP_FRIENDLYNAME => Some("friendlyname"),
        SPDRP_LOCATION_INFORMATION => Some("location"),
        SPDRP_CAPABILITIES => Some("capabilities"),
        SPDRP_ENUMERATOR_NAME => Some("enumerator"),
        _ => None,
    }
}

fn parse_guid_string_le(guid: &str) -> Option<[u8; 16]> {
    let trimmed = guid.trim().trim_matches(|ch| ch == '{' || ch == '}');
    let parts = trimmed.split('-').collect::<Vec<_>>();
    if parts.len() != 5 {
        return None;
    }
    let time_low = u32::from_str_radix(parts[0], 16).ok()?;
    let time_mid = u16::from_str_radix(parts[1], 16).ok()?;
    let time_hi = u16::from_str_radix(parts[2], 16).ok()?;
    if parts[3].len() != 4 || parts[4].len() != 12 {
        return None;
    }
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&time_low.to_le_bytes());
    bytes[4..6].copy_from_slice(&time_mid.to_le_bytes());
    bytes[6..8].copy_from_slice(&time_hi.to_le_bytes());
    bytes[8] = u8::from_str_radix(&parts[3][0..2], 16).ok()?;
    bytes[9] = u8::from_str_radix(&parts[3][2..4], 16).ok()?;
    for index in 0..6 {
        let start = index * 2;
        bytes[10 + index] = u8::from_str_radix(&parts[4][start..start + 2], 16).ok()?;
    }
    Some(bytes)
}

fn wide_storage_size(value: &str) -> u64 {
    ((value.encode_utf16().count() + 1) * 2) as u64
}

fn ansi_storage_size(value: &str) -> u64 {
    (value.len() + 1) as u64
}

fn infer_setup_class(devices: &DeviceManager, inf_path: &str) -> (String, String) {
    let normalized = inf_path.to_ascii_lowercase();
    let class_name = if normalized.contains("net") || normalized.contains("e1i") {
        "Net"
    } else if normalized.contains("disk")
        || normalized.contains("stor")
        || normalized.contains("usb")
    {
        "DiskDrive"
    } else {
        "System"
    };
    let class_guid = devices
        .class_guids_from_name(class_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| "{4D36E97D-E325-11CE-BFC1-08002BE10318}".to_string());
    (class_name.to_string(), class_guid)
}

fn seed_device_registry_snapshot(
    registry: &mut RegistryManager,
    devices: &DeviceManager,
    device: &DeviceRecord,
    path: &str,
) {
    for (name, property) in [
        ("DeviceDesc", "devicedesc"),
        ("HardwareID", "hardwareid"),
        ("CompatibleIDs", "compatibleids"),
        ("Service", "service"),
        ("Class", "class"),
        ("ClassGUID", "classguid"),
        ("Mfg", "mfg"),
        ("FriendlyName", "friendlyname"),
        ("LocationInformation", "location"),
        ("EnumeratorName", "enumerator"),
    ] {
        if let Some((value_type, data)) = devices.property_data(device, property, true) {
            let _ = registry.set_value_at_path(path, name, value_type, &data);
        }
    }
    let _ = registry.set_value_at_path(path, "Capabilities", REG_DWORD, &0u32.to_le_bytes());
    let _ = registry.set_value_at_path(path, "ConfigFlags", REG_DWORD, &0u32.to_le_bytes());
}
