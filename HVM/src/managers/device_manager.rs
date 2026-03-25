use std::collections::{BTreeMap, BTreeSet};

pub const REG_SZ: u32 = 1;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;

/// Stores one seeded emulated Plug and Play device record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub devinst: u32,
    pub instance_id: String,
    pub class_name: String,
    pub class_guid: String,
    pub enumerator: String,
    pub description: String,
    pub friendly_name: String,
    pub manufacturer: String,
    pub service: String,
    pub location: String,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
    pub parent: u32,
    pub children: Vec<u32>,
    pub status: u32,
    pub problem: u32,
    pub present: bool,
}

/// Mirrors the Python device inventory used by setupapi- and device-backed hooks.
#[derive(Debug, Default)]
pub struct DeviceManager {
    devices: BTreeMap<u32, DeviceRecord>,
    instance_map: BTreeMap<String, u32>,
    class_guid_map: BTreeMap<String, BTreeSet<u32>>,
    class_name_map: BTreeMap<String, BTreeSet<u32>>,
}

impl DeviceManager {
    /// Builds the manager with the same seeded root, network, and disk devices as Python.
    pub fn new() -> Self {
        let mut manager = Self::default();
        manager.seed();
        manager
    }

    /// Returns the current device list filtered like the Python baseline.
    pub fn list_devices(
        &self,
        class_guid: &str,
        enumerator: &str,
        present_only: bool,
    ) -> Vec<DeviceRecord> {
        let class_guid_key = class_guid.to_ascii_lowercase();
        let enumerator_key = enumerator.to_ascii_lowercase();
        self.devices
            .values()
            .filter(|device| {
                (class_guid.is_empty() || device.class_guid.eq_ignore_ascii_case(&class_guid_key))
                    && (enumerator.is_empty()
                        || device.enumerator.eq_ignore_ascii_case(&enumerator_key)
                        || device.class_name.eq_ignore_ascii_case(&enumerator_key))
                    && (!present_only || device.present)
            })
            .cloned()
            .collect()
    }

    /// Returns one device by devinst identifier.
    pub fn get(&self, devinst: u32) -> Option<&DeviceRecord> {
        self.devices.get(&devinst)
    }

    /// Finds one device by instance identifier.
    pub fn find_by_instance_id(&self, instance_id: &str) -> Option<&DeviceRecord> {
        let devinst = self.instance_map.get(&instance_id.to_ascii_lowercase())?;
        self.devices.get(devinst)
    }

    /// Returns all class GUIDs registered under the provided class or enumerator name.
    pub fn class_guids_from_name(&self, name: &str) -> Vec<String> {
        let Some(ids) = self.class_name_map.get(&name.to_ascii_lowercase()) else {
            return Vec::new();
        };
        let guids = ids
            .iter()
            .filter_map(|devinst| self.devices.get(devinst))
            .map(|device| device.class_guid.clone())
            .collect::<BTreeSet<_>>();
        guids.iter().cloned().collect()
    }

    /// Returns a Windows-style device path for the requested device.
    pub fn device_path(&self, device: &DeviceRecord) -> String {
        let normalized = device.instance_id.replace('\\', "#");
        let guid = device.class_guid.trim_matches(|ch| ch == '{' || ch == '}');
        format!("\\\\?\\{normalized}#{{{guid}}}")
    }

    /// Encodes one text value using the requested wide or narrow representation.
    pub fn encode_text(&self, text: &str, wide: bool) -> Vec<u8> {
        if wide {
            let mut bytes = text
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            bytes.extend_from_slice(&[0, 0]);
            bytes
        } else {
            let mut bytes = text
                .chars()
                .map(|ch| if ch.is_ascii() { ch as u8 } else { b'?' })
                .collect::<Vec<_>>();
            bytes.push(0);
            bytes
        }
    }

    /// Encodes a multi-string list using the requested wide or narrow representation.
    pub fn encode_multi_sz(&self, values: &[String], wide: bool) -> Vec<u8> {
        if values.is_empty() {
            return vec![0, 0];
        }
        if wide {
            let mut bytes = Vec::new();
            for value in values {
                bytes.extend(value.encode_utf16().flat_map(u16::to_le_bytes));
                bytes.extend_from_slice(&[0, 0]);
            }
            bytes.extend_from_slice(&[0, 0]);
            bytes
        } else {
            let mut bytes = Vec::new();
            for value in values {
                bytes.extend(
                    value
                        .chars()
                        .map(|ch| if ch.is_ascii() { ch as u8 } else { b'?' }),
                );
                bytes.push(0);
            }
            bytes.push(0);
            bytes
        }
    }

    /// Returns setupapi-style property data for one device property key.
    pub fn property_data(
        &self,
        device: &DeviceRecord,
        key: &str,
        wide: bool,
    ) -> Option<(u32, Vec<u8>)> {
        match key.to_ascii_lowercase().as_str() {
            "devicedesc" => Some((REG_SZ, self.encode_text(&device.description, wide))),
            "hardwareid" => Some((
                REG_MULTI_SZ,
                self.encode_multi_sz(&device.hardware_ids, wide),
            )),
            "compatibleids" => Some((
                REG_MULTI_SZ,
                self.encode_multi_sz(&device.compatible_ids, wide),
            )),
            "service" => Some((REG_SZ, self.encode_text(&device.service, wide))),
            "class" => Some((REG_SZ, self.encode_text(&device.class_name, wide))),
            "classguid" => Some((REG_SZ, self.encode_text(&device.class_guid, wide))),
            "mfg" => Some((REG_SZ, self.encode_text(&device.manufacturer, wide))),
            "friendlyname" => Some((REG_SZ, self.encode_text(&device.friendly_name, wide))),
            "location" => Some((REG_SZ, self.encode_text(&device.location, wide))),
            "enumerator" => Some((REG_SZ, self.encode_text(&device.enumerator, wide))),
            "capabilities" | "configflags" => Some((REG_DWORD, 0u32.to_le_bytes().to_vec())),
            _ => None,
        }
    }

    fn seed(&mut self) {
        let root = self.add_device(DeviceRecord {
            devinst: 0x10000,
            instance_id: "ROOT\\HTREE\\ROOT\\0".to_string(),
            class_name: "System".to_string(),
            class_guid: "{4D36E97D-E325-11CE-BFC1-08002BE10318}".to_string(),
            enumerator: "ROOT".to_string(),
            description: "Sandbox Root Enumerator".to_string(),
            friendly_name: "Sandbox Root Enumerator".to_string(),
            manufacturer: "OpenAI Sandbox".to_string(),
            service: "ACPI".to_string(),
            location: "Internal".to_string(),
            hardware_ids: vec!["ROOT\\HTREE\\ROOT\\0".to_string()],
            compatible_ids: Vec::new(),
            parent: 0,
            children: Vec::new(),
            status: 0x0180_200,
            problem: 0,
            present: true,
        });
        let net = self.add_device(DeviceRecord {
            devinst: 0x10001,
            instance_id: "PCI\\VEN_8086&DEV_100E&SUBSYS_00008086&REV_02\\3&11583659&0&18"
                .to_string(),
            class_name: "Net".to_string(),
            class_guid: "{4D36E972-E325-11CE-BFC1-08002BE10318}".to_string(),
            enumerator: "PCI".to_string(),
            description: "Sandbox Intel(R) PRO/1000 MT Desktop Adapter".to_string(),
            friendly_name: "Sandbox Ethernet Adapter".to_string(),
            manufacturer: "Intel".to_string(),
            service: "e1iexpress".to_string(),
            location: "PCI bus 0, device 3, function 0".to_string(),
            hardware_ids: vec!["PCI\\VEN_8086&DEV_100E&SUBSYS_00008086&REV_02".to_string()],
            compatible_ids: vec![
                "PCI\\VEN_8086&DEV_100E".to_string(),
                "PCI\\VEN_8086&CC_020000".to_string(),
            ],
            parent: root.devinst,
            children: Vec::new(),
            status: 0x0180_200,
            problem: 0,
            present: true,
        });
        let disk = self.add_device(DeviceRecord {
            devinst: 0x10002,
            instance_id: "USBSTOR\\DISK&VEN_SANDBOX&PROD_VIRTUAL_DISK&REV_1.00\\0001".to_string(),
            class_name: "DiskDrive".to_string(),
            class_guid: "{4D36E967-E325-11CE-BFC1-08002BE10318}".to_string(),
            enumerator: "USBSTOR".to_string(),
            description: "Sandbox Virtual Disk".to_string(),
            friendly_name: "Sandbox USB Disk".to_string(),
            manufacturer: "OpenAI Sandbox".to_string(),
            service: "disk".to_string(),
            location: "Port_#0001.Hub_#0001".to_string(),
            hardware_ids: vec!["USBSTOR\\DISK&VEN_SANDBOX&PROD_VIRTUAL_DISK&REV_1.00".to_string()],
            compatible_ids: vec!["USBSTOR\\GenDisk".to_string()],
            parent: root.devinst,
            children: Vec::new(),
            status: 0x0180_200,
            problem: 0,
            present: true,
        });
        if let Some(root) = self.devices.get_mut(&root.devinst) {
            root.children = vec![net.devinst, disk.devinst];
        }
    }

    fn add_device(&mut self, record: DeviceRecord) -> DeviceRecord {
        self.instance_map
            .insert(record.instance_id.to_ascii_lowercase(), record.devinst);
        self.class_guid_map
            .entry(record.class_guid.to_ascii_lowercase())
            .or_default()
            .insert(record.devinst);
        self.class_name_map
            .entry(record.class_name.to_ascii_lowercase())
            .or_default()
            .insert(record.devinst);
        self.class_name_map
            .entry(record.enumerator.to_ascii_lowercase())
            .or_default()
            .insert(record.devinst);
        self.devices.insert(record.devinst, record.clone());
        record
    }
}
