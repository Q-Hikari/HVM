use super::*;

use crate::environment_profile::FirmwareProfile;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn matches_firmware_provider(
        signature: u32,
        provider: [u8; 4],
    ) -> bool {
        signature == u32::from_be_bytes(provider) || signature == u32::from_le_bytes(provider)
    }

    pub(in crate::runtime::engine) fn synthetic_raw_smbios_data(&self) -> Vec<u8> {
        Self::build_raw_smbios_data(
            &self.core.environment_profile.firmware,
            &self.core.environment_profile.machine.machine_guid,
        )
    }

    pub(in crate::runtime::engine) fn build_raw_smbios_data(
        firmware: &FirmwareProfile,
        machine_guid: &str,
    ) -> Vec<u8> {
        let mut table_data = Vec::new();

        let mut bios_strings = Vec::new();
        let bios_vendor = Self::smbios_string_index(&mut bios_strings, &firmware.bios_vendor);
        let bios_version = Self::smbios_string_index(&mut bios_strings, &firmware.bios_version);
        let bios_release_date =
            Self::smbios_string_index(&mut bios_strings, &firmware.bios_release_date);
        let mut bios_header = vec![
            0x00,
            0x18,
            0x00,
            0x00,
            bios_vendor,
            bios_version,
            0x00,
            0xE0,
            bios_release_date,
            0x00,
        ];
        bios_header.extend_from_slice(&[0xFF; 8]);
        bios_header.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        Self::append_smbios_table(&mut table_data, &bios_header, &bios_strings);

        let mut system_strings = Vec::new();
        let system_manufacturer =
            Self::smbios_string_index(&mut system_strings, &firmware.system_manufacturer);
        let system_product_name =
            Self::smbios_string_index(&mut system_strings, &firmware.system_product_name);
        let system_version =
            Self::smbios_string_index(&mut system_strings, &firmware.system_version);
        let system_serial =
            Self::smbios_string_index(&mut system_strings, &firmware.system_serial_number);
        let system_sku = Self::smbios_string_index(&mut system_strings, &firmware.system_sku);
        let system_family = Self::smbios_string_index(&mut system_strings, &firmware.system_family);
        let system_uuid = Self::firmware_uuid_bytes(firmware, machine_guid);
        let mut system_header = vec![
            0x01,
            0x1B,
            0x01,
            0x00,
            system_manufacturer,
            system_product_name,
            system_version,
            system_serial,
        ];
        system_header.extend_from_slice(&system_uuid);
        system_header.extend_from_slice(&[0x06, system_sku, system_family]);
        Self::append_smbios_table(&mut table_data, &system_header, &system_strings);

        let mut baseboard_strings = Vec::new();
        let baseboard_manufacturer =
            Self::smbios_string_index(&mut baseboard_strings, &firmware.baseboard_manufacturer);
        let baseboard_product =
            Self::smbios_string_index(&mut baseboard_strings, &firmware.baseboard_product_name);
        let baseboard_version =
            Self::smbios_string_index(&mut baseboard_strings, &firmware.baseboard_version);
        let baseboard_serial =
            Self::smbios_string_index(&mut baseboard_strings, &firmware.baseboard_serial_number);
        let baseboard_asset =
            Self::smbios_string_index(&mut baseboard_strings, &firmware.baseboard_asset_tag);
        let baseboard_location = Self::smbios_string_index(
            &mut baseboard_strings,
            &firmware.baseboard_location_in_chassis,
        );
        let baseboard_header = [
            0x02,
            0x0F,
            0x02,
            0x00,
            baseboard_manufacturer,
            baseboard_product,
            baseboard_version,
            baseboard_serial,
            baseboard_asset,
            0x09,
            baseboard_location,
            0x03,
            0x00,
            0x0A,
            0x00,
        ];
        Self::append_smbios_table(&mut table_data, &baseboard_header, &baseboard_strings);

        let mut chassis_strings = Vec::new();
        let chassis_manufacturer =
            Self::smbios_string_index(&mut chassis_strings, &firmware.chassis_manufacturer);
        let chassis_version =
            Self::smbios_string_index(&mut chassis_strings, &firmware.chassis_version);
        let chassis_serial =
            Self::smbios_string_index(&mut chassis_strings, &firmware.chassis_serial_number);
        let chassis_asset =
            Self::smbios_string_index(&mut chassis_strings, &firmware.chassis_asset_tag);
        let mut chassis_header = vec![
            0x03,
            0x15,
            0x03,
            0x00,
            chassis_manufacturer,
            firmware.chassis_type,
            chassis_version,
            chassis_serial,
            chassis_asset,
            0x03,
            0x03,
            0x03,
            0x02,
        ];
        chassis_header.extend_from_slice(&0u32.to_le_bytes());
        chassis_header.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        Self::append_smbios_table(&mut table_data, &chassis_header, &chassis_strings);

        table_data.extend_from_slice(&[0x7F, 0x04, 0x7F, 0x00, 0x00, 0x00]);

        let mut raw = vec![0x00, 0x03, 0x03, 0x00];
        raw.extend_from_slice(&(table_data.len() as u32).to_le_bytes());
        raw.extend_from_slice(&table_data);
        raw
    }

    pub(in crate::runtime::engine) fn synthetic_acpi_table(&self, table_id: u32) -> Vec<u8> {
        Self::build_acpi_table(&self.core.environment_profile.firmware, table_id)
    }

    pub(in crate::runtime::engine) fn build_acpi_table(
        firmware: &FirmwareProfile,
        table_id: u32,
    ) -> Vec<u8> {
        let signature = if table_id == 0 {
            *b"DSDT"
        } else {
            let be = table_id.to_be_bytes();
            if be.iter().all(u8::is_ascii_graphic) {
                be
            } else {
                table_id.to_le_bytes()
            }
        };
        let body = if firmware.acpi_body.trim().is_empty() {
            b"B660M-ACPI-2023".as_slice()
        } else {
            firmware.acpi_body.as_bytes()
        };
        let total_len = 36 + body.len();
        let mut table = Vec::with_capacity(total_len);
        table.extend_from_slice(&signature);
        table.extend_from_slice(&(total_len as u32).to_le_bytes());
        table.push(2);
        table.push(0);
        table.extend_from_slice(&Self::padded_ascii::<6>(&firmware.acpi_oem_id, b"GBT   "));
        table.extend_from_slice(&Self::padded_ascii::<8>(
            &firmware.acpi_oem_table_id,
            b"B660MPC ",
        ));
        table.extend_from_slice(&1u32.to_le_bytes());
        table.extend_from_slice(&Self::padded_ascii::<4>(&firmware.acpi_creator_id, b"INTL"));
        table.extend_from_slice(&firmware.acpi_creator_revision.to_le_bytes());
        table.extend_from_slice(body);
        table
    }

    pub(in crate::runtime::engine) fn synthetic_firmware_table(
        &self,
        signature: u32,
        table_id: u32,
    ) -> Vec<u8> {
        if Self::matches_firmware_provider(signature, *b"RSMB") {
            self.synthetic_raw_smbios_data()
        } else if Self::matches_firmware_provider(signature, *b"ACPI") {
            self.synthetic_acpi_table(table_id)
        } else if Self::matches_firmware_provider(signature, *b"FIRM") {
            Self::build_firm_table(&self.core.environment_profile.firmware, table_id)
        } else {
            vec![0u8; 0x40]
        }
    }

    pub(in crate::runtime::engine) fn build_firm_table(
        firmware: &FirmwareProfile,
        table_id: u32,
    ) -> Vec<u8> {
        let mut data = vec![0u8; 0x100];
        data[0..4].copy_from_slice(&table_id.to_le_bytes());
        data[4..20].copy_from_slice(&Self::padded_ascii::<16>(
            &firmware.firm_bios_label,
            b"AMI BIOS 2023\0\0\0",
        ));
        data
    }

    pub(in crate::runtime::engine) fn synthetic_firmware_table_list(signature: u32) -> Vec<u8> {
        let ids = if Self::matches_firmware_provider(signature, *b"RSMB") {
            vec![0u32]
        } else if Self::matches_firmware_provider(signature, *b"ACPI") {
            vec![u32::from_be_bytes(*b"DSDT"), u32::from_be_bytes(*b"FACP")]
        } else if Self::matches_firmware_provider(signature, *b"FIRM") {
            vec![0x000C_0000u32, 0x000E_0000u32]
        } else {
            Vec::new()
        };
        ids.into_iter()
            .flat_map(|id| id.to_le_bytes())
            .collect::<Vec<_>>()
    }

    fn append_smbios_table(target: &mut Vec<u8>, header: &[u8], strings: &[String]) {
        target.extend_from_slice(header);
        for string in strings {
            target.extend_from_slice(string.as_bytes());
            target.push(0);
        }
        target.push(0);
    }

    fn smbios_string_index(strings: &mut Vec<String>, value: &str) -> u8 {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            0
        } else {
            strings.push(trimmed.to_string());
            strings.len().min(u8::MAX as usize) as u8
        }
    }

    fn firmware_uuid_bytes(firmware: &FirmwareProfile, machine_guid: &str) -> [u8; 16] {
        const FALLBACK_UUID: [u8; 16] = [
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E,
            0x9F, 0x10,
        ];

        Self::parse_guid_string_le(&firmware.system_uuid)
            .or_else(|| Self::parse_guid_string_le(machine_guid))
            .unwrap_or(FALLBACK_UUID)
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

    fn padded_ascii<const N: usize>(value: &str, fallback: &[u8; N]) -> [u8; N] {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return *fallback;
        }

        let mut bytes = [b' '; N];
        for (index, byte) in trimmed.bytes().take(N).enumerate() {
            bytes[index] = if byte.is_ascii() { byte } else { b'?' };
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_smbios_data_reflects_configured_profile_values() {
        let mut firmware = FirmwareProfile::default();
        firmware.bios_vendor = "Contoso Firmware".to_string();
        firmware.system_product_name = "Workstation-Z9".to_string();
        firmware.system_serial_number = "SYS-CUSTOM-0007".to_string();
        firmware.system_uuid = "12345678-9abc-def0-1234-56789abcdef0".to_string();

        let raw = VirtualExecutionEngine::build_raw_smbios_data(&firmware, "");
        let uuid = VirtualExecutionEngine::parse_guid_string_le(&firmware.system_uuid).unwrap();

        assert!(raw
            .windows("Contoso Firmware".len())
            .any(|w| w == b"Contoso Firmware"));
        assert!(raw
            .windows("Workstation-Z9".len())
            .any(|w| w == b"Workstation-Z9"));
        assert!(raw
            .windows("SYS-CUSTOM-0007".len())
            .any(|w| w == b"SYS-CUSTOM-0007"));
        assert!(raw.windows(uuid.len()).any(|w| w == uuid.as_slice()));
    }

    #[test]
    fn acpi_and_firm_tables_use_configured_ascii_fields() {
        let mut firmware = FirmwareProfile::default();
        firmware.acpi_oem_id = "ACME".to_string();
        firmware.acpi_oem_table_id = "Z790CORP".to_string();
        firmware.acpi_body = "CUSTOM-ACPI-BODY".to_string();
        firmware.firm_bios_label = "CORP BIOS 2026".to_string();

        let acpi = VirtualExecutionEngine::build_acpi_table(&firmware, 0);
        let firm = VirtualExecutionEngine::build_firm_table(&firmware, 0);

        assert!(acpi.windows(4).any(|w| w == b"ACME"));
        assert!(acpi
            .windows("CUSTOM-ACPI-BODY".len())
            .any(|w| w == b"CUSTOM-ACPI-BODY"));
        assert!(firm
            .windows("CORP BIOS 2026".len())
            .any(|w| w == b"CORP BIOS 2026"));
    }
}
