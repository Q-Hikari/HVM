use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn matches_firmware_provider(
        signature: u32,
        provider: [u8; 4],
    ) -> bool {
        signature == u32::from_be_bytes(provider) || signature == u32::from_le_bytes(provider)
    }

    pub(in crate::runtime::engine) fn synthetic_raw_smbios_data() -> Vec<u8> {
        fn append_table(target: &mut Vec<u8>, header: &[u8], strings: &[&str]) {
            target.extend_from_slice(header);
            for string in strings {
                target.extend_from_slice(string.as_bytes());
                target.push(0);
            }
            target.push(0);
        }

        let mut table_data = Vec::new();
        append_table(
            &mut table_data,
            &[
                0x00, 0x18, 0x00, 0x00, 0x01, 0x02, 0x00, 0xE0, 0x03, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            ],
            &[
                "American Megatrends International, LLC.",
                "F16",
                "08/15/2023",
            ],
        );
        append_table(
            &mut table_data,
            &[
                0x01, 0x1B, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6,
                0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F, 0x10, 0x06, 0x05, 0x06,
            ],
            &[
                "Gigabyte Technology Co., Ltd.",
                "B660M DS3H DDR4",
                "Default string",
                "To be filled by O.E.M.",
                "Default string",
                "Default string",
            ],
        );
        append_table(
            &mut table_data,
            &[
                0x02, 0x0F, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x09, 0x06, 0x03, 0x00, 0x0A,
                0x00,
            ],
            &[
                "Gigabyte Technology Co., Ltd.",
                "B660M DS3H DDR4",
                "x.x",
                "Default string",
                "Default string",
                "Default string",
            ],
        );
        append_table(
            &mut table_data,
            &[
                0x03, 0x15, 0x03, 0x00, 0x01, 0x03, 0x03, 0x02, 0x02, 0x02, 0x04, 0x05, 0x06, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            ],
            &[
                "Gigabyte Technology Co., Ltd.",
                "Desktop",
                "Default string",
                "To be filled by O.E.M.",
                "Asset-Tag",
                "SKU-Default",
            ],
        );
        table_data.extend_from_slice(&[0x7F, 0x04, 0x7F, 0x00, 0x00, 0x00]);

        let mut raw = vec![0x00, 0x03, 0x03, 0x00];
        raw.extend_from_slice(&(table_data.len() as u32).to_le_bytes());
        raw.extend_from_slice(&table_data);
        raw
    }

    pub(in crate::runtime::engine) fn synthetic_acpi_table(table_id: u32) -> Vec<u8> {
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
        let body = b"B660M-ACPI-2023";
        let total_len = 36 + body.len();
        let mut table = Vec::with_capacity(total_len);
        table.extend_from_slice(&signature);
        table.extend_from_slice(&(total_len as u32).to_le_bytes());
        table.push(2);
        table.push(0);
        table.extend_from_slice(b"GBT   ");
        table.extend_from_slice(b"B660MPC ");
        table.extend_from_slice(&1u32.to_le_bytes());
        table.extend_from_slice(b"INTL");
        table.extend_from_slice(&0x2023_1201u32.to_le_bytes());
        table.extend_from_slice(body);
        table
    }

    pub(in crate::runtime::engine) fn synthetic_firmware_table(
        signature: u32,
        table_id: u32,
    ) -> Vec<u8> {
        if Self::matches_firmware_provider(signature, *b"RSMB") {
            Self::synthetic_raw_smbios_data()
        } else if Self::matches_firmware_provider(signature, *b"ACPI") {
            Self::synthetic_acpi_table(table_id)
        } else if Self::matches_firmware_provider(signature, *b"FIRM") {
            let mut data = vec![0u8; 0x100];
            data[0..4].copy_from_slice(&table_id.to_le_bytes());
            data[4..20].copy_from_slice(b"AMI BIOS 2023\0\0\0");
            data
        } else {
            vec![0u8; 0x40]
        }
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
}
