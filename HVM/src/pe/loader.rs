use std::cmp::max;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use goblin::pe::export::{ExportAddressTableEntry, Reexport};
use goblin::pe::section_table::SectionTable;
use goblin::pe::PE;

use crate::arch::{arch_name, arch_spec};
use crate::error::VmError;
use crate::memory::manager::{align_up, MemoryManager, PROT_READ};
use crate::models::{ForwardedExportTarget, ModuleRecord};
use crate::pe::relocations::apply_base_relocations;
use crate::pe::tls::collect_tls_callbacks;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_FILE_DLL: u16 = 0x2000;

/// Maps a PE image into the emulated memory manager and returns its runtime record.
pub fn map_image(path: &Path, memory: &mut MemoryManager) -> Result<ModuleRecord, VmError> {
    let resolved_path = std::path::absolute(path).map_err(|source| VmError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let bytes = fs::read(&resolved_path).map_err(|source| VmError::ReadFile {
        path: resolved_path.clone(),
        source,
    })?;
    let pe = PE::parse(&bytes).map_err(|source| VmError::ParsePe {
        path: resolved_path.clone(),
        source,
    })?;
    let optional_header = pe
        .header
        .optional_header
        .ok_or_else(|| VmError::MissingOptionalHeader(resolved_path.clone()))?;
    let machine = pe.header.coff_header.machine;
    let _arch = arch_name(machine).ok_or(VmError::UnsupportedMachine(machine))?;
    let arch = arch_spec(machine).ok_or(VmError::UnsupportedMachine(machine))?;
    let image_size = align_up(optional_header.windows_fields.size_of_image as u64, 0x1000);
    let image_base = pe.image_base;
    let preferred_base = if image_base == 0 {
        Some(arch.alloc_base)
    } else {
        Some(image_base)
    };
    let base = if image_base != 0 && memory.is_free(image_base, image_size, false) {
        memory.map_region(
            image_base,
            image_size,
            section_to_perms(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE),
            &format!("image:{}", resolved_path.display()),
        )?
    } else {
        memory.reserve(
            image_size,
            if image_base == 0 {
                preferred_base
            } else {
                None
            },
            &format!("image:{}", resolved_path.display()),
            false,
        )?
    };

    let headers_size = align_up(
        optional_header.windows_fields.size_of_headers as u64,
        0x1000,
    ) as usize;
    memory
        .write(base, &bytes[..bytes.len().min(headers_size)])
        .map_err(VmError::from)?;
    for section in &pe.sections {
        map_section(memory, base, section, &bytes)?;
    }
    apply_base_relocations(&pe, base, memory)?;
    finalize_image_protections(memory, base, image_size, headers_size as u64, &pe.sections)?;
    let exports = collect_exports(&bytes, &pe, base);

    Ok(ModuleRecord {
        name: resolved_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        path: Some(resolved_path),
        arch: _arch.to_string(),
        is_dll: pe.header.coff_header.characteristics & IMAGE_FILE_DLL != 0,
        base,
        size: image_size,
        entrypoint: base + pe.entry as u64,
        image_base,
        synthetic: false,
        tls_callbacks: collect_tls_callbacks(&pe, base),
        initialized: false,
        exports_by_name: exports.direct_by_name,
        export_name_text_by_key: exports.name_text_by_key,
        exports_by_ordinal: exports.direct_by_ordinal,
        forwarded_exports_by_name: exports.forwarded_by_name,
        forwarded_exports_by_ordinal: exports.forwarded_by_ordinal,
        stub_cursor: 0,
    })
}

fn map_section(
    memory: &mut MemoryManager,
    image_base: u64,
    section: &SectionTable,
    bytes: &[u8],
) -> Result<(), VmError> {
    let virtual_address = image_base + section.virtual_address as u64;
    if let Some(data) = section.data(bytes).map_err(|source| VmError::ParsePe {
        path: Path::new("<memory>").to_path_buf(),
        source,
    })? {
        memory
            .write(virtual_address, data.as_ref())
            .map_err(VmError::from)?;
        let virtual_size = max(section.virtual_size, data.len() as u32) as u64;
        if virtual_size > data.len() as u64 {
            let padding = vec![0; (virtual_size - data.len() as u64) as usize];
            memory
                .write(virtual_address + data.len() as u64, &padding)
                .map_err(VmError::from)?;
        }
    }
    Ok(())
}

fn finalize_image_protections(
    memory: &mut MemoryManager,
    image_base: u64,
    image_size: u64,
    headers_size: u64,
    sections: &[SectionTable],
) -> Result<(), VmError> {
    memory
        .protect(image_base, image_size, PROT_READ)
        .map_err(VmError::from)?;
    if headers_size != 0 {
        memory
            .protect(image_base, headers_size, PROT_READ)
            .map_err(VmError::from)?;
    }
    for section in sections {
        let section_size = align_up(
            max(section.virtual_size, section.size_of_raw_data) as u64,
            0x1000,
        );
        if section_size == 0 {
            continue;
        }
        memory
            .protect(
                image_base + section.virtual_address as u64,
                section_size,
                section_to_perms(section.characteristics),
            )
            .map_err(VmError::from)?;
    }
    Ok(())
}

#[derive(Debug, Default)]
struct CollectedExports {
    direct_by_name: BTreeMap<String, u64>,
    name_text_by_key: BTreeMap<String, String>,
    direct_by_ordinal: BTreeMap<u16, u64>,
    forwarded_by_name: BTreeMap<String, ForwardedExportTarget>,
    forwarded_by_ordinal: BTreeMap<u16, ForwardedExportTarget>,
}

fn collect_exports(bytes: &[u8], pe: &PE<'_>, base: u64) -> CollectedExports {
    let mut exports = CollectedExports::default();

    for export in &pe.exports {
        let Some(name) = export.name else {
            continue;
        };
        let normalized_name = name.to_ascii_lowercase();
        exports
            .name_text_by_key
            .insert(normalized_name.clone(), name.to_string());
        if let Some(target) = export
            .reexport
            .as_ref()
            .and_then(normalize_forwarded_export_target)
        {
            exports.forwarded_by_name.insert(normalized_name, target);
        } else if export.rva != 0 {
            exports
                .direct_by_name
                .insert(normalized_name, base + export.rva as u64);
        }
    }

    let Some(export_data) = pe.export_data.as_ref() else {
        return exports;
    };
    let Some(optional_header) = pe.header.optional_header.as_ref() else {
        return exports;
    };
    let ordinal_base = export_data.export_directory_table.ordinal_base;
    let file_alignment = optional_header.windows_fields.file_alignment;

    for (index, entry) in export_data.export_address_table.iter().enumerate() {
        let Some(ordinal) = ordinal_base
            .checked_add(index as u32)
            .and_then(|value| u16::try_from(value).ok())
        else {
            continue;
        };
        match entry {
            ExportAddressTableEntry::ExportRVA(rva) if *rva != 0 => {
                exports
                    .direct_by_ordinal
                    .insert(ordinal, base + *rva as u64);
            }
            ExportAddressTableEntry::ForwarderRVA(rva) => {
                let Some(target) =
                    parse_forwarded_export_target(bytes, pe, *rva as usize, file_alignment)
                else {
                    continue;
                };
                exports.forwarded_by_ordinal.insert(ordinal, target);
            }
            _ => {}
        }
    }

    exports
}

fn parse_forwarded_export_target(
    bytes: &[u8],
    pe: &PE<'_>,
    rva: usize,
    file_alignment: u32,
) -> Option<ForwardedExportTarget> {
    let offset = rva_to_offset(pe, rva, file_alignment)?;
    let reexport = Reexport::parse(bytes, offset).ok()?;
    normalize_forwarded_export_target(&reexport)
}

fn normalize_forwarded_export_target(reexport: &Reexport<'_>) -> Option<ForwardedExportTarget> {
    match reexport {
        Reexport::DLLName { export, lib } => Some(ForwardedExportTarget::ByName {
            module: normalize_module_name(Path::new(lib)),
            function: export.to_ascii_lowercase(),
        }),
        Reexport::DLLOrdinal { ordinal, lib } => {
            u16::try_from(*ordinal)
                .ok()
                .map(|ordinal| ForwardedExportTarget::ByOrdinal {
                    module: normalize_module_name(Path::new(lib)),
                    ordinal,
                })
        }
    }
}

fn rva_to_offset(pe: &PE<'_>, rva: usize, _file_alignment: u32) -> Option<usize> {
    for section in &pe.sections {
        let section_start = section.virtual_address as usize;
        let section_size = max(section.virtual_size, section.size_of_raw_data) as usize;
        let section_end = section_start.checked_add(section_size)?;
        if (section_start..section_end).contains(&rva) {
            let offset_in_section = rva.checked_sub(section_start)?;
            let raw_offset = section.pointer_to_raw_data as usize;
            return raw_offset.checked_add(offset_in_section);
        }
    }

    let header_size = pe
        .header
        .optional_header
        .as_ref()
        .map(|header| header.windows_fields.size_of_headers as usize)
        .unwrap_or_default();
    (rva < header_size).then_some(rva)
}

fn normalize_module_name(path: &Path) -> String {
    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    if file_name.contains('.') {
        file_name
    } else if file_name.is_empty() {
        file_name
    } else {
        format!("{file_name}.dll")
    }
}

fn section_to_perms(characteristics: u32) -> u32 {
    let mut perms = 0;
    if characteristics & IMAGE_SCN_MEM_READ != 0 {
        perms |= crate::memory::manager::PROT_READ;
    }
    if characteristics & IMAGE_SCN_MEM_WRITE != 0 {
        perms |= crate::memory::manager::PROT_WRITE;
    }
    if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
        perms |= crate::memory::manager::PROT_EXEC;
    }
    if perms == 0 {
        crate::memory::manager::PROT_READ
    } else {
        perms
    }
}
