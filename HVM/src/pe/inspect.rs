use std::fs;
use std::path::Path;

use goblin::pe::PE;

use crate::arch::arch_name;
use crate::error::VmError;
use crate::models::{ImportDescriptorReport, PeInspectReport};

/// Reads the PE metadata needed by the Python-compatible `inspect` command.
pub fn inspect_pe(path: &Path) -> Result<PeInspectReport, VmError> {
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
    let arch = arch_name(machine)
        .ok_or(VmError::UnsupportedMachine(machine))?
        .to_string();
    let imports = collect_imports(&pe);

    Ok(PeInspectReport {
        name: resolved_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        arch,
        image_base: pe.image_base,
        entrypoint_rva: pe.entry as u64,
        size_of_image: optional_header.windows_fields.size_of_image,
        imports,
        has_tls: optional_header.data_directories.get_tls_table().is_some(),
        has_reloc: optional_header
            .data_directories
            .get_base_relocation_table()
            .is_some(),
    })
}

/// Renders inspect output using the same field names as the Python CLI.
pub fn render_inspect(report: &PeInspectReport) -> String {
    let mut output = String::new();
    output.push_str(&format!("name: {}\n", report.name));
    output.push_str(&format!("arch: {}\n", report.arch));
    output.push_str(&format!("image_base: 0x{:X}\n", report.image_base));
    output.push_str(&format!("entrypoint_rva: 0x{:X}\n", report.entrypoint_rva));
    output.push_str(&format!("size_of_image: 0x{:X}\n", report.size_of_image));
    output.push_str("imports:\n");
    for descriptor in &report.imports {
        output.push_str(&format!(
            "  - {}: {}\n",
            descriptor.dll,
            descriptor.symbols.join(", ")
        ));
    }
    output.push_str(&format!("has_tls: {}\n", report.has_tls));
    output.push_str(&format!("has_reloc: {}\n", report.has_reloc));
    output
}

fn collect_imports(pe: &PE<'_>) -> Vec<ImportDescriptorReport> {
    let mut grouped = Vec::new();

    for dll in &pe.libraries {
        let symbols = pe
            .imports
            .iter()
            .filter(|import| import.dll.eq_ignore_ascii_case(dll))
            .take(12)
            .map(|import| format_import_name(import.name.as_ref(), import.ordinal))
            .collect::<Vec<_>>();
        grouped.push(ImportDescriptorReport {
            dll: (*dll).to_string(),
            symbols,
        });
    }

    grouped
}

fn format_import_name(name: &str, ordinal: u16) -> String {
    if name.starts_with("ORDINAL ") {
        return format!("ordinal_{ordinal}");
    }
    name.to_string()
}
