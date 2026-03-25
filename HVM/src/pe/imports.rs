use goblin::pe::PE;

/// Captures the import binding fields needed by the runtime module manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportBinding {
    pub dll: String,
    pub function: String,
    pub ordinal: u16,
    pub offset: u64,
    pub size: usize,
    pub by_ordinal: bool,
}

/// Collects one normalized import binding per thunk entry using Python-compatible naming rules.
pub fn collect_import_bindings(pe: &PE<'_>) -> Vec<ImportBinding> {
    pe.imports
        .iter()
        .map(|import| {
            let by_ordinal = import.name.starts_with("ORDINAL ");
            let function = if by_ordinal {
                format!("ordinal_{}", import.ordinal)
            } else {
                import.name.to_string()
            };
            ImportBinding {
                dll: import.dll.to_string(),
                function,
                ordinal: import.ordinal,
                offset: import.offset as u64,
                size: import.size,
                by_ordinal,
            }
        })
        .collect()
}
