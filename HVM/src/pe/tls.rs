use goblin::pe::PE;

/// Collects TLS callback addresses rebased into the mapped image.
pub fn collect_tls_callbacks(pe: &PE<'_>, mapped_base: u64) -> Vec<u64> {
    pe.tls_data
        .as_ref()
        .map(|tls| {
            tls.callbacks
                .iter()
                .filter_map(|callback| callback.checked_sub(pe.image_base))
                .filter_map(|rva| mapped_base.checked_add(rva))
                .collect()
        })
        .unwrap_or_default()
}
