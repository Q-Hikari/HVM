const LOAD_ALIAS_EXACT_HOSTS: &[(&str, &str)] = &[
    // Keep legacy CRT glue explicit. API-set contracts are resolved through
    // contract families rather than broad host-module aliasing.
    ("vcruntime140.dll", "msvcrt.dll"),
    ("vcruntime140_1.dll", "msvcrt.dll"),
];

const CONTRACT_HOOK_FAMILIES: &[(&str, &str)] = &[
    ("api-ms-win-core-apiquery", "api-ms-win-core-apiquery"),
    ("api-ms-win-core-appcompat", "api-ms-win-core-appcompat"),
    ("api-ms-win-core-atoms", "api-ms-win-core-atoms"),
    ("api-ms-win-core-com", "api-ms-win-core-com"),
    ("api-ms-win-core-console", "api-ms-win-core-console"),
    ("api-ms-win-core-delayload", "api-ms-win-core-delayload"),
    (
        "api-ms-win-core-errorhandling",
        "api-ms-win-core-errorhandling",
    ),
    ("api-ms-win-core-file", "api-ms-win-core-file"),
    ("api-ms-win-core-fibers", "api-ms-win-core-fibers"),
    ("api-ms-win-core-heap", "api-ms-win-core-heap"),
    (
        "api-ms-win-core-largeinteger",
        "api-ms-win-core-largeinteger",
    ),
    (
        "api-ms-win-core-libraryloader",
        "api-ms-win-core-libraryloader",
    ),
    (
        "api-ms-win-core-localization",
        "api-ms-win-core-localization",
    ),
    ("api-ms-win-core-memory", "api-ms-win-core-memory"),
    ("api-ms-win-core-namespace", "api-ms-win-core-namespace"),
    ("api-ms-win-core-path", "api-ms-win-core-path"),
    ("api-ms-win-core-pcw", "api-ms-win-core-pcw"),
    (
        "api-ms-win-core-processthreads",
        "api-ms-win-core-processthreads",
    ),
    (
        "api-ms-win-core-processsnapshot",
        "api-ms-win-core-processsnapshot",
    ),
    ("api-ms-win-core-psapi", "api-ms-win-core-psapi"),
    ("api-ms-win-core-registry", "api-ms-win-core-registry"),
    (
        "api-ms-win-core-registryuserspecific",
        "api-ms-win-core-registryuserspecific",
    ),
    (
        "api-ms-win-core-shlwapi-legacy",
        "api-ms-win-core-shlwapi-legacy",
    ),
    (
        "api-ms-win-core-shlwapi-obsolete",
        "api-ms-win-core-shlwapi-obsolete",
    ),
    ("api-ms-win-core-sidebyside", "api-ms-win-core-sidebyside"),
    ("api-ms-win-core-string", "api-ms-win-core-string"),
    ("api-ms-win-core-synch", "api-ms-win-core-synch"),
    ("api-ms-win-core-sysinfo", "api-ms-win-core-sysinfo"),
    ("api-ms-win-core-versionansi", "api-ms-win-core-versionansi"),
    (
        "api-ms-win-core-windowserrorreporting",
        "api-ms-win-core-windowserrorreporting",
    ),
    ("api-ms-win-core-wow64", "api-ms-win-core-wow64"),
    ("api-ms-win-core-crt", "api-ms-win-core-crt"),
    ("api-ms-win-crt", "api-ms-win-crt"),
    (
        "api-ms-win-security-appcontainer",
        "api-ms-win-security-appcontainer",
    ),
    ("api-ms-win-security-audit", "api-ms-win-security-audit"),
    ("api-ms-win-security-base", "api-ms-win-security-base"),
];

pub fn canonical_runtime_module_name(module_name: &str) -> String {
    aliased_host_module(module_name)
        .map(str::to_string)
        .unwrap_or_else(|| module_name.to_string())
}

pub fn aliased_host_module(module_name: &str) -> Option<&'static str> {
    let normalized = module_name.to_ascii_lowercase();
    LOAD_ALIAS_EXACT_HOSTS
        .iter()
        .find(|(module, _)| *module == normalized)
        .map(|(_, host)| *host)
}

pub fn contract_hook_family(module_name: &str) -> Option<&'static str> {
    let normalized = module_name.to_ascii_lowercase();
    CONTRACT_HOOK_FAMILIES
        .iter()
        .find_map(|(family_prefix, family_key)| {
            (normalized == *family_prefix || normalized.starts_with(&format!("{family_prefix}-")))
                .then_some(*family_key)
        })
}

#[cfg(test)]
mod tests {
    use super::{aliased_host_module, canonical_runtime_module_name, contract_hook_family};

    #[test]
    fn runtime_load_aliases_only_keep_explicit_legacy_hosts() {
        assert_eq!(aliased_host_module("vcruntime140.dll"), Some("msvcrt.dll"));
        assert_eq!(
            canonical_runtime_module_name("vcruntime140_1.dll"),
            "msvcrt.dll"
        );
        assert_eq!(
            canonical_runtime_module_name("api-ms-win-core-libraryloader-l1-2-0.dll"),
            "api-ms-win-core-libraryloader-l1-2-0.dll"
        );
    }

    #[test]
    fn versioned_contracts_collapse_into_manual_hook_families() {
        assert_eq!(
            contract_hook_family("api-ms-win-core-libraryloader-l1-2-0.dll"),
            Some("api-ms-win-core-libraryloader")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-libraryloader-l1-2-1.dll"),
            Some("api-ms-win-core-libraryloader")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-psapi-ansi-l1-1-0.dll"),
            Some("api-ms-win-core-psapi")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-memory-l1-1-1.dll"),
            Some("api-ms-win-core-memory")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-synch-l1-2-1.dll"),
            Some("api-ms-win-core-synch")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-file-l1-2-2.dll"),
            Some("api-ms-win-core-file")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-localization-l2-1-0.dll"),
            Some("api-ms-win-core-localization")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-registry-l1-1-1.dll"),
            Some("api-ms-win-core-registry")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-shlwapi-legacy-l1-1-0.dll"),
            Some("api-ms-win-core-shlwapi-legacy")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-com-l1-1-0.dll"),
            Some("api-ms-win-core-com")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-sysinfo-l1-1-0.dll"),
            Some("api-ms-win-core-sysinfo")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-versionansi-l1-1-0.dll"),
            Some("api-ms-win-core-versionansi")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-console-l3-2-0.dll"),
            Some("api-ms-win-core-console")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-path-l1-1-0.dll"),
            Some("api-ms-win-core-path")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-wow64-l1-1-1.dll"),
            Some("api-ms-win-core-wow64")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-security-base-l1-2-0.dll"),
            Some("api-ms-win-security-base")
        );
        assert_eq!(
            contract_hook_family("api-ms-win-core-crt-l1-1-0.dll"),
            Some("api-ms-win-core-crt")
        );
    }

    #[test]
    fn unmapped_contracts_remain_unmapped() {
        assert_eq!(
            contract_hook_family("api-ms-win-core-datetime-l1-1-0.dll"),
            None
        );
        assert_eq!(
            canonical_runtime_module_name("api-ms-win-core-datetime-l1-1-0.dll"),
            "api-ms-win-core-datetime-l1-1-0.dll"
        );
    }
}
