use crate::hooks::registry::HookRegistry;
use crate::hooks::types::LogicalAbi;

static FUNCTIONS: &[(&str, LogicalAbi)] = &[
    ("ldap_openA", LogicalAbi::Cdecl),
    ("ldap_openW", LogicalAbi::Cdecl),
    ("ldap_initA", LogicalAbi::Cdecl),
    ("ldap_initW", LogicalAbi::Cdecl),
    ("ldap_sslinitA", LogicalAbi::Cdecl),
    ("ldap_sslinitW", LogicalAbi::Cdecl),
    ("ldap_connect", LogicalAbi::Cdecl),
    ("ldap_bindA", LogicalAbi::Cdecl),
    ("ldap_bindW", LogicalAbi::Cdecl),
    ("ldap_bind_sA", LogicalAbi::Cdecl),
    ("ldap_bind_sW", LogicalAbi::Cdecl),
    ("ldap_simple_bind_sA", LogicalAbi::Cdecl),
    ("ldap_simple_bind_sW", LogicalAbi::Cdecl),
    ("ldap_searchA", LogicalAbi::Cdecl),
    ("ldap_searchW", LogicalAbi::Cdecl),
    ("ldap_search_sA", LogicalAbi::Cdecl),
    ("ldap_search_sW", LogicalAbi::Cdecl),
    ("ldap_result", LogicalAbi::Cdecl),
    ("ldap_first_entry", LogicalAbi::Cdecl),
    ("ldap_next_entry", LogicalAbi::Cdecl),
    ("ldap_count_entries", LogicalAbi::Cdecl),
    ("ldap_get_dnA", LogicalAbi::Cdecl),
    ("ldap_get_dnW", LogicalAbi::Cdecl),
    ("ldap_get_valuesA", LogicalAbi::Cdecl),
    ("ldap_get_valuesW", LogicalAbi::Cdecl),
    ("ldap_get_values_lenA", LogicalAbi::Cdecl),
    ("ldap_get_values_lenW", LogicalAbi::Cdecl),
    ("ldap_count_valuesA", LogicalAbi::Cdecl),
    ("ldap_count_valuesW", LogicalAbi::Cdecl),
    ("ldap_count_values_len", LogicalAbi::Cdecl),
    ("ldap_value_freeA", LogicalAbi::Cdecl),
    ("ldap_value_freeW", LogicalAbi::Cdecl),
    ("ldap_value_free_len", LogicalAbi::Cdecl),
    ("ldap_msgfree", LogicalAbi::Cdecl),
    ("ldap_memfree", LogicalAbi::Cdecl),
    ("ldap_get_option", LogicalAbi::Cdecl),
    ("ldap_set_option", LogicalAbi::Cdecl),
    ("ldap_unbind", LogicalAbi::Cdecl),
    ("ldap_unbind_s", LogicalAbi::Cdecl),
];

/// Registers the generated hook definitions for this DLL family.
pub fn register_wldap32_hooks(registry: &mut HookRegistry) {
    registry.register_function_stubs("wldap32.dll", &FUNCTIONS);
}
