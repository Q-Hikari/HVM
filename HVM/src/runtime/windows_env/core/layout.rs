use crate::arch::ArchSpec;

pub(in crate::runtime::windows_env) const TEB_REGION_SIZE: u64 = 0x2000;
pub(in crate::runtime::windows_env) const PEB_REGION_SIZE: u64 = 0x2000;
// Recent APT-C-06 runs exceeded the previous caps by only a small amount.
// Keep a full-page headroom step per architecture so large import surfaces do
// not fail before the runtime reaches IAT resolution.
pub(in crate::runtime::windows_env) const LDR_REGION_SIZE_X86: u64 = 0x1_0000;
pub(in crate::runtime::windows_env) const LDR_REGION_SIZE_X64: u64 = 0x2_0000;
pub(in crate::runtime::windows_env) const PROCESS_PARAMETERS_REGION_SIZE: u64 = 0x2000;
pub(in crate::runtime::windows_env) const PROCESS_BUFFER_SIZE: u64 = 0x1000;
pub(in crate::runtime::windows_env) const ENVIRONMENT_W_BUFFER_SIZE: u64 = 0x4000;
pub(in crate::runtime::windows_env) const ENVIRONMENT_A_BUFFER_SIZE: u64 = 0x2000;
pub(in crate::runtime::windows_env) const GDT_REGION_SIZE: u64 = 0x1000;

pub(crate) fn ldr_region_size_for_arch(arch: &'static ArchSpec) -> u64 {
    if arch.is_x64() {
        LDR_REGION_SIZE_X64
    } else {
        LDR_REGION_SIZE_X86
    }
}

/// Mirrors the key base addresses of the Windows process environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessEnvironmentLayout {
    pub teb_base: u64,
    pub peb_base: u64,
    pub ldr_base: u64,
    pub process_parameters_base: u64,
    pub tls_slots_base: u64,
    pub tls_bitmap_base: u64,
    pub tls_bitmap_buffer: u64,
    pub image_path_buffer: u64,
    pub command_line_buffer: u64,
    pub command_line_ansi_buffer: u64,
    pub current_directory_buffer: u64,
    pub dll_path_buffer: u64,
    pub environment_w_buffer: u64,
    pub environment_a_buffer: u64,
    pub gdt_base: u64,
}

/// Exposes the offset constants needed by parity tests and future hook code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessEnvironmentOffsets {
    pub teb_exception_list: usize,
    pub teb_stack_base: usize,
    pub teb_stack_limit: usize,
    pub teb_self: usize,
    pub teb_client_id: usize,
    pub teb_tls_pointer: usize,
    pub teb_tls_slots: usize,
    pub teb_peb: usize,
    pub teb_last_error: usize,
    pub peb_being_debugged: usize,
    pub peb_image_base: usize,
    pub peb_ldr: usize,
    pub peb_process_parameters: usize,
    pub peb_process_heap: usize,
    pub peb_number_of_heaps: usize,
    pub peb_process_heaps: usize,
    pub peb_tls_bitmap: usize,
    pub peb_nt_global_flag: usize,
    pub process_parameters_length: usize,
    pub process_parameters_maximum_length: usize,
    pub process_parameters_current_directory: usize,
    pub process_parameters_dll_path: usize,
    pub process_parameters_image_path_name: usize,
    pub process_parameters_command_line: usize,
    pub process_parameters_environment: usize,
    pub ldr_length: u32,
    pub ldr_initialized: u64,
    pub ldr_in_load_order: u64,
    pub ldr_in_memory_order: u64,
    pub ldr_in_initialization_order: u64,
    pub ldr_entry_size: usize,
    pub ldr_entry_in_load_order: u64,
    pub ldr_entry_in_memory_order: u64,
    pub ldr_entry_in_initialization_order: u64,
    pub ldr_entry_dll_base: u64,
    pub ldr_entry_entry_point: u64,
    pub ldr_entry_size_of_image: u64,
    pub ldr_entry_full_dll_name: u64,
    pub ldr_entry_base_dll_name: u64,
    pub ldr_entry_flags: u64,
    pub ldr_entry_load_count: u64,
    pub ldr_entry_tls_index: u64,
    pub ldr_entry_hash_links: u64,
    pub ldr_entry_time_date_stamp: u64,
}
