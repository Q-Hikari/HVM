use crate::arch::ArchSpec;

use super::*;

impl WindowsProcessEnvironment {
    pub(super) fn offsets_for_arch(arch: &'static ArchSpec) -> ProcessEnvironmentOffsets {
        let teb = super::super::thread::layout::teb_offsets_for_arch(arch);
        let peb = super::super::process::peb::peb_offsets_for_arch(arch);
        let params =
            super::super::process::parameters::layout::process_parameters_offsets_for_arch(arch);

        let ldr_header = if arch.is_x86() {
            (0x30u32, 0x04u64, 0x0Cu64, 0x14u64, 0x1Cu64)
        } else {
            (0x58u32, 0x04u64, 0x10u64, 0x20u64, 0x30u64)
        };
        let ldr_entry = if arch.is_x86() {
            (
                0x48usize, 0x00u64, 0x08u64, 0x10u64, 0x18u64, 0x1Cu64, 0x20u64, 0x24u64, 0x2Cu64,
                0x34u64, 0x38u64, 0x3Au64, 0x3Cu64, 0x44u64,
            )
        } else {
            (
                0x100usize, 0x00u64, 0x10u64, 0x20u64, 0x30u64, 0x38u64, 0x40u64, 0x48u64, 0x58u64,
                0x68u64, 0x6Cu64, 0x6Eu64, 0x70u64, 0x80u64,
            )
        };

        ProcessEnvironmentOffsets {
            teb_exception_list: teb.exception_list,
            teb_stack_base: teb.stack_base,
            teb_stack_limit: teb.stack_limit,
            teb_self: teb.self_pointer,
            teb_client_id: teb.client_id,
            teb_tls_pointer: teb.tls_pointer,
            teb_tls_slots: teb.tls_slots,
            teb_peb: teb.peb,
            teb_last_error: teb.last_error,
            peb_being_debugged: peb.being_debugged,
            peb_image_base: peb.image_base,
            peb_ldr: peb.ldr,
            peb_process_parameters: peb.process_parameters,
            peb_process_heap: peb.process_heap,
            peb_number_of_heaps: peb.number_of_heaps,
            peb_process_heaps: peb.process_heaps,
            peb_tls_bitmap: peb.tls_bitmap,
            peb_nt_global_flag: peb.nt_global_flag,
            process_parameters_length: params.length,
            process_parameters_maximum_length: params.maximum_length,
            process_parameters_current_directory: params.current_directory,
            process_parameters_dll_path: params.dll_path,
            process_parameters_image_path_name: params.image_path_name,
            process_parameters_command_line: params.command_line,
            process_parameters_environment: params.environment,
            ldr_length: ldr_header.0,
            ldr_initialized: ldr_header.1,
            ldr_in_load_order: ldr_header.2,
            ldr_in_memory_order: ldr_header.3,
            ldr_in_initialization_order: ldr_header.4,
            ldr_entry_size: ldr_entry.0,
            ldr_entry_in_load_order: ldr_entry.1,
            ldr_entry_in_memory_order: ldr_entry.2,
            ldr_entry_in_initialization_order: ldr_entry.3,
            ldr_entry_dll_base: ldr_entry.4,
            ldr_entry_entry_point: ldr_entry.5,
            ldr_entry_size_of_image: ldr_entry.6,
            ldr_entry_full_dll_name: ldr_entry.7,
            ldr_entry_base_dll_name: ldr_entry.8,
            ldr_entry_flags: ldr_entry.9,
            ldr_entry_load_count: ldr_entry.10,
            ldr_entry_tls_index: ldr_entry.11,
            ldr_entry_hash_links: ldr_entry.12,
            ldr_entry_time_date_stamp: ldr_entry.13,
        }
    }
}
