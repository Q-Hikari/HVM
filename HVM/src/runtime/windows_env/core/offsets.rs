use crate::arch::ArchSpec;

use super::*;

impl WindowsProcessEnvironment {
    pub(super) fn offsets_for_arch(arch: &'static ArchSpec) -> ProcessEnvironmentOffsets {
        let teb = super::super::thread::layout::teb_offsets_for_arch(arch);
        let peb = super::super::process::peb::peb_offsets_for_arch(arch);
        let params =
            super::super::process::parameters::layout::process_parameters_offsets_for_arch(arch);

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
            peb_image_base: peb.image_base,
            peb_ldr: peb.ldr,
            peb_process_parameters: peb.process_parameters,
            peb_tls_bitmap: peb.tls_bitmap,
            process_parameters_length: params.length,
            process_parameters_maximum_length: params.maximum_length,
            process_parameters_current_directory: params.current_directory,
            process_parameters_dll_path: params.dll_path,
            process_parameters_image_path_name: params.image_path_name,
            process_parameters_command_line: params.command_line,
            process_parameters_environment: params.environment,
        }
    }
}
