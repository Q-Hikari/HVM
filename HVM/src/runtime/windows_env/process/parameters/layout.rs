use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::runtime::windows_env) struct ProcessParametersOffsetGroup {
    pub length: usize,
    pub maximum_length: usize,
    pub current_directory: usize,
    pub dll_path: usize,
    pub image_path_name: usize,
    pub command_line: usize,
    pub environment: usize,
}

pub(in crate::runtime::windows_env) fn process_parameters_offsets_for_arch(
    arch: &'static ArchSpec,
) -> ProcessParametersOffsetGroup {
    if arch.is_x86() {
        ProcessParametersOffsetGroup {
            length: 0x04,
            maximum_length: 0x00,
            current_directory: 0x24,
            dll_path: 0x30,
            image_path_name: 0x38,
            command_line: 0x40,
            environment: 0x48,
        }
    } else {
        ProcessParametersOffsetGroup {
            length: 0x04,
            maximum_length: 0x00,
            current_directory: 0x38,
            dll_path: 0x50,
            image_path_name: 0x60,
            command_line: 0x70,
            environment: 0x80,
        }
    }
}
