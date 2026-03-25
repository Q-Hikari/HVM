use super::*;

mod environment;
pub(in crate::runtime::windows_env) mod layout;
mod strings;

impl WindowsProcessEnvironment {
    /// Mirrors the effective command line and current directory into stable UTF-16 buffers.
    pub fn configure_process_parameters(
        &mut self,
        command_line: &str,
        current_directory: &str,
    ) -> Result<(), MemoryError> {
        self.configure_process_parameters_with_image_path(
            command_line,
            command_line,
            current_directory,
        )
    }

    /// Mirrors the effective image path, command line, and current directory into process parameters.
    pub fn configure_process_parameters_with_image_path(
        &mut self,
        image_path: &str,
        command_line: &str,
        current_directory: &str,
    ) -> Result<(), MemoryError> {
        self.configure_process_parameters_with_runtime_details(
            image_path,
            command_line,
            current_directory,
            r"C:\Windows\System32",
            r".\hikari\output",
        )
    }

    /// Mirrors the runtime image path, command line, current directory, DLL path, and environment.
    pub fn configure_process_parameters_with_runtime_details(
        &mut self,
        image_path: &str,
        command_line: &str,
        current_directory: &str,
        dll_path: &str,
        tmp_directory: &str,
    ) -> Result<(), MemoryError> {
        let environment = vec![
            ("PATH".to_string(), dll_path.to_string()),
            ("TMP".to_string(), tmp_directory.to_string()),
            ("TEMP".to_string(), tmp_directory.to_string()),
        ];
        self.configure_process_parameters_with_runtime_details_and_environment(
            image_path,
            command_line,
            current_directory,
            dll_path,
            &environment,
        )
    }

    /// Mirrors the runtime image path, command line, current directory, DLL path, and environment.
    pub fn configure_process_parameters_with_runtime_details_and_environment(
        &mut self,
        image_path: &str,
        command_line: &str,
        current_directory: &str,
        dll_path: &str,
        environment: &[(String, String)],
    ) -> Result<(), MemoryError> {
        self.write_wide_process_parameter(
            self.layout.image_path_buffer,
            self.offsets.process_parameters_image_path_name,
            image_path,
        )?;
        self.write_wide_process_parameter(
            self.layout.command_line_buffer,
            self.offsets.process_parameters_command_line,
            command_line,
        )?;
        self.write_ansi_string(self.layout.command_line_ansi_buffer, command_line)?;
        self.write_curdir(current_directory)?;
        self.write_wide_process_parameter(
            self.layout.dll_path_buffer,
            self.offsets.process_parameters_dll_path,
            dll_path,
        )?;
        self.write_environment_blocks_from_entries(environment)?;
        self.write_pointer(
            self.layout.process_parameters_base
                + self.offsets.process_parameters_environment as u64,
            self.layout.environment_w_buffer,
        );
        self.write_process_parameters_metadata();
        Ok(())
    }

    /// Updates the mirrored current-directory buffer in place.
    pub fn set_current_directory(&mut self, current_directory: &str) -> Result<(), MemoryError> {
        self.write_curdir(current_directory)
    }
}
