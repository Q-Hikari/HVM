use super::*;

impl WindowsProcessEnvironment {
    pub(super) fn initialize_process_parameter_buffers(&mut self) {
        self.write_zeroes(self.layout.image_path_buffer, PROCESS_BUFFER_SIZE as usize);
        self.write_zeroes(
            self.layout.command_line_buffer,
            PROCESS_BUFFER_SIZE as usize,
        );
        self.write_zeroes(
            self.layout.command_line_ansi_buffer,
            PROCESS_BUFFER_SIZE as usize,
        );
        self.write_zeroes(
            self.layout.current_directory_buffer,
            PROCESS_BUFFER_SIZE as usize,
        );
        self.write_zeroes(self.layout.dll_path_buffer, PROCESS_BUFFER_SIZE as usize);
        self.write_zeroes(
            self.layout.environment_w_buffer,
            ENVIRONMENT_W_BUFFER_SIZE as usize,
        );
        self.write_zeroes(
            self.layout.environment_a_buffer,
            ENVIRONMENT_A_BUFFER_SIZE as usize,
        );
    }
}
