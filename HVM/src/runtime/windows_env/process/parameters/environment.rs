use super::*;

impl WindowsProcessEnvironment {
    pub(crate) fn write_environment_blocks_from_entries(
        &mut self,
        entries: &[(String, String)],
    ) -> Result<(), MemoryError> {
        let wide = build_wide_environment_block(entries);
        let ansi = build_ansi_environment_block(entries);

        if wide.len() > ENVIRONMENT_W_BUFFER_SIZE as usize
            || ansi.len() > ENVIRONMENT_A_BUFFER_SIZE as usize
        {
            return Err(MemoryError::OutOfMemory {
                size: wide.len().max(ansi.len()) as u64,
            });
        }

        self.write_zeroes(
            self.layout.environment_w_buffer,
            ENVIRONMENT_W_BUFFER_SIZE as usize,
        );
        self.write_zeroes(
            self.layout.environment_a_buffer,
            ENVIRONMENT_A_BUFFER_SIZE as usize,
        );
        self.write_bytes(self.layout.environment_w_buffer, &wide);
        self.write_bytes(self.layout.environment_a_buffer, &ansi);
        Ok(())
    }
}

fn build_wide_environment_block(entries: &[(String, String)]) -> Vec<u8> {
    let mut wide = Vec::new();
    for (name, value) in entries {
        for word in format!("{name}={value}").encode_utf16() {
            wide.extend_from_slice(&word.to_le_bytes());
        }
        wide.extend_from_slice(&[0, 0]);
    }
    wide.extend_from_slice(&[0, 0]);
    wide
}

fn build_ansi_environment_block(entries: &[(String, String)]) -> Vec<u8> {
    let mut ansi = Vec::new();
    for (name, value) in entries {
        for byte in format!("{name}={value}")
            .chars()
            .map(ascii_or_question_mark)
        {
            ansi.push(byte);
        }
        ansi.push(0);
    }
    ansi.push(0);
    ansi
}

fn ascii_or_question_mark(ch: char) -> u8 {
    if ch.is_ascii() {
        ch as u8
    } else {
        b'?'
    }
}
