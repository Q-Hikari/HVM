use std::io::Read;

use flate2::read::{DeflateDecoder, ZlibDecoder};

use super::*;

const COMPRESS_ALGORITHM_INVALID: u32 = 0;
const COMPRESS_ALGORITHM_MSZIP: u32 = 2;
const CABINET_DECOMPRESSOR_MAGIC: u32 = 0x504D_4344;
const ERROR_INVALID_DATA: u32 = 13;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_cabinet_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("cabinet.dll", "CreateDecompressor") => true,
            ("cabinet.dll", "SetDecompressorInformation") => true,
            ("cabinet.dll", "QueryDecompressorInformation") => true,
            ("cabinet.dll", "Decompress") => true,
            ("cabinet.dll", "ResetDecompressor") => true,
            ("cabinet.dll", "CloseDecompressor") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match function {
                "CreateDecompressor" => {
                    self.cabinet_create_decompressor(ctx.raw(0) as u32, ctx.raw(2))
                }
                "SetDecompressorInformation" | "QueryDecompressorInformation" => Ok(1),
                "Decompress" => self.cabinet_decompress(
                    ctx.raw(0),
                    ctx.raw(1),
                    ctx.raw(2) as usize,
                    ctx.raw(3),
                    ctx.raw(4) as usize,
                    ctx.raw(5),
                ),
                "ResetDecompressor" => self.cabinet_reset_decompressor(ctx.raw(0)),
                "CloseDecompressor" => self.cabinet_close_decompressor(ctx.raw(0)),
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }

    fn cabinet_create_decompressor(
        &mut self,
        algorithm: u32,
        handle_out: u64,
    ) -> Result<u64, VmError> {
        if handle_out == 0 || algorithm == COMPRESS_ALGORITHM_INVALID {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let state = self.alloc_process_heap_block(0x20, "cabinet:decompressor")?;
        self.write_u32(state, CABINET_DECOMPRESSOR_MAGIC)?;
        self.write_u32(state + 4, algorithm)?;
        self.write_pointer_value(handle_out, state)?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn cabinet_reset_decompressor(&mut self, handle: u64) -> Result<u64, VmError> {
        if !self.cabinet_validate_decompressor_handle(handle)? {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn cabinet_close_decompressor(&mut self, handle: u64) -> Result<u64, VmError> {
        if !self.cabinet_validate_decompressor_handle(handle)? {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(0);
        }
        self.core.modules.memory_mut().write(handle, &[0u8; 8])?;
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn cabinet_decompress(
        &mut self,
        handle: u64,
        source: u64,
        source_len: usize,
        destination: u64,
        destination_len: usize,
        bytes_written_out: u64,
    ) -> Result<u64, VmError> {
        if !self.cabinet_validate_decompressor_handle(handle)?
            || source == 0
            || destination == 0
            || destination_len == 0
        {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(0);
        }

        let algorithm = self.read_u32(handle + 4)?;
        let source_bytes = self.read_bytes_from_memory(source, source_len)?;
        let Some(decoded) = Self::cabinet_try_decompress(algorithm, &source_bytes) else {
            self.set_last_error(ERROR_INVALID_DATA);
            return Ok(0);
        };
        if decoded.len() > destination_len {
            self.set_last_error(ERROR_INSUFFICIENT_BUFFER as u32);
            return Ok(0);
        }

        self.core
            .modules
            .memory_mut()
            .write(destination, &decoded)?;
        if bytes_written_out != 0 {
            self.write_pointer_value(bytes_written_out, decoded.len() as u64)?;
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(1)
    }

    fn cabinet_validate_decompressor_handle(&self, handle: u64) -> Result<bool, VmError> {
        if handle == 0 {
            return Ok(false);
        }
        Ok(self.read_u32(handle).ok() == Some(CABINET_DECOMPRESSOR_MAGIC))
    }

    fn cabinet_try_decompress(algorithm: u32, source: &[u8]) -> Option<Vec<u8>> {
        if algorithm != COMPRESS_ALGORITHM_MSZIP || source.is_empty() {
            return None;
        }

        for candidate in [source.strip_prefix(b"CK").unwrap_or(source), source] {
            if let Some(decoded) = Self::cabinet_decode_deflate(candidate) {
                return Some(decoded);
            }
            if let Some(decoded) = Self::cabinet_decode_zlib(candidate) {
                return Some(decoded);
            }
        }
        None
    }

    fn cabinet_decode_deflate(source: &[u8]) -> Option<Vec<u8>> {
        let mut decoder = DeflateDecoder::new(source);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).ok()?;
        Some(decoded)
    }

    fn cabinet_decode_zlib(source: &[u8]) -> Option<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(source);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).ok()?;
        Some(decoded)
    }
}
