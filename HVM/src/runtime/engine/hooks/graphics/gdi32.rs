use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_gdi32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("gdi32.dll", "GetDeviceCaps") => true,
            ("gdi32.dll", "DeleteObject") => true,
            ("gdi32.dll", "CreateSolidBrush")
            | ("gdi32.dll", "CreatePen")
            | ("gdi32.dll", "CreateFontIndirectW") => true,
            ("gdi32.dll", "SelectObject") => true,
            ("gdi32.dll", "EnumFontFamiliesW") => true,
            ("gdi32.dll", "GetStockObject") => true,
            ("gdi32.dll", "GetObjectW") => true,
            ("gdi32.dll", "GetTextCharsetInfo") => true,
            ("gdi32.dll", "GetTextMetricsW") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("gdi32.dll", "GetDeviceCaps") => Ok(match arg(args, 1) as i32 {
                    8 => 1,
                    10 => 96,
                    12 => 32,
                    88 => 24,
                    90 => 1920,
                    117 => 1080,
                    118 => 1,
                    _ => 1,
                }),
                ("gdi32.dll", "DeleteObject") => Ok(1),
                ("gdi32.dll", "CreateSolidBrush")
                | ("gdi32.dll", "CreatePen")
                | ("gdi32.dll", "CreateFontIndirectW") => Ok(self.allocate_object_handle() as u64),
                ("gdi32.dll", "SelectObject") => Ok(arg(args, 1).max(1)),
                ("gdi32.dll", "EnumFontFamiliesW") => Ok(1),
                ("gdi32.dll", "GetStockObject") => {
                    Ok(0x40000 + (arg(args, 0) as u32).saturating_mul(4) as u64)
                }
                ("gdi32.dll", "GetObjectW") => {
                    let size = arg(args, 1) as usize;
                    if arg(args, 2) != 0 && size != 0 {
                        self.modules
                            .memory_mut()
                            .write(arg(args, 2), &vec![0u8; size])?;
                    }
                    Ok(size.min(64) as u64)
                }
                ("gdi32.dll", "GetTextCharsetInfo") => {
                    if arg(args, 1) != 0 {
                        self.modules.memory_mut().write(arg(args, 1), &[0u8; 32])?;
                    }
                    Ok(1)
                }
                ("gdi32.dll", "GetTextMetricsW") => {
                    if arg(args, 1) != 0 {
                        let mut metrics = vec![0u8; 60];
                        metrics[0..4].copy_from_slice(&16u32.to_le_bytes());
                        metrics[4..8].copy_from_slice(&12u32.to_le_bytes());
                        metrics[20..24].copy_from_slice(&8u32.to_le_bytes());
                        self.modules.memory_mut().write(arg(args, 1), &metrics)?;
                    }
                    Ok(1)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
