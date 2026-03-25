use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_combase_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("combase.dll", "CoInitializeEx") => true,
            ("combase.dll", "CoUninitialize") => true,
            ("combase.dll", "CoCreateInstance") | ("combase.dll", "CoGetClassObject") => true,
            ("combase.dll", "CoCreateGuid") => true,
            ("combase.dll", "CoTaskMemRealloc") => true,
            ("combase.dll", "StringFromGUID2") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("combase.dll", "CoInitializeEx") => self.dispatch_com_initialize(),
                ("combase.dll", "CoUninitialize") => self.dispatch_com_uninitialize(),
                ("combase.dll", "CoCreateInstance") | ("combase.dll", "CoGetClassObject") => {
                    self.dispatch_com_activation_not_registered(arg(args, 4))
                }
                ("combase.dll", "CoCreateGuid") => self.dispatch_com_create_guid(arg(args, 0)),
                ("combase.dll", "CoTaskMemRealloc") => {
                    self.dispatch_com_task_mem_realloc(arg(args, 0), arg(args, 1))
                }
                ("combase.dll", "StringFromGUID2") => {
                    let guid = self.read_guid_bytes_le_or_zero(arg(args, 0))?;
                    let text = Self::format_guid_bytes_le(&guid);
                    let mut encoded = text
                        .encode_utf16()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<_>>();
                    encoded.extend_from_slice(&[0, 0]);
                    let max_chars = arg(args, 2) as usize;
                    if arg(args, 1) != 0 && max_chars != 0 {
                        let _ =
                            self.write_raw_bytes_to_memory(arg(args, 1), max_chars * 2, &encoded)?;
                    }
                    Ok((text.len() + 1).min(max_chars) as u64)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
