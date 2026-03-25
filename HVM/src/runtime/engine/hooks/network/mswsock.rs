use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_mswsock_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("mswsock.dll", "TransmitFile") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("mswsock.dll", "TransmitFile") => {
                    let socket_handle = arg(args, 0) as u32;
                    if self.network.get_socket(socket_handle).is_none() {
                        self.network.set_last_error(10038);
                        return Ok(0);
                    }
                    let file_handle = arg(args, 1) as u32;
                    let mut transmitted = Vec::new();
                    if let Some(state) = self.file_handles.get_mut(&file_handle) {
                        let current = state.file.stream_position().unwrap_or(0);
                        let file_len = state
                            .file
                            .metadata()
                            .map(|meta| meta.len())
                            .unwrap_or(current);
                        let remaining = file_len.saturating_sub(current) as usize;
                        let requested = arg(args, 2) as usize;
                        let read_len = if requested == 0 {
                            remaining.min(0x10000)
                        } else {
                            remaining.min(requested)
                        };
                        if read_len != 0 {
                            transmitted.resize(read_len, 0);
                            let bytes_read = state.file.read(&mut transmitted).unwrap_or(0);
                            transmitted.truncate(bytes_read);
                        }
                    } else {
                        self.network.set_last_error(10038);
                        return Ok(0);
                    }
                    let peer = self.network.with_socket_mut(socket_handle, |socket| {
                        socket.sent_data.push(transmitted.clone());
                        socket.peer_address.clone()
                    });
                    let mut fields = Map::new();
                    fields.insert("socket".to_string(), json!(socket_handle));
                    fields.insert("bytes".to_string(), json!(transmitted.len()));
                    fields.insert("source".to_string(), json!("TransmitFile"));
                    if let Some(Some((host, port))) = peer {
                        fields.insert("host".to_string(), json!(host));
                        fields.insert("port".to_string(), json!(port));
                    }
                    Self::add_payload_preview_field(&mut fields, &transmitted);
                    self.log_runtime_event("SOCKET_SEND", fields)?;
                    self.network.set_last_error(0);
                    Ok(1)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
