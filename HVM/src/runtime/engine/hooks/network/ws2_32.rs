use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_ws2_32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("ws2_32.dll", "WSAStartup") | ("ws2_32.dll", "ordinal_115") => true,
            ("ws2_32.dll", "WSACleanup") | ("ws2_32.dll", "ordinal_116") => true,
            ("ws2_32.dll", "WSAGetLastError") | ("ws2_32.dll", "ordinal_111") => true,
            ("ws2_32.dll", "WSASetLastError") | ("ws2_32.dll", "ordinal_112") => true,
            ("ws2_32.dll", "WSACreateEvent") => true,
            ("ws2_32.dll", "WSACloseEvent") => true,
            ("ws2_32.dll", "WSAResetEvent") => true,
            ("ws2_32.dll", "WSAWaitForMultipleEvents") => true,
            ("ws2_32.dll", "WSAIoctl") => true,
            ("ws2_32.dll", "socket")
            | ("ws2_32.dll", "ordinal_23")
            | ("ws2_32.dll", "WSASocketW")
            | ("ws2_32.dll", "ordinal_83") => true,
            ("ws2_32.dll", "closesocket") | ("ws2_32.dll", "ordinal_3") => true,
            ("ws2_32.dll", "bind") | ("ws2_32.dll", "ordinal_2") => true,
            ("ws2_32.dll", "connect") | ("ws2_32.dll", "ordinal_4") => true,
            ("ws2_32.dll", "listen") | ("ws2_32.dll", "ordinal_13") => true,
            ("ws2_32.dll", "accept") | ("ws2_32.dll", "ordinal_1") => true,
            ("ws2_32.dll", "getpeername") | ("ws2_32.dll", "ordinal_5") => true,
            ("ws2_32.dll", "getsockname") | ("ws2_32.dll", "ordinal_6") => true,
            ("ws2_32.dll", "send") | ("ws2_32.dll", "ordinal_19") => true,
            ("ws2_32.dll", "WSASend") | ("ws2_32.dll", "ordinal_76") => true,
            ("ws2_32.dll", "recv") | ("ws2_32.dll", "ordinal_16") => true,
            ("ws2_32.dll", "WSARecv") | ("ws2_32.dll", "ordinal_71") => true,
            ("ws2_32.dll", "sendto") | ("ws2_32.dll", "ordinal_20") => true,
            ("ws2_32.dll", "recvfrom") | ("ws2_32.dll", "ordinal_17") => true,
            ("ws2_32.dll", "shutdown") | ("ws2_32.dll", "ordinal_22") => true,
            ("ws2_32.dll", "select") | ("ws2_32.dll", "ordinal_18") => true,
            ("ws2_32.dll", "ioctlsocket") | ("ws2_32.dll", "ordinal_10") => true,
            ("ws2_32.dll", "setsockopt") | ("ws2_32.dll", "ordinal_21") => true,
            ("ws2_32.dll", "getsockopt") | ("ws2_32.dll", "ordinal_7") => true,
            ("ws2_32.dll", "htons") | ("ws2_32.dll", "ordinal_9") => true,
            ("ws2_32.dll", "ntohs") | ("ws2_32.dll", "ordinal_15") => true,
            ("ws2_32.dll", "htonl") | ("ws2_32.dll", "ordinal_8") => true,
            ("ws2_32.dll", "ntohl") | ("ws2_32.dll", "ordinal_14") => true,
            ("ws2_32.dll", "inet_addr") | ("ws2_32.dll", "ordinal_11") => true,
            ("ws2_32.dll", "inet_ntoa") | ("ws2_32.dll", "ordinal_12") => true,
            ("ws2_32.dll", "gethostbyaddr") | ("ws2_32.dll", "ordinal_51") => true,
            ("ws2_32.dll", "gethostbyname") | ("ws2_32.dll", "ordinal_52") => true,
            ("ws2_32.dll", "getprotobyname") | ("ws2_32.dll", "ordinal_53") => true,
            ("ws2_32.dll", "getservbyname") | ("ws2_32.dll", "ordinal_55") => true,
            ("ws2_32.dll", "getservbyport") | ("ws2_32.dll", "ordinal_56") => true,
            ("ws2_32.dll", "gethostname") | ("ws2_32.dll", "ordinal_57") => true,
            ("ws2_32.dll", "getaddrinfo") => true,
            ("ws2_32.dll", "freeaddrinfo") => true,
            ("ws2_32.dll", "WSAEnumNetworkEvents") => true,
            ("ws2_32.dll", "WSAEventSelect") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("ws2_32.dll", "WSAStartup") | ("ws2_32.dll", "ordinal_115") => {
                    let requested_version = arg(args, 0) as u16;
                    if arg(args, 1) != 0 {
                        let mut payload = vec![0u8; 400];
                        payload[0..2].copy_from_slice(&requested_version.to_le_bytes());
                        payload[2..4].copy_from_slice(&0x0202u16.to_le_bytes());
                        payload[4..4 + 20].copy_from_slice(b"WinSock 2.2 Sandbox\0");
                        payload[261..261 + 8].copy_from_slice(b"Running\0");
                        payload[390..392].copy_from_slice(&128u16.to_le_bytes());
                        payload[392..394].copy_from_slice(&1024u16.to_le_bytes());
                        self.modules.memory_mut().write(arg(args, 1), &payload)?;
                    }
                    self.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "WSACleanup") | ("ws2_32.dll", "ordinal_116") => {
                    self.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "WSAGetLastError") | ("ws2_32.dll", "ordinal_111") => {
                    Ok(self.network.last_error() as u64)
                }
                ("ws2_32.dll", "WSASetLastError") | ("ws2_32.dll", "ordinal_112") => {
                    self.network.set_last_error(arg(args, 0) as u32);
                    Ok(0)
                }
                ("ws2_32.dll", "WSACreateEvent") => {
                    let event = self
                        .scheduler
                        .create_event(true, false)
                        .ok_or(VmError::RuntimeInvariant("failed to create wsa event"))?;
                    Ok(event.handle as u64)
                }
                ("ws2_32.dll", "WSACloseEvent") => {
                    Ok(self.scheduler.reset_event(arg(args, 0) as u32).is_some() as u64)
                }
                ("ws2_32.dll", "WSAResetEvent") => {
                    let result = self.scheduler.reset_event(arg(args, 0) as u32).is_some() as u64;
                    self.network
                        .set_last_error(if result != 0 { 0 } else { 10038 });
                    Ok(result)
                }
                ("ws2_32.dll", "WSAWaitForMultipleEvents") => {
                    let count = (arg(args, 0) as usize).min(64);
                    let handles = self.read_wait_handles(count, arg(args, 1))?;
                    self.wait_for_objects(
                        &handles,
                        arg(args, 2) != 0,
                        arg(args, 3) as u32,
                        arg(args, 4) != 0,
                    )
                }
                ("ws2_32.dll", "WSAIoctl") => {
                    if arg(args, 6) != 0 {
                        self.write_u32(arg(args, 6), 0)?;
                    }
                    self.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "socket")
                | ("ws2_32.dll", "ordinal_23")
                | ("ws2_32.dll", "WSASocketW")
                | ("ws2_32.dll", "ordinal_83") => {
                    let handle = self.network.create_socket(
                        arg(args, 0) as i32,
                        arg(args, 1) as i32,
                        arg(args, 2) as i32,
                    );
                    let mut fields = Map::new();
                    fields.insert("socket".to_string(), json!(handle));
                    fields.insert("family".to_string(), json!(arg(args, 0)));
                    fields.insert("socket_type".to_string(), json!(arg(args, 1)));
                    fields.insert("protocol".to_string(), json!(arg(args, 2)));
                    self.log_runtime_event("SOCKET_CREATE", fields)?;
                    self.network.set_last_error(0);
                    Ok(handle as u64)
                }
                ("ws2_32.dll", "closesocket") | ("ws2_32.dll", "ordinal_3") => {
                    let handle = arg(args, 0) as u32;
                    let ok = self.network.close_socket(handle);
                    self.network.set_last_error(if ok { 0 } else { 10038 });
                    Ok(if ok { 0 } else { SOCKET_ERROR })
                }
                ("ws2_32.dll", "bind") | ("ws2_32.dll", "ordinal_2") => {
                    let handle = arg(args, 0) as u32;
                    let (host, port, _) =
                        self.read_sockaddr(arg(args, 1), arg(args, 2) as usize)?;
                    let ok = self.network.with_socket_mut(handle, |socket| {
                        socket.bound_address = Some((host.clone(), port));
                    });
                    if ok.is_some() {
                        self.network.set_last_error(0);
                        Ok(0)
                    } else {
                        self.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "connect") | ("ws2_32.dll", "ordinal_4") => {
                    let handle = arg(args, 0) as u32;
                    let (host, port, _) =
                        self.read_sockaddr(arg(args, 1), arg(args, 2) as usize)?;
                    let ok = self.network.with_socket_mut(handle, |socket| {
                        socket.connected = true;
                        socket.peer_address = Some((host.clone(), port));
                    });
                    if ok.is_some() {
                        let mut fields = Map::new();
                        fields.insert("socket".to_string(), json!(handle));
                        fields.insert("host".to_string(), json!(host));
                        fields.insert("port".to_string(), json!(port));
                        self.log_runtime_event("SOCKET_CONNECT", fields)?;
                        self.network.set_last_error(0);
                        Ok(0)
                    } else {
                        self.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "listen") | ("ws2_32.dll", "ordinal_13") => {
                    let handle = arg(args, 0) as u32;
                    let ok = self.network.with_socket_mut(handle, |socket| {
                        socket.listening = true;
                    });
                    if ok.is_some() {
                        self.network.set_last_error(0);
                        Ok(0)
                    } else {
                        self.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "accept") | ("ws2_32.dll", "ordinal_1") => {
                    let handle = arg(args, 0) as u32;
                    let Some(socket) = self.network.get_socket(handle) else {
                        self.network.set_last_error(10038);
                        return Ok(INVALID_SOCKET);
                    };
                    if !socket.listening {
                        self.network.set_last_error(10022);
                        return Ok(INVALID_SOCKET);
                    }
                    let accepted = self.network.create_socket(
                        socket.family,
                        socket.socket_type,
                        socket.protocol,
                    );
                    let _ = self.network.with_socket_mut(accepted, |new_socket| {
                        new_socket.connected = true;
                        new_socket.bound_address = socket.bound_address.clone();
                        new_socket.peer_address = Some(("127.0.0.1".to_string(), 0));
                    });
                    self.write_sockaddr(arg(args, 1), "127.0.0.1", 0)?;
                    if arg(args, 2) != 0 {
                        self.write_u32(arg(args, 2), 16)?;
                    }
                    self.network.set_last_error(0);
                    Ok(accepted as u64)
                }
                ("ws2_32.dll", "getpeername") | ("ws2_32.dll", "ordinal_5") => {
                    let handle = arg(args, 0) as u32;
                    let Some(socket) = self.network.get_socket(handle) else {
                        self.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    };
                    if arg(args, 2) != 0 {
                        self.write_u32(arg(args, 2), 16)?;
                    }
                    let (host, port) = socket
                        .peer_address
                        .unwrap_or_else(|| ("0.0.0.0".to_string(), 0));
                    self.write_sockaddr(arg(args, 1), &host, port)?;
                    self.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "getsockname") | ("ws2_32.dll", "ordinal_6") => {
                    let handle = arg(args, 0) as u32;
                    let Some(socket) = self.network.get_socket(handle) else {
                        self.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    };
                    if arg(args, 2) != 0 {
                        self.write_u32(arg(args, 2), 16)?;
                    }
                    let (host, port) = socket
                        .bound_address
                        .unwrap_or_else(|| ("0.0.0.0".to_string(), 0));
                    self.write_sockaddr(arg(args, 1), &host, port)?;
                    self.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "send") | ("ws2_32.dll", "ordinal_19") => {
                    let handle = arg(args, 0) as u32;
                    let length = arg(args, 2) as usize;
                    let data = if arg(args, 1) == 0 || length == 0 {
                        Vec::new()
                    } else {
                        self.read_bytes_from_memory(arg(args, 1), length)?
                    };
                    let ok = self.network.with_socket_mut(handle, |socket| {
                        socket.sent_data.push(data.clone());
                    });
                    if ok.is_some() {
                        let mut fields = Map::new();
                        fields.insert("socket".to_string(), json!(handle));
                        fields.insert("bytes".to_string(), json!(data.len()));
                        Self::add_payload_preview_field(&mut fields, &data);
                        self.log_runtime_event("SOCKET_SEND", fields)?;
                        self.network.set_last_error(0);
                        Ok(data.len() as u64)
                    } else {
                        self.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "WSASend") | ("ws2_32.dll", "ordinal_76") => {
                    let handle = arg(args, 0) as u32;
                    let buffer_count = arg(args, 2) as usize;
                    let data = self.read_wsabuf_payload(arg(args, 1), buffer_count)?;
                    let ok = self.network.with_socket_mut(handle, |socket| {
                        socket.sent_data.push(data.clone());
                    });
                    if let Some(()) = ok {
                        if arg(args, 3) != 0 {
                            self.write_u32(arg(args, 3), data.len().min(u32::MAX as usize) as u32)?;
                        }
                        let mut fields = Map::new();
                        fields.insert("socket".to_string(), json!(handle));
                        fields.insert("bytes".to_string(), json!(data.len()));
                        Self::add_payload_preview_field(&mut fields, &data);
                        self.log_runtime_event("SOCKET_SEND", fields)?;
                        self.network.set_last_error(0);
                        Ok(0)
                    } else {
                        if arg(args, 3) != 0 {
                            self.write_u32(arg(args, 3), 0)?;
                        }
                        self.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "recv") | ("ws2_32.dll", "ordinal_16") => {
                    let handle = arg(args, 0) as u32;
                    let length = arg(args, 2) as usize;
                    let Some(mut data) = self.network.with_socket_mut(handle, |socket| {
                        if socket.recv_queue.is_empty() {
                            Vec::new()
                        } else {
                            socket.recv_queue.remove(0)
                        }
                    }) else {
                        self.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    };
                    data.truncate(length);
                    if arg(args, 1) != 0 && !data.is_empty() {
                        self.modules.memory_mut().write(arg(args, 1), &data)?;
                    }
                    let mut fields = Map::new();
                    fields.insert("socket".to_string(), json!(handle));
                    fields.insert("bytes".to_string(), json!(data.len()));
                    self.log_runtime_event("SOCKET_RECV", fields)?;
                    self.network.set_last_error(0);
                    Ok(data.len() as u64)
                }
                ("ws2_32.dll", "WSARecv") | ("ws2_32.dll", "ordinal_71") => {
                    let handle = arg(args, 0) as u32;
                    let buffer_count = arg(args, 2) as usize;
                    let Some(data) = self.network.with_socket_mut(handle, |socket| {
                        if socket.recv_queue.is_empty() {
                            Vec::new()
                        } else {
                            socket.recv_queue.remove(0)
                        }
                    }) else {
                        if arg(args, 3) != 0 {
                            self.write_u32(arg(args, 3), 0)?;
                        }
                        self.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    };
                    let written = self.write_wsabuf_payload(arg(args, 1), buffer_count, &data)?;
                    if arg(args, 3) != 0 {
                        self.write_u32(arg(args, 3), written.min(u32::MAX as usize) as u32)?;
                    }
                    if arg(args, 4) != 0 {
                        self.write_u32(arg(args, 4), 0)?;
                    }
                    let mut fields = Map::new();
                    fields.insert("socket".to_string(), json!(handle));
                    fields.insert("bytes".to_string(), json!(written));
                    self.log_runtime_event("SOCKET_RECV", fields)?;
                    self.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "sendto") | ("ws2_32.dll", "ordinal_20") => {
                    let handle = arg(args, 0) as u32;
                    let length = arg(args, 2) as usize;
                    let data = if arg(args, 1) == 0 || length == 0 {
                        Vec::new()
                    } else {
                        self.read_bytes_from_memory(arg(args, 1), length)?
                    };
                    let (host, port, _) =
                        self.read_sockaddr(arg(args, 4), arg(args, 5) as usize)?;
                    let ok = self.network.with_socket_mut(handle, |socket| {
                        socket.peer_address = Some((host.clone(), port));
                        socket.sent_data.push(data.clone());
                    });
                    if ok.is_some() {
                        let mut fields = Map::new();
                        fields.insert("socket".to_string(), json!(handle));
                        fields.insert("host".to_string(), json!(host));
                        fields.insert("port".to_string(), json!(port));
                        fields.insert("bytes".to_string(), json!(data.len()));
                        Self::add_payload_preview_field(&mut fields, &data);
                        self.log_runtime_event("SOCKET_SEND", fields)?;
                        self.network.set_last_error(0);
                        Ok(data.len() as u64)
                    } else {
                        self.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "recvfrom") | ("ws2_32.dll", "ordinal_17") => {
                    let handle = arg(args, 0) as u32;
                    let length = arg(args, 2) as usize;
                    let Some((mut data, peer)) = self.network.with_socket_mut(handle, |socket| {
                        let payload = if socket.recv_queue.is_empty() {
                            Vec::new()
                        } else {
                            socket.recv_queue.remove(0)
                        };
                        (payload, socket.peer_address.clone())
                    }) else {
                        self.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    };
                    data.truncate(length);
                    if arg(args, 1) != 0 && !data.is_empty() {
                        self.modules.memory_mut().write(arg(args, 1), &data)?;
                    }
                    if let Some((host, port)) = peer {
                        self.write_sockaddr(arg(args, 4), &host, port)?;
                        if arg(args, 5) != 0 {
                            self.write_u32(arg(args, 5), 16)?;
                        }
                        let mut fields = Map::new();
                        fields.insert("socket".to_string(), json!(handle));
                        fields.insert("host".to_string(), json!(host));
                        fields.insert("port".to_string(), json!(port));
                        fields.insert("bytes".to_string(), json!(data.len()));
                        self.log_runtime_event("SOCKET_RECV", fields)?;
                    } else {
                        let mut fields = Map::new();
                        fields.insert("socket".to_string(), json!(handle));
                        fields.insert("bytes".to_string(), json!(data.len()));
                        self.log_runtime_event("SOCKET_RECV", fields)?;
                    }
                    self.network.set_last_error(0);
                    Ok(data.len() as u64)
                }
                ("ws2_32.dll", "shutdown") | ("ws2_32.dll", "ordinal_22") => {
                    let handle = arg(args, 0) as u32;
                    let ok = self.network.with_socket_mut(handle, |socket| {
                        socket.connected = false;
                    });
                    if ok.is_some() {
                        self.network.set_last_error(0);
                        Ok(0)
                    } else {
                        self.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "select") | ("ws2_32.dll", "ordinal_18") => {
                    let read_ready = self
                        .read_fd_set_handles(arg(args, 1))?
                        .into_iter()
                        .filter(|handle| {
                            self.network
                                .get_socket(*handle)
                                .map(|socket| !socket.recv_queue.is_empty())
                                .unwrap_or(false)
                        })
                        .collect::<Vec<_>>();
                    let write_ready = self
                        .read_fd_set_handles(arg(args, 2))?
                        .into_iter()
                        .filter(|handle| self.network.get_socket(*handle).is_some())
                        .collect::<Vec<_>>();
                    self.write_fd_set_handles(arg(args, 1), &read_ready)?;
                    self.write_fd_set_handles(arg(args, 2), &write_ready)?;
                    self.write_fd_set_handles(arg(args, 3), &[])?;
                    self.network.set_last_error(0);
                    Ok(read_ready
                        .iter()
                        .chain(write_ready.iter())
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .len() as u64)
                }
                ("ws2_32.dll", "ioctlsocket") | ("ws2_32.dll", "ordinal_10") => {
                    let handle = arg(args, 0) as u32;
                    let request = arg(args, 1);
                    let value = if arg(args, 2) != 0 {
                        self.read_u32(arg(args, 2))?
                    } else {
                        0
                    };
                    let ok = self.network.with_socket_mut(handle, |socket| {
                        if request == FIONBIO {
                            socket.blocking = value == 0;
                        }
                    });
                    if ok.is_some() {
                        self.network.set_last_error(0);
                        Ok(0)
                    } else {
                        self.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "setsockopt") | ("ws2_32.dll", "ordinal_21") => {
                    let ok = self.network.get_socket(arg(args, 0) as u32).is_some();
                    self.network.set_last_error(if ok { 0 } else { 10038 });
                    Ok(if ok { 0 } else { SOCKET_ERROR })
                }
                ("ws2_32.dll", "getsockopt") | ("ws2_32.dll", "ordinal_7") => {
                    if self.network.get_socket(arg(args, 0) as u32).is_none() {
                        self.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    }
                    if arg(args, 3) != 0 && arg(args, 4) != 0 {
                        let size = self.read_u32(arg(args, 4))? as usize;
                        let payload = vec![0u8; size.min(4)];
                        if !payload.is_empty() {
                            self.modules.memory_mut().write(arg(args, 3), &payload)?;
                        }
                        self.write_u32(arg(args, 4), payload.len() as u32)?;
                    }
                    self.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "htons") | ("ws2_32.dll", "ordinal_9") => {
                    Ok(u16::from_le_bytes((arg(args, 0) as u16).to_be_bytes()) as u64)
                }
                ("ws2_32.dll", "ntohs") | ("ws2_32.dll", "ordinal_15") => {
                    Ok(u16::from_le_bytes((arg(args, 0) as u16).to_be_bytes()) as u64)
                }
                ("ws2_32.dll", "htonl") | ("ws2_32.dll", "ordinal_8") => {
                    Ok(u32::from_le_bytes((arg(args, 0) as u32).to_be_bytes()) as u64)
                }
                ("ws2_32.dll", "ntohl") | ("ws2_32.dll", "ordinal_14") => {
                    Ok(u32::from_le_bytes((arg(args, 0) as u32).to_be_bytes()) as u64)
                }
                ("ws2_32.dll", "inet_addr") | ("ws2_32.dll", "ordinal_11") => {
                    let text = self.read_c_string_from_memory(arg(args, 0))?;
                    Ok(self
                        .resolve_ipv4_like_winsock(&text)
                        .map(|addr| u32::from_le_bytes(addr.octets()))
                        .unwrap_or(u32::MAX) as u64)
                }
                ("ws2_32.dll", "inet_ntoa") | ("ws2_32.dll", "ordinal_12") => {
                    let raw = (arg(args, 0) as u32).to_le_bytes();
                    let text = format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3]);
                    let buffer = self.ensure_inet_ntoa_buffer()?;
                    self.write_c_string_to_memory(buffer, 32, &text)?;
                    Ok(buffer)
                }
                ("ws2_32.dll", "gethostbyaddr") | ("ws2_32.dll", "ordinal_51") => {
                    let data = if arg(args, 0) != 0 && arg(args, 1) >= 4 {
                        self.read_bytes_from_memory(arg(args, 0), 4)?
                    } else {
                        vec![127, 0, 0, 1]
                    };
                    let ip = format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]);
                    Ok(self.create_hostent(&ip, &ip)?)
                }
                ("ws2_32.dll", "gethostbyname") | ("ws2_32.dll", "ordinal_52") => {
                    let name = self.read_c_string_from_memory(arg(args, 0))?;
                    let host_name = non_empty(&name).unwrap_or("localhost");
                    let resolved = self.synthetic_host_ipv4_text(host_name);
                    Ok(self.create_hostent(host_name, &resolved)?)
                }
                ("ws2_32.dll", "getprotobyname") | ("ws2_32.dll", "ordinal_53") => {
                    let name = self
                        .read_c_string_from_memory(arg(args, 0))?
                        .to_ascii_lowercase();
                    let protocol = match name.as_str() {
                        "udp" => 17,
                        "icmp" => 1,
                        _ => 6,
                    };
                    Ok(self
                        .create_protoent(if name.is_empty() { "tcp" } else { &name }, protocol)?)
                }
                ("ws2_32.dll", "getservbyname") | ("ws2_32.dll", "ordinal_55") => {
                    let name = self
                        .read_c_string_from_memory(arg(args, 0))?
                        .to_ascii_lowercase();
                    let protocol = self.read_c_string_from_memory(arg(args, 1))?;
                    let port = match name.as_str() {
                        "https" => 443,
                        "domain" => 53,
                        "smtp" => 25,
                        "pop3" => 110,
                        "imap" => 143,
                        "ftp" => 21,
                        _ => 80,
                    };
                    Ok(self.create_servent(
                        if name.is_empty() { "http" } else { &name },
                        non_empty(&protocol).unwrap_or("tcp"),
                        port,
                    )?)
                }
                ("ws2_32.dll", "getservbyport") | ("ws2_32.dll", "ordinal_56") => {
                    let host_order_port = u16::from_be(arg(args, 0) as u16);
                    let protocol = self.read_c_string_from_memory(arg(args, 1))?;
                    let name = match host_order_port {
                        443 => "https",
                        53 => "domain",
                        25 => "smtp",
                        110 => "pop3",
                        143 => "imap",
                        21 => "ftp",
                        _ => "http",
                    };
                    Ok(self.create_servent(
                        name,
                        non_empty(&protocol).unwrap_or("tcp"),
                        host_order_port,
                    )?)
                }
                ("ws2_32.dll", "gethostname") | ("ws2_32.dll", "ordinal_57") => {
                    let name = self.active_computer_name().to_string();
                    let capacity = arg(args, 1) as usize;
                    if arg(args, 0) == 0 || capacity == 0 {
                        self.network.set_last_error(10014);
                        return Ok(SOCKET_ERROR);
                    }
                    let _ = self.write_c_string_to_memory(arg(args, 0), capacity, &name)?;
                    self.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "getaddrinfo") => {
                    if arg(args, 3) == 0 {
                        self.network.set_last_error(11001);
                        return Ok(11001);
                    }
                    let node_name = self.read_c_string_from_memory(arg(args, 0))?;
                    let service_name = self.read_c_string_from_memory(arg(args, 1))?;
                    let addrinfo = self.create_addrinfo(&node_name, &service_name)?;
                    self.write_pointer_value(arg(args, 3), addrinfo)?;
                    self.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "freeaddrinfo") => Ok(0),
                ("ws2_32.dll", "WSAEnumNetworkEvents") => {
                    if self.network.get_socket(arg(args, 0) as u32).is_none() {
                        self.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    }
                    if arg(args, 1) != 0 {
                        let _ = self.scheduler.reset_event(arg(args, 1) as u32);
                    }
                    if arg(args, 2) != 0 {
                        self.modules.memory_mut().write(arg(args, 2), &[0u8; 44])?;
                    }
                    self.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "WSAEventSelect") => {
                    let socket_ok = self.network.get_socket(arg(args, 0) as u32).is_some();
                    let event_ok = arg(args, 1) == 0
                        || self.scheduler.reset_event(arg(args, 1) as u32).is_some();
                    let ok = socket_ok && event_ok;
                    self.network.set_last_error(if ok { 0 } else { 10038 });
                    Ok(if ok { 0 } else { SOCKET_ERROR })
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
