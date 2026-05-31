use super::*;

impl VirtualExecutionEngine {
    fn parse_raw_http_request(bytes: &[u8]) -> Option<(String, String, Option<String>)> {
        let text = std::str::from_utf8(bytes).ok()?;
        let header_end = text.find("\r\n\r\n").map(|index| index + 4)?;
        let header_block = &text[..header_end];
        let mut lines = header_block.split("\r\n");
        let request_line = lines.next()?.trim();
        let mut parts = request_line.split_whitespace();
        let verb = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        let host = lines.find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("host")
                .then(|| value.trim().to_string())
        });
        Some((verb, path, host))
    }

    fn raw_socket_request_route(&self, handle: u32) -> Option<(String, String, String, usize)> {
        let socket = self.network_state.network.get_socket(handle)?;
        if socket.sent_data_consumed >= socket.sent_data.len() {
            return None;
        }
        let peer_host = socket
            .peer_address
            .as_ref()
            .map(|(host, _)| host.clone())
            .unwrap_or_default();
        let default_host = self
            .network_state
            .dns
            .reverse(&peer_host)
            .cloned()
            .unwrap_or(peer_host);
        for (index, payload) in socket
            .sent_data
            .iter()
            .enumerate()
            .skip(socket.sent_data_consumed)
        {
            if let Some((verb, path, host_override)) = Self::parse_raw_http_request(payload) {
                let host = host_override.unwrap_or_else(|| default_host.clone());
                return Some((host, path, verb, index));
            }
        }
        if socket.sent_data_consumed == socket.sent_data.len() {
            return None;
        }
        let has_generic_rule = self.core.config.http_response_rules.iter().any(|rule| {
            rule.path.as_deref().is_none_or(str::is_empty)
                && rule.verb.as_deref().is_none_or(str::is_empty)
        });
        has_generic_rule.then(|| {
            (
                default_host,
                "/".to_string(),
                "GET".to_string(),
                socket.sent_data_consumed,
            )
        })
    }

    fn signal_socket_event_if_ready(&mut self, handle: u32) {
        let has_read_data = self
            .network_state
            .network
            .get_socket(handle)
            .map(|socket| !socket.recv_queue.is_empty())
            .unwrap_or(false);
        if !has_read_data {
            return;
        }
        let Some(mask) = self.network_state.socket_event_masks.get(&handle).copied() else {
            return;
        };
        if mask & 0x0001 == 0 {
            return;
        }
        let Some(event_handle) = self
            .network_state
            .socket_event_handles
            .get(&handle)
            .copied()
        else {
            return;
        };
        let _ = self.core.scheduler.set_event(event_handle);
    }

    fn take_socket_recv_data(
        &mut self,
        handle: u32,
        length: usize,
    ) -> Option<(Vec<u8>, Option<(String, u16)>)> {
        self.network_state
            .network
            .with_socket_mut(handle, |socket| {
                let peer = socket.peer_address.clone();
                if length == 0 || socket.recv_queue.is_empty() {
                    return (Vec::new(), peer);
                }
                let mut chunk = socket.recv_queue.remove(0);
                if chunk.len() > length {
                    let remainder = chunk.split_off(length);
                    socket.recv_queue.insert(0, remainder);
                }
                (chunk, peer)
            })
    }

    fn inject_raw_socket_http_response_if_ready(&mut self, handle: u32) -> Result<bool, VmError> {
        let Some(socket) = self.network_state.network.get_socket(handle) else {
            return Ok(false);
        };
        if !socket.recv_queue.is_empty() || self.core.config.http_response_rules.is_empty() {
            return Ok(false);
        }
        let Some((host, path, verb, consumed_index)) = self.raw_socket_request_route(handle) else {
            return Ok(false);
        };
        let Some((rule_index, rule)) = self
            .core
            .config
            .http_response_rule_with_index_for(&host, &path, &verb)
        else {
            return Ok(false);
        };
        let match_count = self
            .network_state
            .http_response_rule_hits
            .get(&rule_index)
            .copied()
            .unwrap_or(0);
        let response_index = (match_count as usize).min(rule.responses.len().saturating_sub(1));
        let response = rule.responses[response_index].clone();
        self.network_state
            .http_response_rule_hits
            .insert(rule_index, match_count.saturating_add(1));
        let status_code = response.status_code;
        let body = response.body;
        let mut raw_response =
            Self::build_http_response_headers(status_code, &response.headers, body.len());
        let body_len = body.len();
        raw_response.extend_from_slice(&body);
        let queued = self
            .network_state
            .network
            .with_socket_mut(handle, |socket| {
                socket.recv_queue.push(raw_response);
                socket.sent_data_consumed = consumed_index.saturating_add(1);
            })
            .is_some();
        if !queued {
            return Ok(false);
        }
        let mut fields = Map::new();
        fields.insert("handle".to_string(), json!(handle));
        fields.insert("host".to_string(), json!(host));
        fields.insert("path".to_string(), json!(path));
        fields.insert("verb".to_string(), json!(verb));
        fields.insert("rule_index".to_string(), json!(rule_index));
        fields.insert("match_count".to_string(), json!(match_count));
        fields.insert("response_index".to_string(), json!(response_index));
        fields.insert("status_code".to_string(), json!(status_code));
        fields.insert("body_len".to_string(), json!(body_len));
        self.log_runtime_event("HTTP_RESPONSE_RULE", fields)?;
        self.signal_socket_event_if_ready(handle);
        Ok(true)
    }

    fn ensure_raw_socket_read_ready(&mut self, handle: u32) -> Result<bool, VmError> {
        let injected = self.inject_raw_socket_http_response_if_ready(handle)?;
        let ready = self
            .network_state
            .network
            .get_socket(handle)
            .map(|socket| !socket.recv_queue.is_empty())
            .unwrap_or(false);
        if ready || injected {
            self.signal_socket_event_if_ready(handle);
        }
        Ok(ready)
    }
    pub(in crate::runtime::engine) fn dispatch_ws2_32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
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
            ("ws2_32.dll", "inet_ntop") => true,
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
                    let requested_version = ctx.raw(0) as u16;
                    if ctx.raw(1) != 0 {
                        let mut payload = vec![0u8; 400];
                        payload[0..2].copy_from_slice(&requested_version.to_le_bytes());
                        payload[2..4].copy_from_slice(&0x0202u16.to_le_bytes());
                        payload[4..4 + 20].copy_from_slice(b"WinSock 2.2 Sandbox\0");
                        payload[261..261 + 8].copy_from_slice(b"Running\0");
                        payload[390..392].copy_from_slice(&128u16.to_le_bytes());
                        payload[392..394].copy_from_slice(&1024u16.to_le_bytes());
                        self.core.modules.memory_mut().write(ctx.raw(1), &payload)?;
                    }
                    self.network_state.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "WSACleanup") | ("ws2_32.dll", "ordinal_116") => {
                    self.network_state.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "WSAGetLastError") | ("ws2_32.dll", "ordinal_111") => {
                    Ok(self.network_state.network.last_error() as u64)
                }
                ("ws2_32.dll", "WSASetLastError") | ("ws2_32.dll", "ordinal_112") => {
                    self.network_state.network.set_last_error(ctx.raw(0) as u32);
                    Ok(0)
                }
                ("ws2_32.dll", "WSACreateEvent") => {
                    let event = self
                        .core
                        .scheduler
                        .create_event(true, false)
                        .ok_or(VmError::RuntimeInvariant("failed to create wsa event"))?;
                    Ok(event.handle as u64)
                }
                ("ws2_32.dll", "WSACloseEvent") => {
                    Ok(self.core.scheduler.reset_event(ctx.raw(0) as u32).is_some() as u64)
                }
                ("ws2_32.dll", "WSAResetEvent") => {
                    let result =
                        self.core.scheduler.reset_event(ctx.raw(0) as u32).is_some() as u64;
                    self.network_state
                        .network
                        .set_last_error(if result != 0 { 0 } else { 10038 });
                    Ok(result)
                }
                ("ws2_32.dll", "WSAWaitForMultipleEvents") => {
                    let count = (ctx.raw(0) as usize).min(64);
                    let handles = self.read_wait_handles(count, ctx.raw(1))?;
                    self.wait_for_objects(
                        &handles,
                        ctx.raw(2) != 0,
                        ctx.raw(3) as u32,
                        ctx.raw(4) != 0,
                    )
                }
                ("ws2_32.dll", "WSAIoctl") => {
                    if ctx.raw(6) != 0 {
                        self.write_u32(ctx.raw(6), 0)?;
                    }
                    self.network_state.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "socket")
                | ("ws2_32.dll", "ordinal_23")
                | ("ws2_32.dll", "WSASocketW")
                | ("ws2_32.dll", "ordinal_83") => {
                    let handle = self.network_state.network.create_socket(
                        ctx.raw(0) as i32,
                        ctx.raw(1) as i32,
                        ctx.raw(2) as i32,
                    );
                    let mut fields = Map::new();
                    fields.insert("socket".to_string(), json!(handle));
                    fields.insert("family".to_string(), json!(ctx.raw(0)));
                    fields.insert("socket_type".to_string(), json!(ctx.raw(1)));
                    fields.insert("protocol".to_string(), json!(ctx.raw(2)));
                    self.log_runtime_event("SOCKET_CREATE", fields)?;
                    self.network_state.network.set_last_error(0);
                    Ok(handle as u64)
                }
                ("ws2_32.dll", "closesocket") | ("ws2_32.dll", "ordinal_3") => {
                    let handle = ctx.raw(0) as u32;
                    let ok = self.network_state.network.close_socket(handle);
                    self.network_state.socket_event_handles.remove(&handle);
                    self.network_state.socket_event_masks.remove(&handle);
                    self.network_state
                        .network
                        .set_last_error(if ok { 0 } else { 10038 });
                    Ok(if ok { 0 } else { SOCKET_ERROR })
                }
                ("ws2_32.dll", "bind") | ("ws2_32.dll", "ordinal_2") => {
                    let handle = ctx.raw(0) as u32;
                    let (host, port, _) = self.read_sockaddr(ctx.raw(1), ctx.raw(2) as usize)?;
                    let ok = self
                        .network_state
                        .network
                        .with_socket_mut(handle, |socket| {
                            socket.bound_address = Some((host.clone(), port));
                        });
                    if ok.is_some() {
                        self.network_state.network.set_last_error(0);
                        Ok(0)
                    } else {
                        self.network_state.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "connect") | ("ws2_32.dll", "ordinal_4") => {
                    let handle = ctx.raw(0) as u32;
                    let (host, port, _) = self.read_sockaddr(ctx.raw(1), ctx.raw(2) as usize)?;
                    let ok = self
                        .network_state
                        .network
                        .with_socket_mut(handle, |socket| {
                            socket.connected = true;
                            socket.peer_address = Some((host.clone(), port));
                        });
                    if ok.is_some() {
                        let mut fields = Map::new();
                        fields.insert("socket".to_string(), json!(handle));
                        fields.insert("host".to_string(), json!(host));
                        fields.insert("port".to_string(), json!(port));
                        self.log_runtime_event("SOCKET_CONNECT", fields)?;
                        self.record_network_event(
                            "connect",
                            Some(host),
                            Some(port),
                            None,
                            None,
                            None,
                        );
                        self.network_state.network.set_last_error(0);
                        Ok(0)
                    } else {
                        self.network_state.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "listen") | ("ws2_32.dll", "ordinal_13") => {
                    let handle = ctx.raw(0) as u32;
                    let ok = self
                        .network_state
                        .network
                        .with_socket_mut(handle, |socket| {
                            socket.listening = true;
                        });
                    if ok.is_some() {
                        self.network_state.network.set_last_error(0);
                        Ok(0)
                    } else {
                        self.network_state.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "accept") | ("ws2_32.dll", "ordinal_1") => {
                    let handle = ctx.raw(0) as u32;
                    let Some(socket) = self.network_state.network.get_socket(handle) else {
                        self.network_state.network.set_last_error(10038);
                        return Ok(INVALID_SOCKET);
                    };
                    if !socket.listening {
                        self.network_state.network.set_last_error(10022);
                        return Ok(INVALID_SOCKET);
                    }
                    let accepted = self.network_state.network.create_socket(
                        socket.family,
                        socket.socket_type,
                        socket.protocol,
                    );
                    let _ = self
                        .network_state
                        .network
                        .with_socket_mut(accepted, |new_socket| {
                            new_socket.connected = true;
                            new_socket.bound_address = socket.bound_address.clone();
                            new_socket.peer_address = Some(("127.0.0.1".to_string(), 0));
                        });
                    self.write_sockaddr(ctx.raw(1), "127.0.0.1", 0)?;
                    if ctx.raw(2) != 0 {
                        self.write_u32(ctx.raw(2), 16)?;
                    }
                    self.network_state.network.set_last_error(0);
                    Ok(accepted as u64)
                }
                ("ws2_32.dll", "getpeername") | ("ws2_32.dll", "ordinal_5") => {
                    let handle = ctx.raw(0) as u32;
                    let Some(socket) = self.network_state.network.get_socket(handle) else {
                        self.network_state.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    };
                    if ctx.raw(2) != 0 {
                        self.write_u32(ctx.raw(2), 16)?;
                    }
                    let (host, port) = socket
                        .peer_address
                        .unwrap_or_else(|| ("0.0.0.0".to_string(), 0));
                    self.write_sockaddr(ctx.raw(1), &host, port)?;
                    self.network_state.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "getsockname") | ("ws2_32.dll", "ordinal_6") => {
                    let handle = ctx.raw(0) as u32;
                    let Some(socket) = self.network_state.network.get_socket(handle) else {
                        self.network_state.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    };
                    if ctx.raw(2) != 0 {
                        self.write_u32(ctx.raw(2), 16)?;
                    }
                    let (host, port) = socket
                        .bound_address
                        .unwrap_or_else(|| ("0.0.0.0".to_string(), 0));
                    self.write_sockaddr(ctx.raw(1), &host, port)?;
                    self.network_state.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "send") | ("ws2_32.dll", "ordinal_19") => {
                    let handle = ctx.raw(0) as u32;
                    let length = ctx.raw(2) as usize;
                    let data = if ctx.raw(1) == 0 || length == 0 {
                        Vec::new()
                    } else {
                        self.read_bytes_from_memory(ctx.raw(1), length)?
                    };
                    let ok = self
                        .network_state
                        .network
                        .with_socket_mut(handle, |socket| {
                            socket.sent_data.push(data.clone());
                        });
                    if ok.is_some() {
                        let mut fields = Map::new();
                        fields.insert("socket".to_string(), json!(handle));
                        fields.insert("bytes".to_string(), json!(data.len()));
                        Self::add_payload_preview_field(&mut fields, &data);
                        self.log_runtime_event("SOCKET_SEND", fields)?;
                        self.record_network_event(
                            "send",
                            None,
                            None,
                            Some(data.len() as u64),
                            None,
                            None,
                        );
                        let _ = self.inject_raw_socket_http_response_if_ready(handle)?;
                        self.network_state.network.set_last_error(0);
                        Ok(data.len() as u64)
                    } else {
                        self.network_state.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "WSASend") | ("ws2_32.dll", "ordinal_76") => {
                    let handle = ctx.raw(0) as u32;
                    let buffer_count = ctx.raw(2) as usize;
                    let data = self.read_wsabuf_payload(ctx.raw(1), buffer_count)?;
                    let ok = self
                        .network_state
                        .network
                        .with_socket_mut(handle, |socket| {
                            socket.sent_data.push(data.clone());
                        });
                    if let Some(()) = ok {
                        if ctx.raw(3) != 0 {
                            self.write_u32(ctx.raw(3), data.len().min(u32::MAX as usize) as u32)?;
                        }
                        let mut fields = Map::new();
                        fields.insert("socket".to_string(), json!(handle));
                        fields.insert("bytes".to_string(), json!(data.len()));
                        Self::add_payload_preview_field(&mut fields, &data);
                        self.log_runtime_event("SOCKET_SEND", fields)?;
                        let _ = self.inject_raw_socket_http_response_if_ready(handle)?;
                        self.network_state.network.set_last_error(0);
                        Ok(0)
                    } else {
                        if ctx.raw(3) != 0 {
                            self.write_u32(ctx.raw(3), 0)?;
                        }
                        self.network_state.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "recv") | ("ws2_32.dll", "ordinal_16") => {
                    let handle = ctx.raw(0) as u32;
                    let length = ctx.raw(2) as usize;
                    if self.network_state.network.get_socket(handle).is_none() {
                        self.network_state.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    }
                    let _ = self.ensure_raw_socket_read_ready(handle)?;
                    let Some((data, _)) = self.take_socket_recv_data(handle, length) else {
                        self.network_state.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    };
                    if ctx.raw(1) != 0 && !data.is_empty() {
                        self.core.modules.memory_mut().write(ctx.raw(1), &data)?;
                    }
                    let mut fields = Map::new();
                    fields.insert("socket".to_string(), json!(handle));
                    fields.insert("bytes".to_string(), json!(data.len()));
                    self.log_runtime_event("SOCKET_RECV", fields)?;
                    self.network_state.network.set_last_error(0);
                    Ok(data.len() as u64)
                }
                ("ws2_32.dll", "WSARecv") | ("ws2_32.dll", "ordinal_71") => {
                    let handle = ctx.raw(0) as u32;
                    let buffer_count = ctx.raw(2) as usize;
                    if self.network_state.network.get_socket(handle).is_none() {
                        if ctx.raw(3) != 0 {
                            self.write_u32(ctx.raw(3), 0)?;
                        }
                        self.network_state.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    }
                    let _ = self.ensure_raw_socket_read_ready(handle)?;
                    let Some((data, _)) = self.take_socket_recv_data(handle, usize::MAX) else {
                        if ctx.raw(3) != 0 {
                            self.write_u32(ctx.raw(3), 0)?;
                        }
                        self.network_state.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    };
                    let written = self.write_wsabuf_payload(ctx.raw(1), buffer_count, &data)?;
                    if ctx.raw(3) != 0 {
                        self.write_u32(ctx.raw(3), written.min(u32::MAX as usize) as u32)?;
                    }
                    if ctx.raw(4) != 0 {
                        self.write_u32(ctx.raw(4), 0)?;
                    }
                    let mut fields = Map::new();
                    fields.insert("socket".to_string(), json!(handle));
                    fields.insert("bytes".to_string(), json!(written));
                    self.log_runtime_event("SOCKET_RECV", fields)?;
                    self.network_state.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "sendto") | ("ws2_32.dll", "ordinal_20") => {
                    let handle = ctx.raw(0) as u32;
                    let length = ctx.raw(2) as usize;
                    let data = if ctx.raw(1) == 0 || length == 0 {
                        Vec::new()
                    } else {
                        self.read_bytes_from_memory(ctx.raw(1), length)?
                    };
                    let (host, port, _) = self.read_sockaddr(ctx.raw(4), ctx.raw(5) as usize)?;
                    let ok = self
                        .network_state
                        .network
                        .with_socket_mut(handle, |socket| {
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
                        let _ = self.inject_raw_socket_http_response_if_ready(handle)?;
                        self.network_state.network.set_last_error(0);
                        Ok(data.len() as u64)
                    } else {
                        self.network_state.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "recvfrom") | ("ws2_32.dll", "ordinal_17") => {
                    let handle = ctx.raw(0) as u32;
                    let length = ctx.raw(2) as usize;
                    if self.network_state.network.get_socket(handle).is_none() {
                        self.network_state.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    }
                    let _ = self.ensure_raw_socket_read_ready(handle)?;
                    let Some((data, peer)) = self.take_socket_recv_data(handle, length) else {
                        self.network_state.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    };
                    if ctx.raw(1) != 0 && !data.is_empty() {
                        self.core.modules.memory_mut().write(ctx.raw(1), &data)?;
                    }
                    if let Some((host, port)) = peer {
                        self.write_sockaddr(ctx.raw(4), &host, port)?;
                        if ctx.raw(5) != 0 {
                            self.write_u32(ctx.raw(5), 16)?;
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
                    self.network_state.network.set_last_error(0);
                    Ok(data.len() as u64)
                }
                ("ws2_32.dll", "shutdown") | ("ws2_32.dll", "ordinal_22") => {
                    let handle = ctx.raw(0) as u32;
                    let ok = self
                        .network_state
                        .network
                        .with_socket_mut(handle, |socket| {
                            socket.connected = false;
                        });
                    if ok.is_some() {
                        self.network_state.network.set_last_error(0);
                        Ok(0)
                    } else {
                        self.network_state.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "select") | ("ws2_32.dll", "ordinal_18") => {
                    let nfds = ctx.raw(0);
                    let read_fd_addr = ctx.raw(1);
                    let write_fd_addr = ctx.raw(2);
                    let except_fd_addr = ctx.raw(3);
                    let timeout_addr = ctx.raw(4);

                    // Fast path: empty select with nfds=0 and all fd_set pointers NULL.
                    if nfds == 0 && read_fd_addr == 0 && write_fd_addr == 0 && except_fd_addr == 0 {
                        self.network_state.network.set_last_error(0);
                        self.request_thread_yield("select_null", true);
                        return Ok(0);
                    }

                    let read_ready = self
                        .read_fd_set_handles(read_fd_addr)?
                        .into_iter()
                        .filter(|handle| {
                            self.ensure_raw_socket_read_ready(*handle).unwrap_or(false)
                        })
                        .collect::<Vec<_>>();
                    let write_ready = self
                        .read_fd_set_handles(write_fd_addr)?
                        .into_iter()
                        .filter(|handle| self.network_state.network.get_socket(*handle).is_some())
                        .collect::<Vec<_>>();
                    self.write_fd_set_handles(read_fd_addr, &read_ready)?;
                    self.write_fd_set_handles(write_fd_addr, &write_ready)?;
                    self.write_fd_set_handles(except_fd_addr, &[])?;
                    self.network_state.network.set_last_error(0);

                    let total_ready = read_ready
                        .iter()
                        .chain(write_ready.iter())
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .len();

                    // Empty poll with no timeout: yield periodically (every 10000 calls)
                    // to avoid busy-waiting without excessive scheduling.
                    if total_ready == 0 && timeout_addr == 0 {
                        self.network_state.consecutive_empty_selects += 1;
                        if self.network_state.consecutive_empty_selects >= 10000 {
                            self.network_state.consecutive_empty_selects = 0;
                            self.request_thread_yield("select_empty_poll", true);
                        }
                    } else {
                        self.network_state.consecutive_empty_selects = 0;
                    }

                    Ok(total_ready as u64)
                }
                ("ws2_32.dll", "ioctlsocket") | ("ws2_32.dll", "ordinal_10") => {
                    let handle = ctx.raw(0) as u32;
                    let request = ctx.raw(1);
                    let value = if ctx.raw(2) != 0 {
                        self.read_u32(ctx.raw(2))?
                    } else {
                        0
                    };
                    let ok = self
                        .network_state
                        .network
                        .with_socket_mut(handle, |socket| {
                            if request == FIONBIO {
                                socket.blocking = value == 0;
                            }
                        });
                    if ok.is_some() {
                        if request == FIONREAD {
                            let _ = self.ensure_raw_socket_read_ready(handle)?;
                            if ctx.raw(2) != 0 {
                                let available = self
                                    .network_state
                                    .network
                                    .get_socket(handle)
                                    .map(|s| s.recv_queue.first().map(|b| b.len()).unwrap_or(0))
                                    .unwrap_or(0);
                                self.write_u32(ctx.raw(2), available as u32)?;
                            }
                        }
                        self.network_state.network.set_last_error(0);
                        Ok(0)
                    } else {
                        self.network_state.network.set_last_error(10038);
                        Ok(SOCKET_ERROR)
                    }
                }
                ("ws2_32.dll", "setsockopt") | ("ws2_32.dll", "ordinal_21") => {
                    let ok = self
                        .network_state
                        .network
                        .get_socket(ctx.raw(0) as u32)
                        .is_some();
                    self.network_state
                        .network
                        .set_last_error(if ok { 0 } else { 10038 });
                    Ok(if ok { 0 } else { SOCKET_ERROR })
                }
                ("ws2_32.dll", "getsockopt") | ("ws2_32.dll", "ordinal_7") => {
                    if self
                        .network_state
                        .network
                        .get_socket(ctx.raw(0) as u32)
                        .is_none()
                    {
                        self.network_state.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    }
                    if ctx.raw(3) != 0 && ctx.raw(4) != 0 {
                        let size = self.read_u32(ctx.raw(4))? as usize;
                        let payload = vec![0u8; size.min(4)];
                        if !payload.is_empty() {
                            self.core.modules.memory_mut().write(ctx.raw(3), &payload)?;
                        }
                        self.write_u32(ctx.raw(4), payload.len() as u32)?;
                    }
                    self.network_state.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "htons") | ("ws2_32.dll", "ordinal_9") => {
                    Ok(u16::from_le_bytes((ctx.raw(0) as u16).to_be_bytes()) as u64)
                }
                ("ws2_32.dll", "ntohs") | ("ws2_32.dll", "ordinal_15") => {
                    Ok(u16::from_le_bytes((ctx.raw(0) as u16).to_be_bytes()) as u64)
                }
                ("ws2_32.dll", "htonl") | ("ws2_32.dll", "ordinal_8") => {
                    Ok(u32::from_le_bytes((ctx.raw(0) as u32).to_be_bytes()) as u64)
                }
                ("ws2_32.dll", "ntohl") | ("ws2_32.dll", "ordinal_14") => {
                    Ok(u32::from_le_bytes((ctx.raw(0) as u32).to_be_bytes()) as u64)
                }
                ("ws2_32.dll", "inet_addr") | ("ws2_32.dll", "ordinal_11") => {
                    let text = self.read_c_string_from_memory(ctx.raw(0))?;
                    Ok(self
                        .resolve_ipv4_like_winsock(&text)
                        .map(|addr| u32::from_le_bytes(addr.octets()))
                        .unwrap_or(u32::MAX) as u64)
                }
                ("ws2_32.dll", "inet_ntop") => {
                    let family = ctx.raw(0) as u16;
                    let src = ctx.raw(1);
                    let dst = ctx.raw(2);
                    let capacity = ctx.raw(3) as usize;
                    if src == 0 || dst == 0 || capacity == 0 {
                        self.network_state.network.set_last_error(10014);
                        return Ok(0);
                    }
                    let text = match family {
                        AF_INET => {
                            let bytes = self.read_bytes_from_memory(src, 4)?;
                            if bytes.len() < 4 {
                                self.network_state.network.set_last_error(10014);
                                return Ok(0);
                            }
                            std::net::Ipv4Addr::from([bytes[0], bytes[1], bytes[2], bytes[3]])
                                .to_string()
                        }
                        AF_INET6 => {
                            let bytes = self.read_bytes_from_memory(src, 16)?;
                            if bytes.len() < 16 {
                                self.network_state.network.set_last_error(10014);
                                return Ok(0);
                            }
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(&bytes[..16]);
                            std::net::Ipv6Addr::from(octets).to_string()
                        }
                        _ => {
                            self.network_state.network.set_last_error(10047);
                            return Ok(0);
                        }
                    };
                    if text.len().saturating_add(1) > capacity {
                        self.network_state.network.set_last_error(10022);
                        return Ok(0);
                    }
                    self.write_c_string_to_memory(dst, capacity, &text)?;
                    self.network_state.network.set_last_error(0);
                    Ok(dst)
                }
                ("ws2_32.dll", "inet_ntoa") | ("ws2_32.dll", "ordinal_12") => {
                    let raw = (ctx.raw(0) as u32).to_le_bytes();
                    let text = format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3]);
                    let buffer = self.ensure_inet_ntoa_buffer()?;
                    self.write_c_string_to_memory(buffer, 32, &text)?;
                    Ok(buffer)
                }
                ("ws2_32.dll", "gethostbyaddr") | ("ws2_32.dll", "ordinal_51") => {
                    let data = if ctx.raw(0) != 0 && ctx.raw(1) >= 4 {
                        self.read_bytes_from_memory(ctx.raw(0), 4)?
                    } else {
                        vec![127, 0, 0, 1]
                    };
                    let ip = format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]);
                    Ok(self.create_hostent(&ip, &ip)?)
                }
                ("ws2_32.dll", "gethostbyname") | ("ws2_32.dll", "ordinal_52") => {
                    let name = self.read_c_string_from_memory(ctx.raw(0))?;
                    let host_name = non_empty(&name).unwrap_or("localhost");
                    let resolved = self.network_state.dns.resolve(host_name);
                    self.record_network_event(
                        "dns_resolve",
                        Some(host_name.to_string()),
                        None,
                        None,
                        None,
                        None,
                    );
                    Ok(self.create_hostent(host_name, &resolved)?)
                }
                ("ws2_32.dll", "getprotobyname") | ("ws2_32.dll", "ordinal_53") => {
                    let name = self
                        .read_c_string_from_memory(ctx.raw(0))?
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
                        .read_c_string_from_memory(ctx.raw(0))?
                        .to_ascii_lowercase();
                    let protocol = self.read_c_string_from_memory(ctx.raw(1))?;
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
                    let host_order_port = u16::from_be(ctx.raw(0) as u16);
                    let protocol = self.read_c_string_from_memory(ctx.raw(1))?;
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
                    let capacity = ctx.raw(1) as usize;
                    if ctx.raw(0) == 0 || capacity == 0 {
                        self.network_state.network.set_last_error(10014);
                        return Ok(SOCKET_ERROR);
                    }
                    let _ = self.write_c_string_to_memory(ctx.raw(0), capacity, &name)?;
                    self.network_state.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "getaddrinfo") => {
                    if ctx.raw(3) == 0 {
                        self.network_state.network.set_last_error(11001);
                        return Ok(11001);
                    }
                    let node_name = self.read_c_string_from_memory(ctx.raw(0))?;
                    let service_name = self.read_c_string_from_memory(ctx.raw(1))?;
                    let addrinfo = self.create_addrinfo(&node_name, &service_name)?;
                    self.write_pointer_value(ctx.raw(3), addrinfo)?;
                    if !node_name.is_empty() {
                        self.record_network_event(
                            "dns_resolve",
                            Some(node_name),
                            None,
                            None,
                            None,
                            None,
                        );
                    }
                    self.network_state.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "freeaddrinfo") => Ok(0),
                ("ws2_32.dll", "WSAEnumNetworkEvents") => {
                    let handle = ctx.raw(0) as u32;
                    if self.network_state.network.get_socket(handle).is_none() {
                        self.network_state.network.set_last_error(10038);
                        return Ok(SOCKET_ERROR);
                    }
                    let _ = self.ensure_raw_socket_read_ready(handle)?;
                    if ctx.raw(1) != 0 {
                        let _ = self.core.scheduler.reset_event(ctx.raw(1) as u32);
                    }
                    if ctx.raw(2) != 0 {
                        let mut payload = [0u8; 44];
                        let network_events = if self
                            .network_state
                            .network
                            .get_socket(handle)
                            .map(|socket| !socket.recv_queue.is_empty())
                            .unwrap_or(false)
                        {
                            0x0001u32
                        } else {
                            0
                        };
                        payload[0..4].copy_from_slice(&network_events.to_le_bytes());
                        self.core.modules.memory_mut().write(ctx.raw(2), &payload)?;
                    }
                    self.network_state.network.set_last_error(0);
                    Ok(0)
                }
                ("ws2_32.dll", "WSAEventSelect") => {
                    let socket_handle = ctx.raw(0) as u32;
                    let socket_ok = self
                        .network_state
                        .network
                        .get_socket(socket_handle)
                        .is_some();
                    let event_ok = ctx.raw(1) == 0
                        || self.core.scheduler.reset_event(ctx.raw(1) as u32).is_some();
                    let ok = socket_ok && event_ok;
                    if ok {
                        let _ =
                            self.network_state
                                .network
                                .with_socket_mut(socket_handle, |socket| {
                                    socket.blocking = false;
                                });
                        if ctx.raw(1) == 0 {
                            self.network_state
                                .socket_event_handles
                                .remove(&socket_handle);
                            self.network_state.socket_event_masks.remove(&socket_handle);
                        } else {
                            self.network_state
                                .socket_event_handles
                                .insert(socket_handle, ctx.raw(1) as u32);
                            self.network_state
                                .socket_event_masks
                                .insert(socket_handle, ctx.raw(2) as i32);
                            let _ = self.ensure_raw_socket_read_ready(socket_handle)?;
                        }
                    }
                    self.network_state
                        .network
                        .set_last_error(if ok { 0 } else { 10038 });
                    Ok(if ok { 0 } else { SOCKET_ERROR })
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
