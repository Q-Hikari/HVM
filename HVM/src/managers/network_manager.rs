use crate::managers::handle_table::HandleTable;

/// Stores one emulated socket object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketObject {
    pub family: i32,
    pub socket_type: i32,
    pub protocol: i32,
    pub blocking: bool,
    pub connected: bool,
    pub listening: bool,
    pub bound_address: Option<(String, u16)>,
    pub peer_address: Option<(String, u16)>,
    pub recv_queue: Vec<Vec<u8>>,
    pub sent_data: Vec<Vec<u8>>,
}

/// Stores one WinINet-style session object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternetSession {
    pub agent: String,
    pub access_type: u32,
    pub proxy: String,
    pub proxy_bypass: String,
}

/// Stores one WinINet-style connection object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternetConnection {
    pub session_handle: u32,
    pub server: String,
    pub port: u16,
    pub service: u32,
    pub username: String,
    pub password: String,
}

/// Stores one WinINet-style request object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternetRequest {
    pub parent_handle: u32,
    pub verb: String,
    pub target: String,
    pub version: String,
    pub referrer: String,
    pub headers: String,
    pub request_body: Vec<u8>,
    pub response_body: Vec<u8>,
    pub response_headers: Vec<u8>,
    pub status_code: u32,
    pub sent: bool,
    pub read_offset: usize,
}

/// Mirrors the Python network manager over shared handle-backed objects.
#[derive(Debug)]
pub struct NetworkManager {
    handles: HandleTable,
    wsa_last_error: u32,
}

impl NetworkManager {
    /// Builds a network manager using the provided handle table.
    pub fn new(handles: HandleTable) -> Self {
        Self {
            handles,
            wsa_last_error: 0,
        }
    }

    /// Updates the current Winsock last-error value.
    pub fn set_last_error(&mut self, value: u32) {
        self.wsa_last_error = value;
    }

    /// Returns the current Winsock last-error value.
    pub fn last_error(&self) -> u32 {
        self.wsa_last_error
    }

    /// Allocates one socket object.
    pub fn create_socket(&mut self, family: i32, socket_type: i32, protocol: i32) -> u32 {
        self.handles.allocate(
            "socket",
            SocketObject {
                family,
                socket_type,
                protocol,
                blocking: true,
                connected: false,
                listening: false,
                bound_address: None,
                peer_address: None,
                recv_queue: Vec::new(),
                sent_data: Vec::new(),
            },
        )
    }

    /// Returns a cloned socket object when the handle refers to a socket.
    pub fn get_socket(&self, handle: u32) -> Option<SocketObject> {
        if self.handles.kind(handle) != Some("socket") {
            return None;
        }
        self.handles
            .with_payload::<SocketObject, _, _>(handle, Clone::clone)
    }

    /// Runs a mutable closure over one socket payload.
    pub fn with_socket_mut<R, F: FnOnce(&mut SocketObject) -> R>(
        &self,
        handle: u32,
        f: F,
    ) -> Option<R> {
        if self.handles.kind(handle) != Some("socket") {
            return None;
        }
        self.handles
            .with_payload_mut::<SocketObject, _, _>(handle, f)
    }

    /// Closes one socket handle.
    pub fn close_socket(&mut self, handle: u32) -> bool {
        if self.handles.kind(handle) != Some("socket") {
            return false;
        }
        self.handles.close(handle)
    }

    /// Opens one WinINet-style internet session.
    pub fn internet_open(
        &mut self,
        agent: &str,
        access_type: u32,
        proxy: &str,
        proxy_bypass: &str,
    ) -> u32 {
        self.handles.allocate(
            "internet_session",
            InternetSession {
                agent: agent.to_string(),
                access_type,
                proxy: proxy.to_string(),
                proxy_bypass: proxy_bypass.to_string(),
            },
        )
    }

    /// Opens one WinINet-style connection under a parent session.
    pub fn internet_connect(
        &mut self,
        session_handle: u32,
        server: &str,
        port: u16,
        service: u32,
        username: &str,
        password: &str,
    ) -> u32 {
        self.handles.allocate(
            "internet_connection",
            InternetConnection {
                session_handle,
                server: server.to_string(),
                port,
                service,
                username: username.to_string(),
                password: password.to_string(),
            },
        )
    }

    /// Opens one WinINet-style request object.
    pub fn open_request(
        &mut self,
        parent_handle: u32,
        verb: &str,
        target: &str,
        version: &str,
        referrer: &str,
        headers: &str,
    ) -> u32 {
        self.handles.allocate(
            "internet_request",
            InternetRequest {
                parent_handle,
                verb: verb.to_string(),
                target: target.to_string(),
                version: version.to_string(),
                referrer: referrer.to_string(),
                headers: headers.to_string(),
                request_body: Vec::new(),
                response_body: Vec::new(),
                response_headers: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
                status_code: 200,
                sent: false,
                read_offset: 0,
            },
        )
    }

    /// Returns a cloned connection object.
    pub fn get_connection(&self, handle: u32) -> Option<InternetConnection> {
        if self.handles.kind(handle) != Some("internet_connection") {
            return None;
        }
        self.handles
            .with_payload::<InternetConnection, _, _>(handle, Clone::clone)
    }

    /// Runs a mutable closure over one request payload.
    pub fn with_request_mut<R, F: FnOnce(&mut InternetRequest) -> R>(
        &self,
        handle: u32,
        f: F,
    ) -> Option<R> {
        if self.handles.kind(handle) != Some("internet_request") {
            return None;
        }
        self.handles
            .with_payload_mut::<InternetRequest, _, _>(handle, f)
    }

    /// Returns a cloned request object.
    pub fn get_request(&self, handle: u32) -> Option<InternetRequest> {
        if self.handles.kind(handle) != Some("internet_request") {
            return None;
        }
        self.handles
            .with_payload::<InternetRequest, _, _>(handle, Clone::clone)
    }

    /// Returns the normalized route tuple for one request when resolvable.
    pub fn request_route(&self, handle: u32) -> Option<(String, String, String)> {
        let request = self.get_request(handle)?;
        let verb = request.verb.clone();
        let mut target = request.target.clone();
        let mut host = self
            .get_connection(request.parent_handle)
            .map(|connection| connection.server);
        if host.as_deref().is_none_or(str::is_empty) {
            if let Some((parsed_host, parsed_target)) = split_http_url(&request.target) {
                host = Some(parsed_host);
                target = parsed_target;
            }
        }
        Some((host.unwrap_or_default(), target, verb))
    }

    /// Closes one WinINet-style handle.
    pub fn close_internet_handle(&mut self, handle: u32) -> bool {
        matches!(
            self.handles.kind(handle),
            Some("internet_session" | "internet_connection" | "internet_request")
        ) && self.handles.close(handle)
    }

    /// Allocates one custom handle-backed network object.
    pub fn allocate_custom<T: 'static>(&mut self, kind: &str, payload: T) -> u32 {
        self.handles.allocate(kind, payload)
    }

    /// Returns the custom handle kind when the handle exists.
    pub fn kind(&self, handle: u32) -> Option<&str> {
        self.handles.kind(handle)
    }

    /// Runs a typed read-only closure over one custom payload.
    pub fn with_payload<T: 'static, R, F: FnOnce(&T) -> R>(&self, handle: u32, f: F) -> Option<R> {
        self.handles.with_payload(handle, f)
    }

    /// Runs a typed mutable closure over one custom payload.
    pub fn with_payload_mut<T: 'static, R, F: FnOnce(&mut T) -> R>(
        &self,
        handle: u32,
        f: F,
    ) -> Option<R> {
        self.handles.with_payload_mut(handle, f)
    }

    /// Closes one custom handle when it exists.
    pub fn close_handle(&mut self, handle: u32) -> bool {
        self.handles.close(handle)
    }

    /// Reads up to `size` bytes from the request response body and advances the read offset.
    pub fn request_read(&self, handle: u32, size: usize) -> Vec<u8> {
        self.with_request_mut(handle, |request| {
            if size == 0 {
                return Vec::new();
            }
            let start = request.read_offset;
            let end = (start + size).min(request.response_body.len());
            let data = request.response_body[start..end].to_vec();
            request.read_offset = end;
            data
        })
        .unwrap_or_default()
    }

    /// Returns the unread response bytes remaining for the request.
    pub fn request_remaining(&self, handle: u32) -> usize {
        self.get_request(handle)
            .map(|request| {
                request
                    .response_body
                    .len()
                    .saturating_sub(request.read_offset)
            })
            .unwrap_or(0)
    }
}

fn split_http_url(value: &str) -> Option<(String, String)> {
    let normalized = value.trim();
    let (_, remainder) = normalized.split_once("://")?;
    let (authority, path) = remainder.split_once('/').unwrap_or((remainder, ""));
    let host = authority
        .split('@')
        .next_back()
        .unwrap_or(authority)
        .split(':')
        .next()
        .unwrap_or_default()
        .trim();
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), format!("/{}", path)))
}
