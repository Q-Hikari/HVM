use crate::managers::handle_table::HandleTable;

fn pseudo_sha1(bytes: &[u8]) -> [u8; 20] {
    let mut digest = [0u8; 20];
    for (index, byte) in bytes.iter().enumerate() {
        digest[index % digest.len()] = digest[index % digest.len()]
            .wrapping_add(*byte)
            .wrapping_add(index as u8);
    }
    digest
}

/// Stores one certificate context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateContext {
    pub subject: String,
    pub issuer: String,
    pub encoded: Vec<u8>,
    pub properties: std::collections::BTreeMap<u32, Vec<u8>>,
}

/// Stores one certificate store handle payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateStore {
    pub name: String,
    pub certificates: Vec<u32>,
    pub collection: bool,
}

/// Stores one cryptographic message object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptMessage {
    pub data: Vec<u8>,
    pub r#final: bool,
}

/// Stores one certificate chain object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateChain {
    pub certificates: Vec<u32>,
}

/// Mirrors the Python crypto manager using shared handle-backed objects.
#[derive(Debug)]
pub struct CryptoManager {
    handles: HandleTable,
}

impl CryptoManager {
    /// Builds a crypto manager using the provided handle table.
    pub fn new(handles: HandleTable) -> Self {
        Self { handles }
    }

    /// Opens one certificate store and seeds its default certificate when applicable.
    pub fn open_store(&mut self, name: &str, collection: bool) -> u32 {
        let certificates = if collection {
            Vec::new()
        } else {
            vec![self.default_cert(name)]
        };
        self.handles.allocate(
            "cert_store",
            CertificateStore {
                name: name.to_string(),
                certificates,
                collection,
            },
        )
    }

    /// Returns a cloned store payload.
    pub fn get_store(&self, handle: u32) -> Option<CertificateStore> {
        if self.handles.kind(handle) != Some("cert_store") {
            return None;
        }
        self.handles
            .with_payload::<CertificateStore, _, _>(handle, Clone::clone)
    }

    /// Adds all certificates from one sibling store into a collection store.
    pub fn add_store_to_collection(&self, collection_handle: u32, sibling_handle: u32) -> bool {
        let Some(sibling) = self.get_store(sibling_handle) else {
            return false;
        };
        self.handles
            .with_payload_mut::<CertificateStore, _, _>(collection_handle, |collection| {
                for certificate in sibling.certificates {
                    if !collection.certificates.contains(&certificate) {
                        collection.certificates.push(certificate);
                    }
                }
            })
            .is_some()
    }

    /// Finds the next certificate in a store using the Python baseline iteration rules.
    pub fn find_certificate(&self, store_handle: u32, previous: u32) -> u32 {
        let Some(store) = self.get_store(store_handle) else {
            return 0;
        };
        if previous == 0 {
            return store.certificates.first().copied().unwrap_or(0);
        }
        let Some(index) = store
            .certificates
            .iter()
            .position(|candidate| *candidate == previous)
        else {
            return 0;
        };
        store.certificates.get(index + 1).copied().unwrap_or(0)
    }

    /// Returns a cloned certificate context payload.
    pub fn get_certificate(&self, handle: u32) -> Option<CertificateContext> {
        if self.handles.kind(handle) != Some("cert_context") {
            return None;
        }
        self.handles
            .with_payload::<CertificateContext, _, _>(handle, Clone::clone)
    }

    /// Opens an empty cryptographic message object.
    pub fn open_message(&mut self) -> u32 {
        self.handles.allocate(
            "crypt_msg",
            CryptMessage {
                data: Vec::new(),
                r#final: false,
            },
        )
    }

    /// Returns a cloned cryptographic message payload.
    pub fn get_message(&self, handle: u32) -> Option<CryptMessage> {
        if self.handles.kind(handle) != Some("crypt_msg") {
            return None;
        }
        self.handles
            .with_payload::<CryptMessage, _, _>(handle, Clone::clone)
    }

    /// Runs a mutable closure over one cryptographic message payload.
    pub fn with_message_mut<R, F: FnOnce(&mut CryptMessage) -> R>(
        &self,
        handle: u32,
        f: F,
    ) -> Option<R> {
        if self.handles.kind(handle) != Some("crypt_msg") {
            return None;
        }
        self.handles
            .with_payload_mut::<CryptMessage, _, _>(handle, f)
    }

    /// Opens one certificate chain payload.
    pub fn open_chain(&mut self, certificates: &[u32]) -> u32 {
        self.handles.allocate(
            "cert_chain",
            CertificateChain {
                certificates: certificates.to_vec(),
            },
        )
    }

    /// Closes one handle only if it matches the requested kind.
    pub fn close_handle(&mut self, handle: u32, kind: &str) -> bool {
        if self.handles.kind(handle) != Some(kind) {
            return false;
        }
        self.handles.close(handle)
    }

    fn default_cert(&mut self, store_name: &str) -> u32 {
        let encoded = format!("CERT:{store_name}").into_bytes();
        let digest = pseudo_sha1(&encoded);
        let mut properties = std::collections::BTreeMap::new();
        properties.insert(3, digest.to_vec());
        properties.insert(20, digest.to_vec());
        properties.insert(11, b"Sandbox Friendly Name\0".to_vec());
        self.handles.allocate(
            "cert_context",
            CertificateContext {
                subject: format!(
                    "CN={}",
                    if store_name.is_empty() {
                        "Sandbox Certificate"
                    } else {
                        store_name
                    }
                ),
                issuer: "CN=Sandbox Root".to_string(),
                encoded,
                properties,
            },
        )
    }
}
