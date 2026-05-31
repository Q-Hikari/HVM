use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};

use crate::managers::handle_table::HandleTable;

const PUBLICKEYBLOB: u8 = 0x06;
const PRIVATEKEYBLOB: u8 = 0x07;
const PLAINTEXTKEYBLOB: u8 = 0x08;
const OPAQUEKEYBLOB: u8 = 0x09;
const CUR_BLOB_VERSION: u8 = 0x02;

const CALG_AES_128: u32 = 0x0000_660e;
const CALG_AES_192: u32 = 0x0000_660f;
const CALG_AES_256: u32 = 0x0000_6610;
const CALG_AES: u32 = 0x0000_6611;

const KP_IV: u32 = 1;
const KP_MODE: u32 = 4;
const KP_ALGID: u32 = 7;
const KP_BLOCKLEN: u32 = 8;
const KP_KEYLEN: u32 = 9;

const CRYPT_MODE_CBC: u32 = 1;
const CRYPT_MODE_ECB: u32 = 2;

const RSA1_MAGIC: u32 = 0x3141_5352;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoKeyMode {
    Cbc,
    Ecb,
}

impl CryptoKeyMode {
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            CRYPT_MODE_CBC => Some(Self::Cbc),
            CRYPT_MODE_ECB => Some(Self::Ecb),
            _ => None,
        }
    }

    fn raw(self) -> u32 {
        match self {
            Self::Cbc => CRYPT_MODE_CBC,
            Self::Ecb => CRYPT_MODE_ECB,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricKey {
    pub alg_id: u32,
    pub key: Vec<u8>,
    pub mode: CryptoKeyMode,
    pub iv: Vec<u8>,
    pub feedback: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    pub alg_id: u32,
    pub bit_len: u32,
    pub public_exponent: u32,
    pub modulus: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoBlobInfo {
    pub blob_type: u8,
    pub version: u8,
    pub alg_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidHandle,
    InvalidBlob,
    InvalidLength,
    InvalidPadding,
    InvalidParameter,
    UnsupportedAlg(u32),
    UnsupportedBlobType(CryptoBlobInfo),
    UnsupportedFlags(u32),
    UnsupportedMode(u32),
    UnsupportedOpaqueBlob(CryptoBlobInfo),
    UnsupportedParam(u32),
}

/// Manages emulated certificate stores and crypto objects via handle tables.
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

    /// Finds the next certificate in a store.
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

    /// Imports one CryptoAPI key blob and returns a stable key handle.
    pub fn import_key(&mut self, blob: &[u8]) -> Result<u32, CryptoError> {
        let info = Self::blob_info(blob)?;
        if info.version != CUR_BLOB_VERSION {
            return Err(CryptoError::InvalidBlob);
        }
        match info.blob_type {
            PUBLICKEYBLOB => self.import_public_key(blob, info.alg_id),
            PRIVATEKEYBLOB => Err(CryptoError::UnsupportedBlobType(info)),
            PLAINTEXTKEYBLOB => self.import_plaintext_key(blob, info.alg_id),
            OPAQUEKEYBLOB => Err(CryptoError::UnsupportedOpaqueBlob(info)),
            _ => Err(CryptoError::UnsupportedBlobType(info)),
        }
    }

    /// Returns the emulated imported key kind when this is a crypto-managed handle.
    pub fn imported_key_kind(&self, handle: u32) -> Option<&str> {
        match self.handles.kind(handle) {
            Some("crypto_key") | Some("rsa_public_key") => self.handles.kind(handle),
            _ => None,
        }
    }

    /// Reads one imported symmetric key payload.
    pub fn get_key(&self, handle: u32) -> Option<SymmetricKey> {
        if self.handles.kind(handle) != Some("crypto_key") {
            return None;
        }
        self.handles
            .with_payload::<SymmetricKey, _, _>(handle, Clone::clone)
    }

    /// Updates one imported key parameter.
    pub fn set_key_param(&self, handle: u32, param: u32, data: &[u8]) -> Result<(), CryptoError> {
        if self.handles.kind(handle) != Some("crypto_key") {
            return Err(CryptoError::InvalidHandle);
        }
        match param {
            KP_MODE => {
                let raw = read_u32_le(data)?;
                let Some(mode) = CryptoKeyMode::from_raw(raw) else {
                    return Err(CryptoError::UnsupportedMode(raw));
                };
                self.handles
                    .with_payload_mut::<SymmetricKey, _, _>(handle, |key| key.mode = mode)
                    .ok_or(CryptoError::InvalidHandle)?;
                Ok(())
            }
            KP_IV => {
                self.handles
                    .with_payload_mut::<SymmetricKey, _, _>(handle, |key| {
                        if data.len() != key.iv.len() {
                            return Err(CryptoError::InvalidLength);
                        }
                        key.iv.copy_from_slice(data);
                        key.feedback.copy_from_slice(data);
                        Ok(())
                    })
                    .ok_or(CryptoError::InvalidHandle)??;
                Ok(())
            }
            _ => Err(CryptoError::UnsupportedParam(param)),
        }
    }

    /// Returns a selected key parameter payload.
    pub fn get_key_param(&self, handle: u32, param: u32) -> Result<Vec<u8>, CryptoError> {
        if let Some(key) = self.get_key(handle) {
            return match param {
                KP_MODE => Ok(key.mode.raw().to_le_bytes().to_vec()),
                KP_ALGID => Ok(key.alg_id.to_le_bytes().to_vec()),
                KP_BLOCKLEN => Ok((block_len_bytes(key.alg_id)? as u32 * 8)
                    .to_le_bytes()
                    .to_vec()),
                KP_KEYLEN => Ok((key.key.len() as u32 * 8).to_le_bytes().to_vec()),
                KP_IV => Ok(key.iv),
                _ => Err(CryptoError::UnsupportedParam(param)),
            };
        }
        if self.handles.kind(handle) == Some("rsa_public_key") {
            let public_key = self
                .handles
                .with_payload::<RsaPublicKey, _, _>(handle, Clone::clone)
                .ok_or(CryptoError::InvalidHandle)?;
            return match param {
                KP_ALGID => Ok(public_key.alg_id.to_le_bytes().to_vec()),
                KP_KEYLEN => Ok(public_key.bit_len.to_le_bytes().to_vec()),
                _ => Err(CryptoError::UnsupportedParam(param)),
            };
        }
        Err(CryptoError::InvalidHandle)
    }

    /// Encrypts one buffer using the imported key handle.
    pub fn encrypt_buffer(
        &self,
        handle: u32,
        final_block: bool,
        flags: u32,
        input: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if flags != 0 {
            return Err(CryptoError::UnsupportedFlags(flags));
        }
        self.handles
            .with_payload_mut::<SymmetricKey, _, _>(handle, |key| {
                encrypt_symmetric(key, final_block, input)
            })
            .ok_or(CryptoError::InvalidHandle)?
    }

    /// Decrypts one buffer using the imported key handle.
    pub fn decrypt_buffer(
        &self,
        handle: u32,
        final_block: bool,
        flags: u32,
        input: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if flags != 0 {
            return Err(CryptoError::UnsupportedFlags(flags));
        }
        self.handles
            .with_payload_mut::<SymmetricKey, _, _>(handle, |key| {
                decrypt_symmetric(key, final_block, input)
            })
            .ok_or(CryptoError::InvalidHandle)?
    }

    /// Closes one imported key handle.
    pub fn close_key(&mut self, handle: u32) -> bool {
        self.close_handle(handle, "crypto_key") || self.close_handle(handle, "rsa_public_key")
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

    fn blob_info(blob: &[u8]) -> Result<CryptoBlobInfo, CryptoError> {
        if blob.len() < 8 {
            return Err(CryptoError::InvalidBlob);
        }
        Ok(CryptoBlobInfo {
            blob_type: blob[0],
            version: blob[1],
            alg_id: u32::from_le_bytes(blob[4..8].try_into().unwrap()),
        })
    }

    fn import_plaintext_key(&mut self, blob: &[u8], alg_id: u32) -> Result<u32, CryptoError> {
        if blob.len() < 12 {
            return Err(CryptoError::InvalidBlob);
        }
        let key_len = u32::from_le_bytes(blob[8..12].try_into().unwrap()) as usize;
        let Some(key_bytes) = blob.get(12..12 + key_len) else {
            return Err(CryptoError::InvalidBlob);
        };
        if blob.len() != 12 + key_len {
            return Err(CryptoError::InvalidBlob);
        }
        let effective_alg = normalize_aes_alg_id(alg_id, key_bytes.len())?;
        let block_len = block_len_bytes(effective_alg)?;
        let key = SymmetricKey {
            alg_id: effective_alg,
            key: key_bytes.to_vec(),
            mode: CryptoKeyMode::Cbc,
            iv: vec![0u8; block_len],
            feedback: vec![0u8; block_len],
        };
        Ok(self.handles.allocate("crypto_key", key))
    }

    fn import_public_key(&mut self, blob: &[u8], alg_id: u32) -> Result<u32, CryptoError> {
        if blob.len() < 20 {
            return Err(CryptoError::InvalidBlob);
        }
        let magic = u32::from_le_bytes(blob[8..12].try_into().unwrap());
        let bit_len = u32::from_le_bytes(blob[12..16].try_into().unwrap());
        let public_exponent = u32::from_le_bytes(blob[16..20].try_into().unwrap());
        if magic != RSA1_MAGIC || bit_len == 0 || bit_len % 8 != 0 {
            return Err(CryptoError::InvalidBlob);
        }
        let modulus_len = (bit_len / 8) as usize;
        let Some(modulus) = blob.get(20..20 + modulus_len) else {
            return Err(CryptoError::InvalidBlob);
        };
        if blob.len() < 20 + modulus_len {
            return Err(CryptoError::InvalidBlob);
        }
        Ok(self.handles.allocate(
            "rsa_public_key",
            RsaPublicKey {
                alg_id,
                bit_len,
                public_exponent,
                modulus: modulus.to_vec(),
            },
        ))
    }
}

fn read_u32_le(bytes: &[u8]) -> Result<u32, CryptoError> {
    let Some(raw) = bytes.get(..4) else {
        return Err(CryptoError::InvalidLength);
    };
    Ok(u32::from_le_bytes(raw.try_into().unwrap()))
}

fn normalize_aes_alg_id(alg_id: u32, key_len: usize) -> Result<u32, CryptoError> {
    match (alg_id, key_len) {
        (CALG_AES_128, 16) => Ok(CALG_AES_128),
        (CALG_AES_192, 24) => Ok(CALG_AES_192),
        (CALG_AES_256, 32) => Ok(CALG_AES_256),
        (CALG_AES, 16) => Ok(CALG_AES_128),
        (CALG_AES, 24) => Ok(CALG_AES_192),
        (CALG_AES, 32) => Ok(CALG_AES_256),
        (CALG_AES_128 | CALG_AES_192 | CALG_AES_256 | CALG_AES, _) => {
            Err(CryptoError::InvalidLength)
        }
        _ => Err(CryptoError::UnsupportedAlg(alg_id)),
    }
}

fn block_len_bytes(alg_id: u32) -> Result<usize, CryptoError> {
    match alg_id {
        CALG_AES_128 | CALG_AES_192 | CALG_AES_256 => Ok(16),
        _ => Err(CryptoError::UnsupportedAlg(alg_id)),
    }
}

fn encrypt_symmetric(
    key: &mut SymmetricKey,
    final_block: bool,
    input: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let block_len = block_len_bytes(key.alg_id)?;
    let mut buffer = input.to_vec();
    if final_block {
        let pad = block_len - (buffer.len() % block_len);
        buffer.extend(std::iter::repeat_n(pad as u8, pad));
    } else if buffer.len() % block_len != 0 {
        return Err(CryptoError::InvalidLength);
    }
    apply_symmetric_blocks(key, &mut buffer, true, final_block)?;
    Ok(buffer)
}

fn decrypt_symmetric(
    key: &mut SymmetricKey,
    final_block: bool,
    input: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let block_len = block_len_bytes(key.alg_id)?;
    if input.len() % block_len != 0 {
        return Err(CryptoError::InvalidLength);
    }
    let mut buffer = input.to_vec();
    apply_symmetric_blocks(key, &mut buffer, false, final_block)?;
    if final_block {
        trim_pkcs7_padding(&mut buffer, block_len)?;
    }
    Ok(buffer)
}

fn apply_symmetric_blocks(
    key: &mut SymmetricKey,
    buffer: &mut [u8],
    encrypt: bool,
    final_block: bool,
) -> Result<(), CryptoError> {
    let block_len = block_len_bytes(key.alg_id)?;
    if buffer.len() % block_len != 0 {
        return Err(CryptoError::InvalidLength);
    }
    match key.alg_id {
        CALG_AES_128 => apply_aes_blocks::<Aes128>(key, buffer, encrypt, final_block),
        CALG_AES_192 => apply_aes_blocks::<Aes192>(key, buffer, encrypt, final_block),
        CALG_AES_256 => apply_aes_blocks::<Aes256>(key, buffer, encrypt, final_block),
        _ => Err(CryptoError::UnsupportedAlg(key.alg_id)),
    }
}

fn apply_aes_blocks<C>(
    key: &mut SymmetricKey,
    buffer: &mut [u8],
    encrypt: bool,
    final_block: bool,
) -> Result<(), CryptoError>
where
    C: BlockEncrypt + BlockDecrypt + KeyInit,
{
    let cipher = C::new_from_slice(&key.key).map_err(|_| CryptoError::InvalidLength)?;
    match key.mode {
        CryptoKeyMode::Ecb => {
            for chunk in buffer.chunks_exact_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                if encrypt {
                    cipher.encrypt_block(&mut block);
                } else {
                    cipher.decrypt_block(&mut block);
                }
                chunk.copy_from_slice(&block);
            }
        }
        CryptoKeyMode::Cbc => {
            let mut previous = key.feedback.clone();
            if previous.len() != 16 {
                return Err(CryptoError::InvalidLength);
            }
            for chunk in buffer.chunks_exact_mut(16) {
                if encrypt {
                    for (dst, iv_byte) in chunk.iter_mut().zip(previous.iter()) {
                        *dst ^= *iv_byte;
                    }
                    let mut block = GenericArray::clone_from_slice(chunk);
                    cipher.encrypt_block(&mut block);
                    chunk.copy_from_slice(&block);
                    previous.copy_from_slice(chunk);
                } else {
                    let cipher_text = chunk.to_vec();
                    let mut block = GenericArray::clone_from_slice(chunk);
                    cipher.decrypt_block(&mut block);
                    for (dst, iv_byte) in block.iter_mut().zip(previous.iter()) {
                        *dst ^= *iv_byte;
                    }
                    chunk.copy_from_slice(&block);
                    previous.copy_from_slice(&cipher_text);
                }
            }
            if final_block {
                key.feedback.copy_from_slice(&key.iv);
            } else {
                key.feedback.copy_from_slice(&previous);
            }
        }
    }
    Ok(())
}

fn trim_pkcs7_padding(buffer: &mut Vec<u8>, block_len: usize) -> Result<(), CryptoError> {
    let Some(&padding) = buffer.last() else {
        return Err(CryptoError::InvalidPadding);
    };
    let padding = padding as usize;
    if padding == 0 || padding > block_len || padding > buffer.len() {
        return Err(CryptoError::InvalidPadding);
    }
    if !buffer[buffer.len() - padding..]
        .iter()
        .all(|byte| usize::from(*byte) == padding)
    {
        return Err(CryptoError::InvalidPadding);
    }
    buffer.truncate(buffer.len() - padding);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plaintext_aes_blob(key: &[u8], alg_id: u32) -> Vec<u8> {
        let mut blob = vec![PLAINTEXTKEYBLOB, CUR_BLOB_VERSION, 0, 0];
        blob.extend_from_slice(&alg_id.to_le_bytes());
        blob.extend_from_slice(&(key.len() as u32).to_le_bytes());
        blob.extend_from_slice(key);
        blob
    }

    #[test]
    fn imports_plaintext_aes_128_and_decrypts_ecb() {
        let mut manager = CryptoManager::new(HandleTable::new(0xD000));
        let handle = manager
            .import_key(&plaintext_aes_blob(
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ],
                CALG_AES_128,
            ))
            .unwrap();
        manager
            .set_key_param(handle, KP_MODE, &CRYPT_MODE_ECB.to_le_bytes())
            .unwrap();
        let plaintext = manager
            .decrypt_buffer(
                handle,
                false,
                0,
                &[
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ],
            )
            .unwrap();
        assert_eq!(
            plaintext,
            vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
    }

    #[test]
    fn rejects_invalid_pkcs7_padding() {
        let mut manager = CryptoManager::new(HandleTable::new(0xD000));
        let handle = manager
            .import_key(&plaintext_aes_blob(&[0u8; 16], CALG_AES_128))
            .unwrap();
        manager
            .set_key_param(handle, KP_MODE, &CRYPT_MODE_ECB.to_le_bytes())
            .unwrap();
        let error = manager
            .decrypt_buffer(handle, true, 0, &[0u8; 16])
            .unwrap_err();
        assert_eq!(error, CryptoError::InvalidPadding);
    }
}
