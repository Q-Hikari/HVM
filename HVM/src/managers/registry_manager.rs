use std::collections::{BTreeMap, BTreeSet};

pub const HKEY_CLASSES_ROOT: u32 = 0x8000_0000;
pub const HKEY_CURRENT_USER: u32 = 0x8000_0001;
pub const HKEY_LOCAL_MACHINE: u32 = 0x8000_0002;
pub const HKEY_USERS: u32 = 0x8000_0003;
pub const HKEY_CURRENT_CONFIG: u32 = 0x8000_0005;

const ROOT_KEY_NAMES: &[(u32, &str)] = &[
    (HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT"),
    (HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
    (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"),
    (HKEY_USERS, "HKEY_USERS"),
    (HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryValue {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryKey {
    path: String,
    subkeys: BTreeSet<String>,
    values: BTreeMap<String, RegistryValue>,
}

/// Mirrors the Python registry manager used by the legacy runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryManager {
    next_handle: u32,
    handles: BTreeMap<u32, String>,
    keys: BTreeMap<String, RegistryKey>,
}

impl Default for RegistryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryManager {
    pub fn new() -> Self {
        let mut manager = Self {
            next_handle: 0x5000,
            handles: BTreeMap::new(),
            keys: BTreeMap::new(),
        };
        for (_, root_name) in ROOT_KEY_NAMES {
            let normalized = Self::normalize_path(root_name);
            manager.keys.insert(
                normalized.clone(),
                RegistryKey {
                    path: normalized,
                    subkeys: BTreeSet::new(),
                    values: BTreeMap::new(),
                },
            );
        }
        manager.seed_defaults();
        manager
    }

    pub fn open_key(&mut self, root_handle: u32, subkey: &str, create: bool) -> Option<u32> {
        let root = self.resolve_root(root_handle)?;
        let full_path = if subkey.is_empty() {
            root
        } else {
            format!("{root}\\{subkey}")
        };
        let normalized = Self::normalize_path(&full_path);
        if create {
            self.ensure_key(&full_path);
        } else if !self.keys.contains_key(&normalized) {
            return None;
        }
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(4);
        self.handles.insert(handle, normalized);
        Some(handle)
    }

    pub fn create_key(&mut self, root_handle: u32, subkey: &str) -> (Option<u32>, bool) {
        let root = match self.resolve_root(root_handle) {
            Some(root) => root,
            None => return (None, false),
        };
        let full_path = if subkey.is_empty() {
            root
        } else {
            format!("{root}\\{subkey}")
        };
        let normalized = Self::normalize_path(&full_path);
        let existed = self.keys.contains_key(&normalized);
        let handle = self.open_key(root_handle, subkey, true);
        (handle, !existed)
    }

    pub fn full_path_for_handle_and_subkey(
        &self,
        root_handle: u32,
        subkey: &str,
    ) -> Option<String> {
        let root = self.resolve_root(root_handle)?;
        Some(if subkey.is_empty() {
            root
        } else {
            format!("{root}\\{subkey}")
        })
    }

    pub fn full_path_for_handle(&self, handle: u32) -> Option<String> {
        self.resolve_root(handle)
    }

    pub fn close(&mut self, handle: u32) -> bool {
        self.handles.remove(&handle).is_some()
    }

    pub fn query_value(&self, handle: u32, name: &str) -> Option<&RegistryValue> {
        let key = self.lookup_key(handle)?;
        let normalized = name.to_ascii_lowercase();
        key.values
            .get(&normalized)
            .or_else(|| normalized.is_empty().then(|| key.values.get("")).flatten())
    }

    pub fn set_value(&mut self, handle: u32, name: &str, value_type: u32, data: &[u8]) -> bool {
        let Some(path) = self.resolve_path_for_handle(handle) else {
            return false;
        };
        let Some(key) = self.keys.get_mut(&path) else {
            return false;
        };
        key.values.insert(
            name.to_ascii_lowercase(),
            RegistryValue {
                name: name.to_string(),
                value_type,
                data: data.to_vec(),
            },
        );
        true
    }

    pub fn set_value_at_path(
        &mut self,
        path: &str,
        name: &str,
        value_type: u32,
        data: &[u8],
    ) -> bool {
        let normalized = self.ensure_key(path);
        let Some(key) = self.keys.get_mut(&normalized) else {
            return false;
        };
        key.values.insert(
            name.to_ascii_lowercase(),
            RegistryValue {
                name: name.to_string(),
                value_type,
                data: data.to_vec(),
            },
        );
        true
    }

    pub fn delete_value(&mut self, handle: u32, name: &str) -> bool {
        let Some(path) = self.resolve_path_for_handle(handle) else {
            return false;
        };
        let Some(key) = self.keys.get_mut(&path) else {
            return false;
        };
        key.values.remove(&name.to_ascii_lowercase()).is_some()
    }

    pub fn enum_subkey(&self, handle: u32, index: u32) -> Option<&str> {
        let key = self.lookup_key(handle)?;
        key.subkeys.iter().nth(index as usize).map(String::as_str)
    }

    pub fn query_info(&self, handle: u32) -> (u32, u32, u32, u32, u32) {
        let Some(key) = self.lookup_key(handle) else {
            return (0, 0, 0, 0, 0);
        };
        let max_subkey_len = key
            .subkeys
            .iter()
            .map(|name| name.chars().count() as u32)
            .max()
            .unwrap_or(0);
        let max_value_name_len = key
            .values
            .values()
            .map(|value| value.name.chars().count() as u32)
            .max()
            .unwrap_or(0);
        let max_value_len = key
            .values
            .values()
            .map(|value| value.data.len() as u32)
            .max()
            .unwrap_or(0);
        (
            key.subkeys.len() as u32,
            key.values.len() as u32,
            max_subkey_len,
            max_value_name_len,
            max_value_len,
        )
    }

    pub fn delete_key(&mut self, root_handle: u32, subkey: &str) -> bool {
        let Some(root) = self.resolve_root(root_handle) else {
            return false;
        };
        let full_path = if subkey.is_empty() {
            root
        } else {
            format!("{root}\\{subkey}")
        };
        let normalized = Self::normalize_path(&full_path);
        let Some(key) = self.keys.get(&normalized) else {
            return false;
        };
        if !key.subkeys.is_empty() {
            return false;
        }
        if let Some((parent_path, leaf)) = normalized.rsplit_once('\\') {
            if let Some(parent) = self.keys.get_mut(parent_path) {
                parent.subkeys.remove(leaf);
            }
        }
        self.keys.remove(&normalized);
        true
    }

    fn seed_defaults(&mut self) {
        let normalized =
            self.ensure_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        if let Some(key) = self.keys.get_mut(&normalized) {
            key.values.insert(
                "productname".to_string(),
                RegistryValue {
                    name: "ProductName".to_string(),
                    value_type: 1,
                    data: wide_string("Windows 10 Pro"),
                },
            );
            key.values.insert(
                "currentbuild".to_string(),
                RegistryValue {
                    name: "CurrentBuild".to_string(),
                    value_type: 1,
                    data: wide_string("19045"),
                },
            );
            key.values.insert(
                "currentversion".to_string(),
                RegistryValue {
                    name: "CurrentVersion".to_string(),
                    value_type: 1,
                    data: wide_string("10.0"),
                },
            );
            key.values.insert(
                "productid".to_string(),
                RegistryValue {
                    name: "ProductId".to_string(),
                    value_type: 1,
                    data: wide_string("00330-80000-00000-AAOEM"),
                },
            );
        }

        let cryptography = self.ensure_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography");
        if let Some(key) = self.keys.get_mut(&cryptography) {
            key.values.insert(
                "machineguid".to_string(),
                RegistryValue {
                    name: "MachineGuid".to_string(),
                    value_type: 1,
                    data: wide_string("8f2c1e53-9d5a-4c16-9a6e-1e4c2a9f7b31"),
                },
            );
        }
    }

    fn normalize_path(path: &str) -> String {
        path.replace('/', "\\")
            .split('\\')
            .filter(|part| !part.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join("\\")
    }

    fn resolve_root(&self, root_handle: u32) -> Option<String> {
        ROOT_KEY_NAMES
            .iter()
            .find_map(|(handle, name)| (*handle == root_handle).then_some((*name).to_string()))
            .or_else(|| self.handles.get(&root_handle).cloned())
    }

    fn resolve_path_for_handle(&self, handle: u32) -> Option<String> {
        self.resolve_root(handle)
            .map(|path| Self::normalize_path(&path))
    }

    fn lookup_key(&self, handle: u32) -> Option<&RegistryKey> {
        let path = self.resolve_path_for_handle(handle)?;
        self.keys.get(&path)
    }

    fn ensure_key(&mut self, path: &str) -> String {
        let normalized = Self::normalize_path(path);
        if self.keys.contains_key(&normalized) {
            return normalized;
        }

        let mut current = String::new();
        let parts = normalized.split('\\').collect::<Vec<_>>();
        for part in parts {
            let parent = (!current.is_empty()).then(|| current.clone());
            if !current.is_empty() {
                current.push('\\');
            }
            current.push_str(part);
            if !self.keys.contains_key(&current) {
                self.keys.insert(
                    current.clone(),
                    RegistryKey {
                        path: current.clone(),
                        subkeys: BTreeSet::new(),
                        values: BTreeMap::new(),
                    },
                );
                if let Some(parent_path) = parent {
                    if let Some(parent_key) = self.keys.get_mut(&parent_path) {
                        parent_key.subkeys.insert(part.to_string());
                    }
                }
            }
        }

        normalized
    }
}

fn wide_string(value: &str) -> Vec<u8> {
    let mut bytes = value
        .encode_utf16()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    bytes.extend_from_slice(&[0, 0]);
    bytes
}
