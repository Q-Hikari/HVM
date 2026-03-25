use std::collections::BTreeMap;

use crate::environment_profile::ServiceProfile;
use crate::managers::handle_table::HandleTable;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceControlManagerHandle {
    pub machine_name: String,
    pub database_name: String,
    pub access: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHandle {
    pub service_name: String,
    pub access: u32,
}

#[derive(Debug)]
pub struct ServiceManager {
    handles: HandleTable,
    inventory: BTreeMap<String, ServiceProfile>,
}

impl ServiceManager {
    pub fn new(handles: HandleTable, services: Vec<ServiceProfile>) -> Self {
        let mut inventory = BTreeMap::new();
        for service in services {
            if service.name.trim().is_empty() {
                continue;
            }
            inventory.insert(service.name.to_ascii_lowercase(), service);
        }
        Self { handles, inventory }
    }

    pub fn open_manager(&mut self, machine_name: &str, database_name: &str, access: u32) -> u32 {
        self.handles.allocate(
            "sc_manager",
            ServiceControlManagerHandle {
                machine_name: machine_name.to_string(),
                database_name: database_name.to_string(),
                access,
            },
        )
    }

    pub fn is_manager_handle(&self, handle: u32) -> bool {
        self.handles.kind(handle) == Some("sc_manager")
    }

    pub fn open_service(
        &mut self,
        manager_handle: u32,
        service_name: &str,
        access: u32,
    ) -> Option<u32> {
        if !self.is_manager_handle(manager_handle) {
            return None;
        }
        let key = service_name.to_ascii_lowercase();
        let service_name = self.inventory.get(&key)?.name.clone();
        Some(self.handles.allocate(
            "service",
            ServiceHandle {
                service_name,
                access,
            },
        ))
    }

    pub fn is_service_handle(&self, handle: u32) -> bool {
        self.handles.kind(handle) == Some("service")
    }

    pub fn get_service(&self, handle: u32) -> Option<ServiceProfile> {
        if self.handles.kind(handle) != Some("service") {
            return None;
        }
        let payload = self
            .handles
            .with_payload::<ServiceHandle, _, _>(handle, Clone::clone)?;
        self.find_service(&payload.service_name).cloned()
    }

    pub fn find_service(&self, service_name: &str) -> Option<&ServiceProfile> {
        self.inventory.get(&service_name.to_ascii_lowercase())
    }

    pub fn enumerate_services(&self) -> Vec<ServiceProfile> {
        self.inventory.values().cloned().collect()
    }

    pub fn update_service<R, F: FnOnce(&mut ServiceProfile) -> R>(
        &mut self,
        handle: u32,
        update: F,
    ) -> Option<R> {
        let service_name = self
            .handles
            .with_payload::<ServiceHandle, _, _>(handle, |payload| payload.service_name.clone())?;
        let service = self.inventory.get_mut(&service_name.to_ascii_lowercase())?;
        Some(update(service))
    }

    pub fn close_handle(&mut self, handle: u32) -> bool {
        matches!(self.handles.kind(handle), Some("sc_manager" | "service"))
            && self.handles.close(handle)
    }
}
