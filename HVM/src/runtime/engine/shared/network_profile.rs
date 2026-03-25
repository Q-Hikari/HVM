use super::*;

use crate::environment_profile::{NetworkAdapterProfile, NetworkAddressProfile};

#[derive(Debug, Clone, Copy)]
struct IpAddrStringLayout {
    size: u64,
    next_offset: u64,
    ip_offset: u64,
    mask_offset: u64,
    context_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct AdapterInfoLayout {
    size: u64,
    next_offset: u64,
    combo_index_offset: u64,
    adapter_name_offset: u64,
    description_offset: u64,
    address_length_offset: u64,
    address_offset: u64,
    index_offset: u64,
    type_offset: u64,
    dhcp_enabled_offset: u64,
    current_ip_offset: u64,
    ip_list_offset: u64,
    gateway_list_offset: u64,
    dhcp_server_offset: u64,
    have_wins_offset: u64,
    primary_wins_offset: u64,
    secondary_wins_offset: u64,
    lease_obtained_offset: u64,
    lease_expires_offset: u64,
    ip_addr_layout: IpAddrStringLayout,
}

#[derive(Debug, Clone, Copy)]
struct FixedInfoLayout {
    size: u64,
    host_name_offset: u64,
    domain_name_offset: u64,
    current_dns_offset: u64,
    dns_list_offset: u64,
    node_type_offset: u64,
    scope_id_offset: u64,
    enable_routing_offset: u64,
    enable_proxy_offset: u64,
    enable_dns_offset: u64,
    ip_addr_layout: IpAddrStringLayout,
}

#[derive(Debug, Clone, Copy)]
struct AdapterAddressesLayout {
    size: u64,
    next_offset: u64,
    adapter_name_offset: u64,
    first_unicast_offset: u64,
    dns_suffix_offset: u64,
    description_offset: u64,
    friendly_name_offset: u64,
    physical_address_offset: u64,
    physical_address_length_offset: u64,
    flags_offset: u64,
    mtu_offset: u64,
    if_type_offset: u64,
    oper_status_offset: u64,
    ipv6_if_index_offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct UnicastAddressLayout {
    size: u64,
    next_offset: u64,
    socket_address_offset: u64,
    socket_length_offset: u64,
    prefix_origin_offset: u64,
    suffix_origin_offset: u64,
    dad_state_offset: u64,
    valid_lifetime_offset: u64,
    preferred_lifetime_offset: u64,
    lease_lifetime_offset: u64,
    on_link_prefix_length_offset: u64,
}

impl VirtualExecutionEngine {
    fn effective_network_host_name(&self) -> String {
        let configured = self.environment_profile.network.host_name.trim();
        if configured.is_empty() {
            self.active_computer_name().to_string()
        } else {
            configured.to_string()
        }
    }

    fn effective_network_domain_name(&self) -> String {
        let configured = self.environment_profile.network.domain_name.trim();
        if !configured.is_empty() {
            return configured.to_string();
        }
        let suffix = self.environment_profile.network.dns_suffix.trim();
        if !suffix.is_empty() {
            return suffix.to_string();
        }
        "lan".to_string()
    }

    fn effective_network_dns_suffix(&self, adapter: &NetworkAdapterProfile) -> String {
        if !adapter.dns_suffix.trim().is_empty() {
            adapter.dns_suffix.clone()
        } else if !self
            .environment_profile
            .network
            .dns_suffix
            .trim()
            .is_empty()
        {
            self.environment_profile.network.dns_suffix.clone()
        } else {
            self.effective_network_domain_name()
        }
    }

    fn effective_network_dns_servers(
        &self,
        adapter: Option<&NetworkAdapterProfile>,
    ) -> Vec<String> {
        if let Some(adapter) = adapter {
            if !adapter.dns_servers.is_empty() {
                return adapter.dns_servers.clone();
            }
        }
        if !self.environment_profile.network.dns_servers.is_empty() {
            return self.environment_profile.network.dns_servers.clone();
        }
        vec!["192.168.56.1".to_string()]
    }

    fn effective_network_adapters(&self) -> Vec<NetworkAdapterProfile> {
        if self.environment_profile.network.adapters.is_empty() {
            vec![NetworkAdapterProfile::default()]
        } else {
            self.environment_profile.network.adapters.clone()
        }
    }

    fn ip_addr_string_layout(&self) -> IpAddrStringLayout {
        if self.arch.is_x86() {
            IpAddrStringLayout {
                size: 40,
                next_offset: 0,
                ip_offset: 4,
                mask_offset: 20,
                context_offset: 36,
            }
        } else {
            IpAddrStringLayout {
                size: 48,
                next_offset: 0,
                ip_offset: 8,
                mask_offset: 24,
                context_offset: 40,
            }
        }
    }

    fn ip_adapter_info_layout(&self) -> AdapterInfoLayout {
        let ip_addr_layout = self.ip_addr_string_layout();
        if self.arch.is_x86() {
            AdapterInfoLayout {
                size: 640,
                next_offset: 0,
                combo_index_offset: 4,
                adapter_name_offset: 8,
                description_offset: 268,
                address_length_offset: 400,
                address_offset: 404,
                index_offset: 412,
                type_offset: 416,
                dhcp_enabled_offset: 420,
                current_ip_offset: 424,
                ip_list_offset: 428,
                gateway_list_offset: 468,
                dhcp_server_offset: 508,
                have_wins_offset: 548,
                primary_wins_offset: 552,
                secondary_wins_offset: 592,
                lease_obtained_offset: 632,
                lease_expires_offset: 636,
                ip_addr_layout,
            }
        } else {
            AdapterInfoLayout {
                size: 704,
                next_offset: 0,
                combo_index_offset: 8,
                adapter_name_offset: 12,
                description_offset: 272,
                address_length_offset: 404,
                address_offset: 408,
                index_offset: 416,
                type_offset: 420,
                dhcp_enabled_offset: 424,
                current_ip_offset: 432,
                ip_list_offset: 440,
                gateway_list_offset: 488,
                dhcp_server_offset: 536,
                have_wins_offset: 584,
                primary_wins_offset: 592,
                secondary_wins_offset: 640,
                lease_obtained_offset: 688,
                lease_expires_offset: 696,
                ip_addr_layout,
            }
        }
    }

    fn fixed_info_layout(&self) -> FixedInfoLayout {
        let ip_addr_layout = self.ip_addr_string_layout();
        if self.arch.is_x86() {
            FixedInfoLayout {
                size: 584,
                host_name_offset: 0,
                domain_name_offset: 132,
                current_dns_offset: 264,
                dns_list_offset: 268,
                node_type_offset: 308,
                scope_id_offset: 312,
                enable_routing_offset: 572,
                enable_proxy_offset: 576,
                enable_dns_offset: 580,
                ip_addr_layout,
            }
        } else {
            FixedInfoLayout {
                size: 600,
                host_name_offset: 0,
                domain_name_offset: 132,
                current_dns_offset: 264,
                dns_list_offset: 272,
                node_type_offset: 320,
                scope_id_offset: 324,
                enable_routing_offset: 584,
                enable_proxy_offset: 588,
                enable_dns_offset: 592,
                ip_addr_layout,
            }
        }
    }

    fn ip_adapter_addresses_layout(&self) -> AdapterAddressesLayout {
        if self.arch.is_x86() {
            AdapterAddressesLayout {
                size: 144,
                next_offset: 8,
                adapter_name_offset: 12,
                first_unicast_offset: 16,
                dns_suffix_offset: 32,
                description_offset: 36,
                friendly_name_offset: 40,
                physical_address_offset: 44,
                physical_address_length_offset: 52,
                flags_offset: 56,
                mtu_offset: 60,
                if_type_offset: 64,
                oper_status_offset: 68,
                ipv6_if_index_offset: 72,
            }
        } else {
            AdapterAddressesLayout {
                size: 184,
                next_offset: 8,
                adapter_name_offset: 16,
                first_unicast_offset: 24,
                dns_suffix_offset: 56,
                description_offset: 64,
                friendly_name_offset: 72,
                physical_address_offset: 80,
                physical_address_length_offset: 88,
                flags_offset: 92,
                mtu_offset: 96,
                if_type_offset: 100,
                oper_status_offset: 104,
                ipv6_if_index_offset: 108,
            }
        }
    }

    fn unicast_address_layout(&self) -> UnicastAddressLayout {
        if self.arch.is_x86() {
            UnicastAddressLayout {
                size: 48,
                next_offset: 8,
                socket_address_offset: 12,
                socket_length_offset: 16,
                prefix_origin_offset: 20,
                suffix_origin_offset: 24,
                dad_state_offset: 28,
                valid_lifetime_offset: 32,
                preferred_lifetime_offset: 36,
                lease_lifetime_offset: 40,
                on_link_prefix_length_offset: 44,
            }
        } else {
            UnicastAddressLayout {
                size: 64,
                next_offset: 8,
                socket_address_offset: 16,
                socket_length_offset: 24,
                prefix_origin_offset: 32,
                suffix_origin_offset: 36,
                dad_state_offset: 40,
                valid_lifetime_offset: 44,
                preferred_lifetime_offset: 48,
                lease_lifetime_offset: 52,
                on_link_prefix_length_offset: 56,
            }
        }
    }

    pub(in crate::runtime::engine) fn iphlpapi_get_number_of_interfaces(
        &mut self,
        count_ptr: u64,
    ) -> Result<u64, VmError> {
        if count_ptr == 0 {
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let count = self
            .effective_network_adapters()
            .len()
            .min(u32::MAX as usize) as u32;
        self.write_u32(count_ptr, count)?;
        Ok(ERROR_SUCCESS)
    }

    pub(in crate::runtime::engine) fn iphlpapi_get_best_interface(
        &mut self,
        best_if_index_ptr: u64,
    ) -> Result<u64, VmError> {
        if best_if_index_ptr == 0 {
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let Some(adapter) = self.effective_network_adapters().into_iter().next() else {
            self.write_u32(best_if_index_ptr, 0)?;
            return Ok(ERROR_NO_DATA);
        };
        self.write_u32(best_if_index_ptr, adapter.if_index)?;
        Ok(ERROR_SUCCESS)
    }

    pub(in crate::runtime::engine) fn iphlpapi_get_friendly_if_index(&self, if_index: u32) -> u64 {
        if_index as u64
    }

    pub(in crate::runtime::engine) fn iphlpapi_get_network_params(
        &mut self,
        buffer: u64,
        size_ptr: u64,
    ) -> Result<u64, VmError> {
        let layout = self.fixed_info_layout();
        let dns_servers = self.effective_network_dns_servers(None);
        let extra_dns_nodes = dns_servers.len().saturating_sub(1) as u64;
        let required = layout.size + extra_dns_nodes * layout.ip_addr_layout.size;
        if size_ptr == 0 {
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let available = self.read_u32(size_ptr).unwrap_or(0) as u64;
        self.write_u32(size_ptr, required.min(u32::MAX as u64) as u32)?;
        if buffer == 0 || available < required {
            return Ok(ERROR_BUFFER_OVERFLOW);
        }

        self.fill_memory_pattern(buffer, required, 0)?;
        let host_name = self.effective_network_host_name();
        let domain_name = self.effective_network_domain_name();
        let scope_id = self.environment_profile.network.scope_id.clone();
        self.write_c_string_to_memory(buffer + layout.host_name_offset, 132, &host_name)?;
        self.write_c_string_to_memory(buffer + layout.domain_name_offset, 132, &domain_name)?;
        self.write_pointer_value(buffer + layout.current_dns_offset, 0)?;
        self.write_u32(
            buffer + layout.node_type_offset,
            self.environment_profile.network.node_type,
        )?;
        self.write_c_string_to_memory(buffer + layout.scope_id_offset, 260, &scope_id)?;
        self.write_u32(
            buffer + layout.enable_routing_offset,
            self.environment_profile.network.enable_routing as u32,
        )?;
        self.write_u32(
            buffer + layout.enable_proxy_offset,
            self.environment_profile.network.enable_proxy as u32,
        )?;
        self.write_u32(
            buffer + layout.enable_dns_offset,
            self.environment_profile.network.enable_dns as u32,
        )?;

        let mut extra_cursor = buffer + layout.size;
        self.write_ip_addr_string_chain(
            buffer + layout.dns_list_offset,
            &dns_servers
                .into_iter()
                .map(|server| NetworkAddressProfile {
                    address: server,
                    netmask: "0.0.0.0".to_string(),
                })
                .collect::<Vec<_>>(),
            &mut extra_cursor,
            layout.ip_addr_layout,
        )?;
        Ok(ERROR_SUCCESS)
    }

    pub(in crate::runtime::engine) fn iphlpapi_get_adapters_info(
        &mut self,
        buffer: u64,
        size_ptr: u64,
    ) -> Result<u64, VmError> {
        let layout = self.ip_adapter_info_layout();
        let adapters = self.effective_network_adapters();
        if adapters.is_empty() {
            if size_ptr != 0 {
                self.write_u32(size_ptr, 0)?;
            }
            return Ok(ERROR_NO_DATA);
        }
        let extra_nodes = adapters
            .iter()
            .map(|adapter| {
                adapter.ipv4_addresses.len().saturating_sub(1)
                    + adapter.gateways.len().saturating_sub(1)
            })
            .sum::<usize>() as u64;
        let required =
            adapters.len() as u64 * layout.size + extra_nodes * layout.ip_addr_layout.size;
        if size_ptr == 0 {
            return Ok(ERROR_INVALID_PARAMETER);
        }
        let available = self.read_u32(size_ptr).unwrap_or(0) as u64;
        self.write_u32(size_ptr, required.min(u32::MAX as u64) as u32)?;
        if buffer == 0 || available < required {
            return Ok(ERROR_BUFFER_OVERFLOW);
        }

        self.fill_memory_pattern(buffer, required, 0)?;
        let mut extra_cursor = buffer + adapters.len() as u64 * layout.size;
        for (index, adapter) in adapters.iter().enumerate() {
            let base = buffer + index as u64 * layout.size;
            let next = if index + 1 < adapters.len() {
                base + layout.size
            } else {
                0
            };
            self.write_pointer_value(base + layout.next_offset, next)?;
            self.write_u32(base + layout.combo_index_offset, adapter.if_index)?;
            self.write_c_string_to_memory(base + layout.adapter_name_offset, 260, &adapter.name)?;
            self.write_c_string_to_memory(
                base + layout.description_offset,
                132,
                &adapter.description,
            )?;

            let mac = parse_mac_address_bytes(&adapter.mac_address);
            self.write_u32(base + layout.address_length_offset, mac.len().min(8) as u32)?;
            if !mac.is_empty() {
                self.write_raw_bytes_to_memory(base + layout.address_offset, 8, &mac)?;
            }
            self.write_u32(base + layout.index_offset, adapter.if_index)?;
            self.write_u32(base + layout.type_offset, adapter.adapter_type)?;
            self.write_u32(
                base + layout.dhcp_enabled_offset,
                adapter.dhcp_enabled as u32,
            )?;
            self.write_pointer_value(base + layout.current_ip_offset, 0)?;
            self.write_ip_addr_string_chain(
                base + layout.ip_list_offset,
                &effective_ipv4_addresses(adapter),
                &mut extra_cursor,
                layout.ip_addr_layout,
            )?;
            self.write_ip_addr_string_chain(
                base + layout.gateway_list_offset,
                &effective_gateway_entries(adapter),
                &mut extra_cursor,
                layout.ip_addr_layout,
            )?;
            self.write_ip_addr_string_chain(
                base + layout.dhcp_server_offset,
                &[NetworkAddressProfile {
                    address: effective_dhcp_server(adapter),
                    netmask: "0.0.0.0".to_string(),
                }],
                &mut extra_cursor,
                layout.ip_addr_layout,
            )?;
            self.write_u32(base + layout.have_wins_offset, 0)?;
            self.write_ip_addr_string_chain(
                base + layout.primary_wins_offset,
                &[NetworkAddressProfile {
                    address: "0.0.0.0".to_string(),
                    netmask: "0.0.0.0".to_string(),
                }],
                &mut extra_cursor,
                layout.ip_addr_layout,
            )?;
            self.write_ip_addr_string_chain(
                base + layout.secondary_wins_offset,
                &[NetworkAddressProfile {
                    address: "0.0.0.0".to_string(),
                    netmask: "0.0.0.0".to_string(),
                }],
                &mut extra_cursor,
                layout.ip_addr_layout,
            )?;
            self.write_service_time(base + layout.lease_obtained_offset, 0)?;
            self.write_service_time(base + layout.lease_expires_offset, 0)?;
        }
        Ok(ERROR_SUCCESS)
    }

    pub(in crate::runtime::engine) fn iphlpapi_get_adapters_addresses(
        &mut self,
        family: u64,
        buffer: u64,
        size_ptr: u64,
    ) -> Result<u64, VmError> {
        if size_ptr == 0 {
            return Ok(ERROR_INVALID_PARAMETER);
        }
        if family != 0 && family != AF_INET as u64 {
            self.write_u32(size_ptr, 0)?;
            return Ok(ERROR_NO_DATA);
        }

        let adapters = self
            .effective_network_adapters()
            .into_iter()
            .filter(|adapter| !adapter.ipv4_addresses.is_empty())
            .collect::<Vec<_>>();
        if adapters.is_empty() {
            self.write_u32(size_ptr, 0)?;
            return Ok(ERROR_NO_DATA);
        }

        let layout = self.ip_adapter_addresses_layout();
        let unicast_layout = self.unicast_address_layout();
        let unicast_count = adapters
            .iter()
            .map(|adapter| adapter.ipv4_addresses.len())
            .sum::<usize>() as u64;

        let mut required = adapters.len() as u64 * layout.size;
        required = align_up(required, self.arch.pointer_size as u64);
        required += unicast_count * unicast_layout.size;
        required = align_up(required, 4);
        required += unicast_count * 16;
        required = align_up(required, self.arch.pointer_size as u64);
        for adapter in &adapters {
            let dns_suffix = self.effective_network_dns_suffix(adapter);
            required += (adapter.name.len() + 1) as u64;
            required = align_up(required, 2);
            required += wide_storage_size(&dns_suffix);
            required = align_up(required, 2);
            required += wide_storage_size(&adapter.description);
            required = align_up(required, 2);
            required += wide_storage_size(&adapter.friendly_name);
            required = align_up(required, self.arch.pointer_size as u64);
        }

        let available = self.read_u32(size_ptr).unwrap_or(0) as u64;
        self.write_u32(size_ptr, required.min(u32::MAX as u64) as u32)?;
        if buffer == 0 || available < required {
            return Ok(ERROR_BUFFER_OVERFLOW);
        }

        self.fill_memory_pattern(buffer, required, 0)?;
        let base_end = buffer + adapters.len() as u64 * layout.size;
        let mut unicast_cursor = align_up(base_end, self.arch.pointer_size as u64);
        let sockaddr_start = align_up(unicast_cursor + unicast_count * unicast_layout.size, 4);
        let mut sockaddr_cursor = sockaddr_start;
        let mut string_cursor = align_up(
            sockaddr_start + unicast_count * 16,
            self.arch.pointer_size as u64,
        );

        for (index, adapter) in adapters.iter().enumerate() {
            let base = buffer + index as u64 * layout.size;
            let next = if index + 1 < adapters.len() {
                base + layout.size
            } else {
                0
            };
            self.write_u32(base, layout.size as u32)?;
            self.write_u32(base + 4, adapter.if_index)?;
            self.write_pointer_value(base + layout.next_offset, next)?;

            let adapter_name = write_inline_ansi_string(self, &mut string_cursor, &adapter.name)?;
            let dns_suffix_text = self.effective_network_dns_suffix(adapter);
            let dns_suffix = write_inline_wide_string(self, &mut string_cursor, &dns_suffix_text)?;
            let description =
                write_inline_wide_string(self, &mut string_cursor, &adapter.description)?;
            let friendly_name =
                write_inline_wide_string(self, &mut string_cursor, &adapter.friendly_name)?;

            self.write_pointer_value(base + layout.adapter_name_offset, adapter_name)?;
            self.write_pointer_value(base + layout.dns_suffix_offset, dns_suffix)?;
            self.write_pointer_value(base + layout.description_offset, description)?;
            self.write_pointer_value(base + layout.friendly_name_offset, friendly_name)?;

            let mac = parse_mac_address_bytes(&adapter.mac_address);
            self.write_u32(
                base + layout.physical_address_length_offset,
                mac.len().min(8) as u32,
            )?;
            if !mac.is_empty() {
                self.write_raw_bytes_to_memory(base + layout.physical_address_offset, 8, &mac)?;
            }
            self.write_u32(base + layout.flags_offset, 0x0000_0080)?;
            self.write_u32(base + layout.mtu_offset, adapter.mtu)?;
            self.write_u32(base + layout.if_type_offset, adapter.adapter_type)?;
            self.write_u32(base + layout.oper_status_offset, adapter.oper_status)?;
            self.write_u32(base + layout.ipv6_if_index_offset, 0)?;

            let addresses = effective_ipv4_addresses(adapter);
            if addresses.is_empty() {
                self.write_pointer_value(base + layout.first_unicast_offset, 0)?;
                continue;
            }

            let mut unicast_nodes = Vec::with_capacity(addresses.len());
            for _ in &addresses {
                unicast_nodes.push(unicast_cursor);
                unicast_cursor += unicast_layout.size;
            }
            self.write_pointer_value(base + layout.first_unicast_offset, unicast_nodes[0])?;
            for (address_index, address) in addresses.iter().enumerate() {
                let node = unicast_nodes[address_index];
                let next_node = unicast_nodes.get(address_index + 1).copied().unwrap_or(0);
                let sockaddr = sockaddr_cursor;
                sockaddr_cursor += 16;

                self.write_u32(node, unicast_layout.size as u32)?;
                self.write_u32(node + 4, 0)?;
                self.write_pointer_value(node + unicast_layout.next_offset, next_node)?;
                self.write_pointer_value(node + unicast_layout.socket_address_offset, sockaddr)?;
                self.write_u32(node + unicast_layout.socket_length_offset, 16)?;
                self.write_u32(node + unicast_layout.prefix_origin_offset, 3)?;
                self.write_u32(node + unicast_layout.suffix_origin_offset, 1)?;
                self.write_u32(node + unicast_layout.dad_state_offset, 4)?;
                self.write_u32(node + unicast_layout.valid_lifetime_offset, u32::MAX)?;
                self.write_u32(node + unicast_layout.preferred_lifetime_offset, u32::MAX)?;
                self.write_u32(node + unicast_layout.lease_lifetime_offset, u32::MAX)?;
                self.modules.memory_mut().write(
                    node + unicast_layout.on_link_prefix_length_offset,
                    &[ipv4_prefix_length(&address.netmask)],
                )?;
                self.write_sockaddr(sockaddr, &address.address, 0)?;
            }
        }

        Ok(ERROR_SUCCESS)
    }

    fn write_ip_addr_string_chain(
        &mut self,
        first_node: u64,
        entries: &[NetworkAddressProfile],
        extra_cursor: &mut u64,
        layout: IpAddrStringLayout,
    ) -> Result<(), VmError> {
        let effective = if entries.is_empty() {
            vec![NetworkAddressProfile {
                address: "0.0.0.0".to_string(),
                netmask: "0.0.0.0".to_string(),
            }]
        } else {
            entries.to_vec()
        };
        let mut node_addresses = Vec::with_capacity(effective.len());
        node_addresses.push(first_node);
        for _ in effective.iter().skip(1) {
            node_addresses.push(*extra_cursor);
            *extra_cursor += layout.size;
        }

        for (index, entry) in effective.iter().enumerate() {
            let node = node_addresses[index];
            let next = node_addresses.get(index + 1).copied().unwrap_or(0);
            self.write_pointer_value(node + layout.next_offset, next)?;
            self.write_c_string_to_memory(node + layout.ip_offset, 16, &entry.address)?;
            self.write_c_string_to_memory(node + layout.mask_offset, 16, &entry.netmask)?;
            self.write_u32(node + layout.context_offset, 0)?;
        }
        Ok(())
    }

    fn write_service_time(&mut self, address: u64, value: i64) -> Result<(), VmError> {
        if self.arch.is_x86() {
            self.write_u32(address, value as u32)
        } else {
            self.modules
                .memory_mut()
                .write(address, &value.to_le_bytes())
                .map_err(VmError::from)
        }
    }
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        (value + (align - 1)) & !(align - 1)
    }
}

fn wide_storage_size(value: &str) -> u64 {
    ((value.encode_utf16().count() + 1) * 2) as u64
}

fn write_inline_ansi_string(
    engine: &mut VirtualExecutionEngine,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, VmError> {
    let address = *cursor;
    let capacity = value.len() + 1;
    engine.write_c_string_to_memory(address, capacity, value)?;
    *cursor += capacity as u64;
    Ok(address)
}

fn write_inline_wide_string(
    engine: &mut VirtualExecutionEngine,
    cursor: &mut u64,
    value: &str,
) -> Result<u64, VmError> {
    *cursor = align_up(*cursor, 2);
    let address = *cursor;
    let capacity = value.encode_utf16().count() + 1;
    engine.write_wide_string_to_memory(address, capacity, value)?;
    *cursor += (capacity * 2) as u64;
    *cursor = align_up(*cursor, engine.arch.pointer_size as u64);
    Ok(address)
}

fn effective_ipv4_addresses(adapter: &NetworkAdapterProfile) -> Vec<NetworkAddressProfile> {
    if adapter.ipv4_addresses.is_empty() {
        vec![NetworkAddressProfile {
            address: "0.0.0.0".to_string(),
            netmask: "0.0.0.0".to_string(),
        }]
    } else {
        adapter.ipv4_addresses.clone()
    }
}

fn effective_gateway_entries(adapter: &NetworkAdapterProfile) -> Vec<NetworkAddressProfile> {
    if adapter.gateways.is_empty() {
        vec![NetworkAddressProfile {
            address: "0.0.0.0".to_string(),
            netmask: "0.0.0.0".to_string(),
        }]
    } else {
        adapter
            .gateways
            .iter()
            .cloned()
            .map(|gateway| NetworkAddressProfile {
                address: gateway,
                netmask: "0.0.0.0".to_string(),
            })
            .collect()
    }
}

fn effective_dhcp_server(adapter: &NetworkAdapterProfile) -> String {
    if adapter.dhcp_enabled && !adapter.dhcp_server.trim().is_empty() {
        adapter.dhcp_server.clone()
    } else {
        "0.0.0.0".to_string()
    }
}

fn parse_mac_address_bytes(raw: &str) -> Vec<u8> {
    let compact = raw
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    if compact.len() < 2 {
        return Vec::new();
    }
    let mut bytes = Vec::with_capacity(compact.len() / 2);
    let raw_bytes = compact.as_bytes();
    let mut index = 0usize;
    while index + 1 < raw_bytes.len() {
        let Ok(slice) = std::str::from_utf8(&raw_bytes[index..index + 2]) else {
            break;
        };
        let Ok(byte) = u8::from_str_radix(slice, 16) else {
            break;
        };
        bytes.push(byte);
        index += 2;
    }
    bytes
}

fn ipv4_prefix_length(netmask: &str) -> u8 {
    netmask
        .parse::<Ipv4Addr>()
        .map(|address| {
            address
                .octets()
                .into_iter()
                .map(|octet| octet.count_ones() as u8)
                .sum()
        })
        .unwrap_or(0)
}
