use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_crypt32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        ctx: &HookContext<'_>,
    ) -> Option<Result<u64, VmError>> {
        let handled = match (module_name, function) {
            ("crypt32.dll", "CertOpenStore") => true,
            ("crypt32.dll", "CertOpenSystemStoreW") => true,
            ("crypt32.dll", "CertCloseStore") => true,
            ("crypt32.dll", "CertAddStoreToCollection") => true,
            ("crypt32.dll", "CertEnumCertificatesInStore") => true,
            ("crypt32.dll", "CertFindCertificateInStore") => true,
            ("crypt32.dll", "CryptMsgOpenToDecode") => true,
            ("crypt32.dll", "CryptMsgClose") => true,
            _ => false,
        };
        if !handled {
            return None;
        }

        Some((|| -> Result<u64, VmError> {
            match (module_name, function) {
                ("crypt32.dll", "CertOpenStore") => {
                    let provider = ctx.raw(0);
                    let collection = provider == 11;
                    let name = if ctx.raw(4) != 0 {
                        self.read_provider_name(ctx.raw(4))?
                    } else {
                        self.read_provider_name(provider)?
                    };
                    let handle = self
                        .network_state
                        .crypto
                        .open_store(non_empty(&name).unwrap_or("SandboxStore"), collection);
                    Ok(handle as u64)
                }
                ("crypt32.dll", "CertOpenSystemStoreW") => {
                    let handle = self.network_state.crypto.open_store(
                        non_empty(&self.read_wide_string_from_memory(ctx.raw(1))?)
                            .unwrap_or("System"),
                        false,
                    );
                    Ok(handle as u64)
                }
                ("crypt32.dll", "CertCloseStore") => {
                    let handle = self
                        .network_state
                        .crypto
                        .close_handle(ctx.raw(0) as u32, "cert_store");
                    Ok(handle as u64)
                }
                ("crypt32.dll", "CertAddStoreToCollection") => {
                    let handle = self
                        .network_state
                        .crypto
                        .add_store_to_collection(ctx.raw(0) as u32, ctx.raw(1) as u32);
                    Ok(handle as u64)
                }
                ("crypt32.dll", "CertEnumCertificatesInStore") => {
                    let handle = self
                        .network_state
                        .crypto
                        .find_certificate(ctx.raw(0) as u32, ctx.raw(1) as u32);
                    Ok(handle as u64)
                }
                ("crypt32.dll", "CertFindCertificateInStore") => {
                    let handle = self
                        .network_state
                        .crypto
                        .find_certificate(ctx.raw(0) as u32, ctx.raw(5) as u32);
                    Ok(handle as u64)
                }
                ("crypt32.dll", "CryptMsgOpenToDecode") => {
                    let handle = self.network_state.crypto.open_message();
                    Ok(handle as u64)
                }
                ("crypt32.dll", "CryptMsgClose") => {
                    let handle = self
                        .network_state
                        .crypto
                        .close_handle(ctx.raw(0) as u32, "crypt_msg");
                    Ok(handle as u64)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
