use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn dispatch_crypt32_hook(
        &mut self,
        module_name: &str,
        function: &str,
        args: &[u64],
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
                    let provider = arg(args, 0);
                    let collection = provider == 11;
                    let name = if arg(args, 4) != 0 {
                        self.read_provider_name(arg(args, 4))?
                    } else {
                        self.read_provider_name(provider)?
                    };
                    Ok(self
                        .crypto
                        .open_store(non_empty(&name).unwrap_or("SandboxStore"), collection)
                        as u64)
                }
                ("crypt32.dll", "CertOpenSystemStoreW") => Ok(self.crypto.open_store(
                    non_empty(&self.read_wide_string_from_memory(arg(args, 1))?)
                        .unwrap_or("System"),
                    false,
                ) as u64),
                ("crypt32.dll", "CertCloseStore") => {
                    Ok(self.crypto.close_handle(arg(args, 0) as u32, "cert_store") as u64)
                }
                ("crypt32.dll", "CertAddStoreToCollection") => Ok(self
                    .crypto
                    .add_store_to_collection(arg(args, 0) as u32, arg(args, 1) as u32)
                    as u64),
                ("crypt32.dll", "CertEnumCertificatesInStore") => Ok(self
                    .crypto
                    .find_certificate(arg(args, 0) as u32, arg(args, 1) as u32)
                    as u64),
                ("crypt32.dll", "CertFindCertificateInStore") => Ok(self
                    .crypto
                    .find_certificate(arg(args, 0) as u32, arg(args, 5) as u32)
                    as u64),
                ("crypt32.dll", "CryptMsgOpenToDecode") => Ok(self.crypto.open_message() as u64),
                ("crypt32.dll", "CryptMsgClose") => {
                    Ok(self.crypto.close_handle(arg(args, 0) as u32, "crypt_msg") as u64)
                }
                _ => unreachable!("prechecked extracted dispatch should always match"),
            }
        })())
    }
}
