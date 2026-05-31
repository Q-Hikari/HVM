/// Virtual path mapping for anti-VM detection bypass.
///
/// This module provides Windows-style virtual paths for modules loaded in the
/// emulated environment. This is critical for bypassing anti-VM detection that
/// checks module paths in the LDR_DATA_TABLE_ENTRY structure.
use std::path::Path;

/// Represents a Windows path style for module loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsPathStyle {
    /// Main executable: e.g., "F:\sample.exe"
    MainExecutable,
    /// System32 DLL (native bitness): e.g., "C:\Windows\System32\ntdll.dll"
    System32,
    /// SysWOW64 DLL (32-bit on 64-bit OS): e.g., "C:\Windows\SysWOW64\ntdll.dll"
    SysWOW64,
    /// Application directory: e.g., "F:\dependency.dll"
    AppDirectory,
}

/// Virtual path mapper for converting Linux paths to Windows-style paths.
#[derive(Debug, Clone)]
pub struct VirtualPathMapper {
    /// The drive letter for the main executable (e.g., 'F')
    main_drive: char,
    /// Main application directory (e.g., "F:\\" or "F:\\Sample")
    main_directory: String,
    /// System root directory (usually "C:\Windows")
    system_root: String,
    /// System DLL directory (usually "C:\Windows\System32" or "C:\Windows\SysWOW64")
    system_directory: String,
}

impl Default for VirtualPathMapper {
    fn default() -> Self {
        Self {
            main_drive: 'F',
            main_directory: "F:\\".to_string(),
            system_root: "C:\\Windows".to_string(),
            system_directory: "C:\\Windows\\System32".to_string(),
        }
    }
}

impl VirtualPathMapper {
    /// Creates a new virtual path mapper.
    pub fn new(main_drive: char, is_wow64: bool) -> Self {
        let main_directory = format!("{main_drive}:\\");
        let system_root = "C:\\Windows".to_string();
        let system_directory = format!(
            "{}\\{}",
            system_root,
            if is_wow64 { "SysWOW64" } else { "System32" }
        );
        Self {
            main_drive,
            main_directory,
            system_root,
            system_directory,
        }
    }

    /// Creates a mapper from runtime/profile paths instead of guessing from architecture.
    pub fn from_environment(image_path: &str, system_root: &str, system_directory: &str) -> Self {
        Self::from_environment_with_module_directory(
            image_path,
            system_root,
            system_directory,
            None,
        )
    }

    /// Creates a mapper from runtime/profile paths and an optional runtime module-directory hint.
    ///
    /// When the configured module directory ends with `System32` or `SysWOW64`, prefer that
    /// subdirectory under the guest Windows root so loader-visible DLL paths reflect the active
    /// process bitness rather than the host snapshot path.
    pub fn from_environment_with_module_directory(
        image_path: &str,
        system_root: &str,
        system_directory: &str,
        module_directory: Option<&Path>,
    ) -> Self {
        let normalized_system_root = Self::normalize_windows_directory(system_root, "C:\\Windows");
        let normalized_system_directory = module_directory
            .and_then(Self::guest_system_subdirectory_from_module_directory)
            .map(|subdirectory| Self::join_windows_path(&normalized_system_root, subdirectory))
            .unwrap_or_else(|| {
                Self::normalize_windows_directory(system_directory, "C:\\Windows\\System32")
            });
        let main_directory = Self::windows_parent_directory(image_path)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "F:\\".to_string());
        let main_drive = image_path
            .chars()
            .next()
            .filter(|value| value.is_ascii_alphabetic())
            .map(|value| value.to_ascii_uppercase())
            .unwrap_or('F');

        Self {
            main_drive,
            main_directory,
            system_root: normalized_system_root,
            system_directory: normalized_system_directory,
        }
    }

    fn guest_system_subdirectory_from_module_directory(
        module_directory: &Path,
    ) -> Option<&'static str> {
        let directory_name = module_directory.file_name()?.to_string_lossy();
        if directory_name.eq_ignore_ascii_case("system32") {
            Some("System32")
        } else if directory_name.eq_ignore_ascii_case("syswow64") {
            Some("SysWOW64")
        } else {
            None
        }
    }

    /// Maps a Linux module path to a Windows-style virtual path.
    ///
    /// # Arguments
    /// * `linux_path` - The original Linux file path
    /// * `module_name` - The module name (e.g., "ntdll.dll")
    /// * `is_main_module` - Whether this is the main executable
    /// * `is_system_dll` - Whether this is a system DLL
    ///
    /// # Returns
    /// A Windows-style path string
    pub fn map_path(
        &self,
        linux_path: &str,
        module_name: &str,
        is_main_module: bool,
        is_system_dll: bool,
    ) -> String {
        if is_main_module {
            let filename = Path::new(linux_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| module_name.to_string());
            Self::join_windows_path(&self.main_directory, &filename)
        } else if is_system_dll {
            Self::join_windows_path(&self.system_directory, module_name)
        } else {
            Self::join_windows_path(&self.main_directory, module_name)
        }
    }

    fn join_windows_path(base: &str, leaf: &str) -> String {
        format!("{}\\{}", base.trim_end_matches(['\\', '/']), leaf)
    }

    fn normalize_windows_directory(value: &str, fallback: &str) -> String {
        let trimmed = value.trim().trim_end_matches(['\\', '/']);
        if trimmed.is_empty() {
            fallback.to_string()
        } else {
            trimmed.to_string()
        }
    }

    fn windows_parent_directory(path: &str) -> Option<String> {
        let trimmed = path.trim().trim_end_matches(['\\', '/']);
        let separator = trimmed.rfind(['\\', '/'])?;
        let parent = &trimmed[..separator];
        if parent.is_empty() {
            None
        } else if parent.ends_with(':') {
            Some(format!("{parent}\\"))
        } else {
            Some(parent.to_string())
        }
    }

    /// Returns the system root path (e.g., "C:\Windows").
    pub fn system_root(&self) -> &str {
        &self.system_root
    }

    /// Returns the main drive letter.
    pub fn main_drive(&self) -> char {
        self.main_drive
    }

    /// Checks if a module name is a known system DLL.
    pub fn is_system_dll(module_name: &str) -> bool {
        let name_lower = module_name.to_lowercase();

        // Common system DLLs
        let system_dlls = [
            "ntdll.dll",
            "kernel32.dll",
            "kernelbase.dll",
            "advapi32.dll",
            "user32.dll",
            "gdi32.dll",
            "shell32.dll",
            "shlwapi.dll",
            "ole32.dll",
            "oleaut32.dll",
            "comdlg32.dll",
            "comctl32.dll",
            "version.dll",
            "imagehlp.dll",
            "psapi.dll",
            "ws2_32.dll",
            "wininet.dll",
            "urlmon.dll",
            "crypt32.dll",
            "bcrypt.dll",
            "rpcrt4.dll",
            "sechost.dll",
            "msvcrt.dll",
            "lpk.dll",
            "usp10.dll",
            "win32u.dll",
            "imm32.dll",
            "winmm.dll",
            "setupapi.dll",
            "cfgmgr32.dll",
            "devobj.dll",
            "dwmapi.dll",
            "uxtheme.dll",
            "msimg32.dll",
            "gdiplus.dll",
            "opengl32.dll",
            "glu32.dll",
            "wsock32.dll",
            "mswsock.dll",
            "dnsapi.dll",
            "iphlpapi.dll",
            "netapi32.dll",
            "mpr.dll",
            "winspool.drv",
            "combase.dll",
            "windows.storage.dll",
            "shcore.dll",
            "profapi.dll",
            "kernel.appcore.dll",
        ];

        // API sets (api-ms-win-*.dll)
        if name_lower.starts_with("api-ms-win-") || name_lower.starts_with("api-ms-win-core-") {
            return true;
        }
        if name_lower.starts_with("api-ms-win-crt-") {
            return true;
        }
        if name_lower.starts_with("api-ms-win-service-") {
            return true;
        }
        if name_lower.starts_with("api-ms-win-security-") {
            return true;
        }
        if name_lower.starts_with("api-ms-win-eventing-") || name_lower.starts_with("api-ms-win-") {
            return true;
        }
        if name_lower.starts_with("ext-ms-win-") {
            return true;
        }

        system_dlls.contains(&name_lower.as_str())
    }

    /// Converts a Linux path to Windows-style backslash path.
    pub fn to_windows_style(linux_path: &str) -> String {
        linux_path.replace('/', "\\")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main_executable_path() {
        let mapper = VirtualPathMapper::new('F', false);
        let path = mapper.map_path("/home/user/samples/malware.exe", "malware.exe", true, false);
        assert_eq!(path, "F:\\malware.exe");
    }

    #[test]
    fn test_system_dll_path_x86() {
        let mapper = VirtualPathMapper::new('F', false);
        let path = mapper.map_path("/opt/dlls/ntdll.dll", "ntdll.dll", false, true);
        assert_eq!(path, "C:\\Windows\\System32\\ntdll.dll");
    }

    #[test]
    fn test_system_dll_path_wow64() {
        let mapper = VirtualPathMapper::new('F', true);
        let path = mapper.map_path("/opt/dlls/ntdll.dll", "ntdll.dll", false, true);
        assert_eq!(path, "C:\\Windows\\SysWOW64\\ntdll.dll");
    }

    #[test]
    fn test_is_system_dll() {
        assert!(VirtualPathMapper::is_system_dll("ntdll.dll"));
        assert!(VirtualPathMapper::is_system_dll("NTDLL.DLL"));
        assert!(VirtualPathMapper::is_system_dll("kernel32.dll"));
        assert!(VirtualPathMapper::is_system_dll(
            "api-ms-win-core-memory-l1-1-0.dll"
        ));
        assert!(!VirtualPathMapper::is_system_dll("myapp.dll"));
    }

    #[test]
    fn test_profile_driven_system_directory_stays_system32_for_native_x86() {
        let mapper = VirtualPathMapper::from_environment(
            "F:\\A0044620.exe",
            "C:\\Windows",
            "C:\\Windows\\System32",
        );
        let path = mapper.map_path("/opt/dlls/shlwapi.dll", "shlwapi.dll", false, true);
        assert_eq!(path, "C:\\Windows\\System32\\shlwapi.dll");
    }

    #[test]
    fn test_profile_driven_paths_use_image_parent_directory() {
        let mapper = VirtualPathMapper::from_environment(
            "F:\\Drop\\A0044620.exe",
            "C:\\Windows",
            "C:\\Windows\\System32",
        );
        let path = mapper.map_path("/opt/dlls/helper.dll", "helper.dll", false, false);
        assert_eq!(path, "F:\\Drop\\helper.dll");
    }

    #[test]
    fn test_profile_driven_system_directory_prefers_module_directory_hint() {
        let mapper = VirtualPathMapper::from_environment_with_module_directory(
            "F:\\A0044620.exe",
            "C:\\Windows",
            "C:\\Windows\\System32",
            Some(Path::new("system_dll/SysWOW64")),
        );
        let path = mapper.map_path("/opt/dlls/shlwapi.dll", "shlwapi.dll", false, true);
        assert_eq!(path, "C:\\Windows\\SysWOW64\\shlwapi.dll");
    }
}
