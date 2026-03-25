use std::fs;
use std::path::{absolute, Path, PathBuf};

use goblin::pe::PE;

use crate::arch::arch_name;
use crate::error::VmError;

const IMAGE_FILE_DLL: u16 = 0x2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleKind {
    Executable,
    DynamicLibrary,
}

impl SampleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executable => "exe",
            Self::DynamicLibrary => "dll",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleDescriptor {
    pub name: String,
    pub path: PathBuf,
    pub arch: String,
    pub kind: SampleKind,
    pub exports: Vec<String>,
    pub run_supported: bool,
}

impl SampleDescriptor {
    pub fn first_export(&self) -> Option<&str> {
        self.exports.first().map(String::as_str)
    }
}

pub fn default_sample_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../Sample")
}

pub fn discover_default_samples() -> Result<Vec<SampleDescriptor>, VmError> {
    discover_samples(default_sample_dir())
}

pub fn discover_samples(sample_dir: impl AsRef<Path>) -> Result<Vec<SampleDescriptor>, VmError> {
    let sample_dir = sample_dir.as_ref();
    let resolved_dir = absolute(sample_dir).map_err(|source| VmError::ReadFile {
        path: sample_dir.to_path_buf(),
        source,
    })?;
    let mut samples = Vec::new();

    for entry in fs::read_dir(&resolved_dir).map_err(|source| VmError::ReadFile {
        path: resolved_dir.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| VmError::ReadFile {
            path: resolved_dir.clone(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| VmError::ReadFile {
            path: path.clone(),
            source,
        })?;
        if !file_type.is_file() {
            continue;
        }

        let bytes = fs::read(&path).map_err(|source| VmError::ReadFile {
            path: path.clone(),
            source,
        })?;
        let pe = PE::parse(&bytes).map_err(|source| VmError::ParsePe {
            path: path.clone(),
            source,
        })?;
        let machine = pe.header.coff_header.machine;
        let arch = arch_name(machine)
            .ok_or(VmError::UnsupportedMachine(machine))?
            .to_string();
        let kind = if pe.header.coff_header.characteristics & IMAGE_FILE_DLL != 0 {
            SampleKind::DynamicLibrary
        } else {
            SampleKind::Executable
        };
        let mut exports = pe
            .exports
            .iter()
            .filter_map(|export| export.name.map(str::to_string))
            .collect::<Vec<_>>();
        exports.sort();
        exports.dedup();

        samples.push(SampleDescriptor {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            path,
            arch: arch.clone(),
            kind,
            exports,
            run_supported: matches!(arch.as_str(), "x86" | "x64"),
        });
    }

    samples.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(samples)
}

pub fn first_runnable_sample() -> Result<Option<SampleDescriptor>, VmError> {
    let samples = discover_default_samples()?;
    Ok(samples
        .iter()
        .find(|sample| sample.run_supported && sample.arch.eq_ignore_ascii_case("x86"))
        .cloned()
        .or_else(|| samples.into_iter().find(|sample| sample.run_supported)))
}

pub fn first_exported_sample() -> Result<Option<SampleDescriptor>, VmError> {
    Ok(discover_default_samples()?
        .into_iter()
        .find(|sample| !sample.exports.is_empty()))
}

pub fn first_runnable_exported_sample() -> Result<Option<SampleDescriptor>, VmError> {
    let samples = discover_default_samples()?;
    Ok(samples
        .iter()
        .find(|sample| {
            sample.run_supported
                && !sample.exports.is_empty()
                && sample.arch.eq_ignore_ascii_case("x86")
        })
        .cloned()
        .or_else(|| {
            samples
                .into_iter()
                .find(|sample| sample.run_supported && !sample.exports.is_empty())
        }))
}

pub fn render_sample_catalog(samples: &[SampleDescriptor]) -> String {
    let mut output = String::new();
    for sample in samples {
        output.push_str(&format!(
            "{} | arch={} | kind={} | run={}\n",
            sample.name,
            sample.arch,
            sample.kind.as_str(),
            if sample.run_supported {
                "yes"
            } else {
                "inspect-only"
            }
        ));
        if sample.exports.is_empty() {
            output.push_str("  exports: <none>\n");
        } else {
            output.push_str(&format!("  exports: {}\n", sample.exports.join(", ")));
        }
    }
    output
}
