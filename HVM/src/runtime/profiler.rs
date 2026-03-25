use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::config::EngineConfig;
use crate::error::VmError;
use crate::models::RunStopReason;

#[derive(Debug, Default)]
pub struct RuntimeProfiler {
    output_path: Option<PathBuf>,
    sections: BTreeMap<&'static str, RuntimeProfileCounter>,
}

#[derive(Debug, Clone, Copy, Default)]
struct RuntimeProfileCounter {
    calls: u64,
    total_ns: u64,
    max_ns: u64,
}

#[derive(Debug)]
pub struct RuntimeProfileGuard {
    profiler: *mut RuntimeProfiler,
    section: &'static str,
    started_at: Option<Instant>,
}

impl Drop for RuntimeProfileGuard {
    fn drop(&mut self) {
        if self.profiler.is_null() {
            return;
        }
        let Some(started_at) = self.started_at else {
            return;
        };
        let elapsed = started_at.elapsed();
        unsafe {
            (*self.profiler).record_duration(self.section, elapsed);
        }
    }
}

impl RuntimeProfiler {
    pub fn from_env(config: &EngineConfig) -> Self {
        let output_path = first_env_var_os(&[
            "HVM_HIKARI_VIRTUAL_ENGINE_PROFILE_PATH",
            "VM_ENGINE_PROFILE_PATH",
        ])
        .map(PathBuf::from)
        .or_else(|| {
            first_env_var_os(&["HVM_HIKARI_VIRTUAL_ENGINE_PROFILE", "VM_ENGINE_PROFILE"]).map(
                |_| {
                    let sample_name = config
                        .main_module
                        .file_name()
                        .and_then(|name| name.to_str())
                        .filter(|name| !name.is_empty())
                        .unwrap_or("sample");
                    config
                        .sandbox_output_dir
                        .join("profiles")
                        .join(format!("{sample_name}.runtime_profile.json"))
                },
            )
        });
        Self {
            output_path,
            sections: BTreeMap::new(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.output_path.is_some()
    }

    pub fn start_scope(&mut self, section: &'static str) -> RuntimeProfileGuard {
        if !self.enabled() {
            return RuntimeProfileGuard {
                profiler: std::ptr::null_mut(),
                section,
                started_at: None,
            };
        }
        RuntimeProfileGuard {
            profiler: self as *mut Self,
            section,
            started_at: Some(Instant::now()),
        }
    }

    pub fn emit_report(
        &self,
        wall_duration: Duration,
        instructions: u64,
        stop_reason: RunStopReason,
    ) -> Result<(), VmError> {
        let Some(path) = self.output_path.as_ref() else {
            return Ok(());
        };

        let wall_ns = duration_to_ns(wall_duration);
        let instructions_per_second = if wall_duration.is_zero() {
            0.0
        } else {
            instructions as f64 / wall_duration.as_secs_f64()
        };
        let mut sections = self
            .sections
            .iter()
            .map(|(name, counter)| {
                json!({
                    "name": name,
                    "calls": counter.calls,
                    "total_ns": counter.total_ns,
                    "total_ms": ns_to_ms(counter.total_ns),
                    "avg_ns": if counter.calls == 0 { 0 } else { counter.total_ns / counter.calls },
                    "avg_ms": if counter.calls == 0 { 0.0 } else { ns_to_ms(counter.total_ns / counter.calls) },
                    "max_ns": counter.max_ns,
                    "max_ms": ns_to_ms(counter.max_ns),
                    "share_of_wall": if wall_ns == 0 { 0.0 } else { counter.total_ns as f64 / wall_ns as f64 },
                })
            })
            .collect::<Vec<_>>();
        sections.sort_by(|left, right| {
            let left_ns = left["total_ns"].as_u64().unwrap_or(0);
            let right_ns = right["total_ns"].as_u64().unwrap_or(0);
            right_ns.cmp(&left_ns)
        });

        let report = json!({
            "timing_model": "inclusive_sections",
            "wall_ns": wall_ns,
            "wall_ms": ns_to_ms(wall_ns),
            "instructions": instructions,
            "instructions_per_second": instructions_per_second,
            "stop_reason": stop_reason.as_str(),
            "sections": sections,
        });

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| VmError::OutputIo {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let rendered =
            serde_json::to_string_pretty(&report).map_err(|source| VmError::OutputIo {
                path: path.clone(),
                source: std::io::Error::other(source),
            })?;
        fs::write(path, rendered).map_err(|source| VmError::OutputIo {
            path: path.clone(),
            source,
        })?;
        Ok(())
    }

    fn record_duration(&mut self, section: &'static str, duration: Duration) {
        if !self.enabled() {
            return;
        }
        let elapsed_ns = duration_to_ns(duration);
        let counter = self.sections.entry(section).or_default();
        counter.calls = counter.calls.saturating_add(1);
        counter.total_ns = counter.total_ns.saturating_add(elapsed_ns);
        counter.max_ns = counter.max_ns.max(elapsed_ns);
    }
}

fn first_env_var_os(names: &[&str]) -> Option<std::ffi::OsString> {
    names.iter().find_map(env::var_os)
}

fn duration_to_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

fn ns_to_ms(ns: u64) -> f64 {
    ns as f64 / 1_000_000.0
}
