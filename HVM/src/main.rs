use std::io::Read;
use std::path::Path;

use chrono::Utc;
use clap::Parser;
use hvm::cli::Cli;
use hvm::cli::Commands;
use hvm::config::EngineConfig;
use hvm::error::VmError;
use hvm::pe::inspect::{inspect_pe, render_inspect};
use hvm::runtime::engine::{render_run_summary, VirtualExecutionEngine};
use hvm::samples::{discover_samples, render_sample_catalog};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), VmError> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Inspect { path } => {
            let report = inspect_pe(Path::new(&path))?;
            print!("{}", render_inspect(&report));
            Ok(())
        }
        Commands::Samples { dir } => {
            let samples = discover_samples(Path::new(&dir))?;
            print!("{}", render_sample_catalog(&samples));
            Ok(())
        }
        Commands::Run { config } => {
            let config = load_config(std::path::Path::new(&config))?;
            let wall_start = std::time::Instant::now();
            let mut engine = VirtualExecutionEngine::new(config)?;
            match engine.run() {
                Ok(result) => {
                    let wall = wall_start.elapsed();
                    let ips = if wall.as_secs_f64() > 0.0 {
                        result.instructions as f64 / wall.as_secs_f64()
                    } else {
                        0.0
                    };
                    println!();
                    print!("{}", render_run_summary(&result));
                    println!(
                        "wall_time={:.2}s instructions_per_second={:.0} peak_rss={}",
                        wall.as_secs_f64(),
                        ips,
                        get_peak_rss_kb(),
                    );
                    Ok(())
                }
                Err(error) => {
                    let wall = wall_start.elapsed();
                    let instructions = engine.instruction_count();
                    let _ = engine.log_error_summary(&error.to_string());
                    let _ = engine.flush_api_logs_for_test();
                    let ips = if wall.as_secs_f64() > 0.0 {
                        instructions as f64 / wall.as_secs_f64()
                    } else {
                        0.0
                    };
                    eprintln!("{error}");
                    println!();
                    println!(
                        "entrypoint=0x{:X}\ninstructions={}\nstopped=false\nexit_code=None\nstop_reason=error\nwall_time={:.2}s instructions_per_second={:.0} peak_rss={}",
                        engine.entrypoint(),
                        instructions,
                        wall.as_secs_f64(),
                        ips,
                        get_peak_rss_kb(),
                    );
                    std::process::exit(1);
                }
            }
        }
        Commands::Analyze {
            sample,
            profile,
            max_instructions,
            timeout,
            output,
            workdir,
        } => run_analyze(
            &sample,
            &profile,
            max_instructions,
            timeout,
            &output,
            workdir.as_deref(),
        ),
        Commands::Batch {
            dir,
            profile,
            max_instructions,
            timeout,
            output_dir,
            workdir,
        } => run_batch(
            &dir,
            &profile,
            max_instructions,
            timeout,
            &output_dir,
            workdir.as_deref(),
        ),
    }
}

fn run_analyze(
    sample: &str,
    profile: &str,
    max_instructions: u64,
    timeout_secs: u64,
    output: &str,
    workdir: Option<&str>,
) -> Result<(), VmError> {
    use std::fs;

    let sample_path = Path::new(sample);
    if !sample_path.exists() {
        eprintln!("error: sample file not found: {sample}");
        std::process::exit(1);
    }

    let workdir = workdir.map(std::path::PathBuf::from).unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    });

    let output_path = Path::new(output);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|source| VmError::OutputIo {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    // Streaming hash — don't load the whole file into memory.
    let sample_size = fs::metadata(sample_path)
        .map_err(|source| VmError::ReadFile {
            path: sample_path.to_path_buf(),
            source,
        })?
        .len();
    let sample_hash = sha256_file(sample_path)?;

    let output_dir = output_path.parent().unwrap_or(Path::new(".")).to_path_buf();

    let config = EngineConfig::for_sandbox(
        sample_path,
        profile,
        max_instructions,
        &output_dir,
        &workdir,
    )
    .map_err(VmError::Config)?;

    let mut engine = VirtualExecutionEngine::new(config)?;
    let _ = timeout_secs; // Wall-clock timeout delegated to Go caller via process kill.
    let timestamp = now_iso();
    let result = engine.run_with_result(&sample_hash, sample_size, &timestamp);

    match result {
        Ok((_run_result, mut sandbox_result)) => {
            if let Ok(pe_report) = inspect_pe(sample_path) {
                sandbox_result.pe_info = Some(hvm::sandbox_result::PeInfo {
                    arch: pe_report.arch.clone(),
                    image_base: pe_report.image_base,
                    entrypoint_rva: pe_report.entrypoint_rva,
                    size_of_image: pe_report.size_of_image,
                    imports: pe_report
                        .imports
                        .into_iter()
                        .map(|desc| hvm::sandbox_result::ImportEntry {
                            dll: desc.dll,
                            symbols: desc.symbols,
                        })
                        .collect(),
                    has_tls: pe_report.has_tls,
                    has_relocations: pe_report.has_reloc,
                });
            }
            write_sandbox_result(&sandbox_result, output_path)
        }
        Err(e) => {
            // On error, still write a result JSON with the error info.
            let mut sandbox_result = hvm::sandbox_result::SandboxResult {
                sample_hash,
                sample_size,
                arch: String::new(),
                timestamp: now_iso(),
                execution_time_ms: 0,
                hvm_version: env!("CARGO_PKG_VERSION").to_string(),
                status: hvm::sandbox_result::status::ERROR.to_string(),
                exit_code: None,
                stop_reason: "error".to_string(),
                instruction_count: 0,
                error_message: Some(e.to_string()),
                api_calls: Vec::new(),
                network_events: Vec::new(),
                file_operations: Vec::new(),
                registry_operations: Vec::new(),
                process_operations: Vec::new(),
                dropped_files: Vec::new(),
                console_output: String::new(),
                pe_info: None,
            };
            if let Ok(pe_report) = inspect_pe(sample_path) {
                sandbox_result.arch = pe_report.arch.clone();
            }
            write_sandbox_result(&sandbox_result, output_path)
        }
    }
}

fn run_batch(
    dir: &str,
    profile: &str,
    max_instructions: u64,
    timeout_secs: u64,
    output_dir: &str,
    workdir: Option<&str>,
) -> Result<(), VmError> {
    use std::fs;

    let dir_path = Path::new(dir);
    if !dir_path.is_dir() {
        eprintln!("error: not a directory: {dir}");
        std::process::exit(1);
    }

    let output_dir_path = Path::new(output_dir);
    fs::create_dir_all(output_dir_path).map_err(|source| VmError::OutputIo {
        path: output_dir_path.to_path_buf(),
        source,
    })?;

    let workdir = workdir.map(std::path::PathBuf::from).unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    });

    let mut count = 0usize;
    let mut errors = 0usize;

    for entry in fs::read_dir(dir_path).map_err(|source| VmError::OutputIo {
        path: dir_path.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| VmError::OutputIo {
            path: dir_path.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Only process files with known PE extensions.
        let ext = path.extension().and_then(|e| e.to_str());
        match ext {
            Some("exe") | Some("dll") | Some("sys") | Some("ocx") => {}
            _ => continue,
        }

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let result_path = output_dir_path.join(format!("{file_name}.result.json"));
        eprintln!("[batch] analyzing: {file_name}");

        match run_analyze(
            &path.to_string_lossy(),
            profile,
            max_instructions,
            timeout_secs,
            &result_path.to_string_lossy(),
            Some(&workdir.to_string_lossy()),
        ) {
            Ok(()) => count += 1,
            Err(e) => {
                eprintln!("[batch] error analyzing {file_name}: {e}");
                errors += 1;
            }
        }
    }

    eprintln!("[batch] done: {count} analyzed, {errors} errors");
    Ok(())
}

fn write_sandbox_result(
    result: &hvm::sandbox_result::SandboxResult,
    path: &Path,
) -> Result<(), VmError> {
    use std::fs;
    let json = serde_json::to_string_pretty(result).map_err(|e| VmError::OutputIo {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::Other, e),
    })?;
    fs::write(path, json).map_err(|source| VmError::OutputIo {
        path: path.to_path_buf(),
        source,
    })?;
    eprintln!(
        "[analyze] status={} instructions={} output={}",
        result.status,
        result.instruction_count,
        path.display()
    );
    Ok(())
}

/// Streaming SHA-256 from a file — avoids loading the whole file into memory.
fn sha256_file(path: &Path) -> Result<String, VmError> {
    use sha2::{Digest, Sha256};
    use std::fs::File;
    let mut file = File::open(path).map_err(|source| VmError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|source| VmError::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in &hash {
        use std::fmt::Write;
        write!(hex, "{b:02x}").unwrap();
    }
    Ok(hex)
}

/// Returns the current time as an ISO 8601 / RFC 3339 string.
fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn load_config(path: &std::path::Path) -> Result<EngineConfig, VmError> {
    hvm::config::load_config(path).map_err(VmError::Config)
}

/// Returns peak RSS in KB from /proc/self/status (Linux only).
fn get_peak_rss_kb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                })
            })
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}
