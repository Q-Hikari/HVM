use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::config::EngineConfig;
use crate::error::VmError;
use crate::hooks::base::HookDefinition;

const DEFAULT_FLUSH_THRESHOLD: usize = 1024;
const OUTPUT_BUFFER_CAPACITY: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiLogArg {
    pub index: usize,
    pub name: String,
    pub kind: String,
    pub value: u64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRef {
    pub va: u64,
    pub owner: String,
    pub module: Option<String>,
    pub module_base: Option<u64>,
    pub rva: Option<u64>,
    pub module_path: Option<String>,
    pub region: Option<String>,
    pub region_base: Option<u64>,
    pub region_offset: Option<u64>,
}

impl AddressRef {
    pub fn unknown(va: u64) -> Self {
        Self {
            va,
            owner: if va == 0 {
                "NULL".to_string()
            } else {
                "unknown".to_string()
            },
            module: None,
            module_base: None,
            rva: None,
            module_path: None,
            region: None,
            region_base: None,
            region_offset: None,
        }
    }

    pub(crate) fn to_json_value(&self) -> Value {
        let mut record = Map::new();
        record.insert("va".to_string(), json!(self.va));
        record.insert("owner".to_string(), json!(self.owner));
        if let Some(module) = &self.module {
            record.insert("module".to_string(), json!(module));
        }
        if let Some(module_base) = self.module_base {
            record.insert("module_base".to_string(), json!(module_base));
        }
        if let Some(rva) = self.rva {
            record.insert("rva".to_string(), json!(rva));
        }
        if let Some(module_path) = &self.module_path {
            record.insert("module_path".to_string(), json!(module_path));
        }
        if let Some(region) = &self.region {
            record.insert("region".to_string(), json!(region));
        }
        if let Some(region_base) = self.region_base {
            record.insert("region_base".to_string(), json!(region_base));
        }
        if let Some(region_offset) = self.region_offset {
            record.insert("region_offset".to_string(), json!(region_offset));
        }
        Value::Object(record)
    }
}

#[derive(Debug)]
struct OutputStream {
    path: PathBuf,
    writer: BufWriter<File>,
}

#[derive(Debug)]
pub struct ApiLogger {
    trace_enabled: bool,
    native_events_enabled: bool,
    console_enabled: bool,
    include_return: bool,
    console_output_to_console: bool,
    call_sequence: u64,
    record_sequence: u64,
    flush_threshold: usize,
    pending_lines: Vec<String>,
    pending_human_lines: Vec<String>,
    pending_records: Vec<String>,
    pending_console_text: Vec<String>,
    stream: Option<OutputStream>,
    human_stream: Option<OutputStream>,
    json_stream: Option<OutputStream>,
    console_stream: Option<OutputStream>,
}

impl ApiLogger {
    pub fn new(config: &EngineConfig) -> Result<Self, VmError> {
        let human_log_path = config
            .api_human_log_path
            .clone()
            .or_else(|| default_human_log_path(config.api_log_path.as_deref()));
        let jsonl_path = config
            .api_jsonl_path
            .clone()
            .or_else(|| default_jsonl_path(config.api_log_path.as_deref()));
        let has_trace_sink = config.api_log_to_console
            || config.api_log_path.is_some()
            || human_log_path.is_some()
            || jsonl_path.is_some();
        Ok(Self {
            trace_enabled: config.trace_api_calls && has_trace_sink,
            native_events_enabled: config.trace_native_events && has_trace_sink,
            console_enabled: config.api_log_to_console,
            include_return: config.api_log_include_return,
            console_output_to_console: config.console_output_to_console,
            call_sequence: 0,
            record_sequence: 0,
            flush_threshold: DEFAULT_FLUSH_THRESHOLD,
            pending_lines: Vec::with_capacity(DEFAULT_FLUSH_THRESHOLD),
            pending_human_lines: Vec::with_capacity(DEFAULT_FLUSH_THRESHOLD),
            pending_records: Vec::with_capacity(DEFAULT_FLUSH_THRESHOLD),
            pending_console_text: Vec::with_capacity(DEFAULT_FLUSH_THRESHOLD),
            stream: open_stream(config.api_log_path.as_ref())?,
            human_stream: open_stream(human_log_path.as_ref())?,
            json_stream: open_stream(jsonl_path.as_ref())?,
            console_stream: open_stream(config.console_output_path.as_ref())?,
        })
    }

    pub fn enabled(&self) -> bool {
        self.console_enabled
            || self.stream.is_some()
            || self.human_stream.is_some()
            || self.json_stream.is_some()
    }

    pub fn trace_enabled(&self) -> bool {
        self.trace_enabled
    }

    pub fn writes_marker(&self, marker: &str) -> bool {
        let full_trace_sink =
            self.console_enabled || self.stream.is_some() || self.json_stream.is_some();
        let human_trace_sink = self.human_stream.is_some() && should_write_human_log(marker);
        if is_api_marker(marker) {
            self.trace_enabled && (full_trace_sink || human_trace_sink)
        } else if is_native_marker(marker) {
            self.native_events_enabled && full_trace_sink
        } else {
            full_trace_sink || human_trace_sink
        }
    }

    pub fn native_trace_sampling_enabled(&self) -> bool {
        [
            "NATIVE_BLOCK",
            "NATIVE_LOOP",
            "NATIVE_PROGRESS",
            "NATIVE_SUMMARY",
            "NATIVE_FAULT",
            "NATIVE_TRACE_WINDOW",
        ]
        .into_iter()
        .any(|marker| self.writes_marker(marker))
    }

    pub fn log_api_call(
        &mut self,
        pid: u32,
        tid: u32,
        tick_ms: u64,
        instruction_count: u64,
        definition: &HookDefinition,
        pc: u64,
        return_to: Option<u64>,
        target_base: u64,
        args: &[ApiLogArg],
        pc_ref: Option<AddressRef>,
        return_ref: Option<AddressRef>,
    ) -> Result<u64, VmError> {
        if !self.trace_enabled {
            return Ok(0);
        }
        self.call_sequence = self.call_sequence.saturating_add(1);
        let call_id = self.call_sequence;
        let return_to = return_to.unwrap_or(0);
        let args_text = format_args(args);
        let mut record = self.base_record("API_CALL", pid, tid, tick_ms, instruction_count);
        record.insert("call_id".to_string(), json!(call_id));
        record.insert("pc".to_string(), json!(pc));
        record.insert("pc_va".to_string(), json!(pc));
        record.insert("return_to".to_string(), json!(return_to));
        record.insert("return_to_va".to_string(), json!(return_to));
        record.insert(
            "target".to_string(),
            json!(format!("{}!{}", definition.module, definition.function)),
        );
        record.insert("target_module".to_string(), json!(definition.module));
        record.insert("target_function".to_string(), json!(definition.function));
        record.insert("target_base".to_string(), json!(target_base));
        record.insert("args_text".to_string(), json!(args_text));
        record.insert(
            "args".to_string(),
            Value::Array(
                args.iter()
                    .map(|arg| {
                        json!({
                            "index": arg.index,
                            "name": arg.name,
                            "kind": arg.kind,
                            "value": arg.value,
                            "text": arg.text,
                        })
                    })
                    .collect(),
            ),
        );
        if let Some(pc_ref) = pc_ref {
            if let Some(module) = &pc_ref.module {
                record.insert("pc_module".to_string(), json!(module));
            }
            if let Some(rva) = pc_ref.rva {
                record.insert("pc_rva".to_string(), json!(rva));
            }
            record.insert("pc_ref".to_string(), pc_ref.to_json_value());
        }
        if let Some(return_ref) = return_ref {
            if let Some(module) = &return_ref.module {
                record.insert("return_to_module".to_string(), json!(module));
            }
            if let Some(module_base) = return_ref.module_base {
                record.insert("return_to_module_base".to_string(), json!(module_base));
            }
            if let Some(rva) = return_ref.rva {
                record.insert("return_to_rva".to_string(), json!(rva));
            }
            record.insert("return_to_ref".to_string(), return_ref.to_json_value());
            record.insert("return_owner".to_string(), json!(return_ref.owner));
        }
        let line = format!(
            "[API_CALL] id={call_id} tid=0x{tid:X} pc=0x{pc:X} return_to=0x{return_to:X} target={}!{} target_base=0x{target_base:X} args={{{args_text}}}",
            definition.module, definition.function,
        );
        self.emit("API_CALL", line, Some(record))?;
        Ok(call_id)
    }

    pub fn log_api_return(
        &mut self,
        pid: u32,
        tid: u32,
        tick_ms: u64,
        instruction_count: u64,
        call_id: u64,
        definition: &HookDefinition,
        pc: u64,
        target_base: u64,
        retval: u64,
        last_error: u32,
        decoded_text: Option<String>,
        pc_ref: Option<AddressRef>,
    ) -> Result<(), VmError> {
        if !self.trace_enabled || !self.include_return || call_id == 0 {
            return Ok(());
        }
        let retval_text = format!("0x{retval:X}");
        let mut record = self.base_record("API_RET", pid, tid, tick_ms, instruction_count);
        record.insert("call_id".to_string(), json!(call_id));
        record.insert("pc".to_string(), json!(pc));
        record.insert("pc_va".to_string(), json!(pc));
        record.insert(
            "target".to_string(),
            json!(format!("{}!{}", definition.module, definition.function)),
        );
        record.insert("target_module".to_string(), json!(definition.module));
        record.insert("target_function".to_string(), json!(definition.function));
        record.insert("target_base".to_string(), json!(target_base));
        record.insert("retval".to_string(), json!(retval));
        record.insert("retval_text".to_string(), json!(retval_text));
        record.insert("last_error".to_string(), json!(last_error));
        if let Some(decoded_text) = &decoded_text {
            record.insert("decoded_text".to_string(), json!(decoded_text));
        }
        if let Some(pc_ref) = pc_ref {
            if let Some(module) = &pc_ref.module {
                record.insert("pc_module".to_string(), json!(module));
            }
            if let Some(rva) = pc_ref.rva {
                record.insert("pc_rva".to_string(), json!(rva));
            }
            record.insert("pc_ref".to_string(), pc_ref.to_json_value());
        }
        let mut line = format!(
            "[API_RET] id={call_id} tid=0x{tid:X} pc=0x{pc:X} target={}!{} target_base=0x{target_base:X} retval={retval_text} last_error=0x{last_error:X}",
            definition.module, definition.function,
        );
        if let Some(decoded_text) = decoded_text {
            line.push_str(" decoded={");
            line.push_str(&decoded_text);
            line.push('}');
        }
        self.emit("API_RET", line, Some(record))
    }

    pub fn log_console_output(
        &mut self,
        pid: u32,
        tid: u32,
        tick_ms: u64,
        instruction_count: u64,
        source: &str,
        text: &str,
        handle: u64,
    ) -> Result<(), VmError> {
        let clean = text.replace("\r\n", "\n");
        let mut record = self.base_record("CONSOLE_OUT", pid, tid, tick_ms, instruction_count);
        record.insert("source".to_string(), json!(source));
        record.insert("handle".to_string(), json!(handle));
        record.insert("text".to_string(), json!(clean));
        self.emit(
            "CONSOLE_OUT",
            format!(
                "[CONSOLE_OUT] source={} handle=0x{:X} text={}",
                source,
                handle & 0xFFFF_FFFF,
                format_line_value(&Value::String(clean.clone())),
            ),
            Some(record),
        )?;
        if self.console_output_to_console && !clean.is_empty() {
            print!("{clean}");
        }
        if let Some(stream) = self.console_stream.as_mut() {
            let mut persisted = clean;
            if !persisted.ends_with('\n') {
                persisted.push('\n');
            }
            self.pending_console_text.push(persisted);
            if self.pending_console_text.len() >= self.flush_threshold {
                flush_console_stream(stream, &mut self.pending_console_text)?;
            }
        }
        Ok(())
    }

    pub fn log_event(
        &mut self,
        marker: &str,
        pid: u32,
        tid: u32,
        tick_ms: u64,
        instruction_count: u64,
        fields: Map<String, Value>,
    ) -> Result<(), VmError> {
        let mut record = self.base_record(marker, pid, tid, tick_ms, instruction_count);
        let mut parts = vec![format!("[{marker}]")];
        for (key, value) in fields {
            parts.push(format!("{key}={}", format_line_value(&value)));
            record.insert(key, value);
        }
        self.emit(marker, parts.join(" "), Some(record))
    }

    pub fn flush(&mut self) -> Result<(), VmError> {
        if let Some(stream) = self.stream.as_mut() {
            flush_line_stream(stream, &mut self.pending_lines)?;
        }
        if let Some(stream) = self.human_stream.as_mut() {
            flush_line_stream(stream, &mut self.pending_human_lines)?;
        }
        if let Some(stream) = self.json_stream.as_mut() {
            flush_line_stream(stream, &mut self.pending_records)?;
        }
        if let Some(stream) = self.console_stream.as_mut() {
            flush_console_stream(stream, &mut self.pending_console_text)?;
        }
        Ok(())
    }

    fn emit(
        &mut self,
        marker: &str,
        line: String,
        record: Option<Map<String, Value>>,
    ) -> Result<(), VmError> {
        if self.console_enabled {
            println!("{line}");
        }
        if self.stream.is_some() {
            self.pending_lines.push(line.clone());
            if self.pending_lines.len() >= self.flush_threshold {
                if let Some(stream) = self.stream.as_mut() {
                    flush_line_stream(stream, &mut self.pending_lines)?;
                }
            }
        }
        if self.human_stream.is_some() && should_write_human_log(marker) {
            self.pending_human_lines.push(line);
            if self.pending_human_lines.len() >= self.flush_threshold {
                if let Some(stream) = self.human_stream.as_mut() {
                    flush_line_stream(stream, &mut self.pending_human_lines)?;
                }
            }
        }
        if let Some(record) = record {
            if self.json_stream.is_some() {
                self.pending_records.push(
                    serde_json::to_string(&Value::Object(record))
                        .unwrap_or_else(|_| "{}".to_string()),
                );
                if self.pending_records.len() >= self.flush_threshold {
                    if let Some(stream) = self.json_stream.as_mut() {
                        flush_line_stream(stream, &mut self.pending_records)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn base_record(
        &mut self,
        marker: &str,
        pid: u32,
        tid: u32,
        tick_ms: u64,
        instruction_count: u64,
    ) -> Map<String, Value> {
        self.record_sequence = self.record_sequence.saturating_add(1);
        let mut record = Map::new();
        record.insert("seq".to_string(), json!(self.record_sequence));
        record.insert("event".to_string(), json!(marker.to_ascii_lowercase()));
        record.insert("marker".to_string(), json!(marker));
        record.insert("tick_ms".to_string(), json!(tick_ms));
        record.insert("instruction_count".to_string(), json!(instruction_count));
        record.insert("pid".to_string(), json!(pid));
        record.insert("tid".to_string(), json!(tid));
        record
    }
}

impl Drop for ApiLogger {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn open_stream(path: Option<&PathBuf>) -> Result<Option<OutputStream>, VmError> {
    let Some(path) = path else {
        return Ok(None);
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| VmError::OutputIo {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let file = File::create(path).map_err(|source| VmError::OutputIo {
        path: path.clone(),
        source,
    })?;
    Ok(Some(OutputStream {
        path: path.clone(),
        writer: BufWriter::with_capacity(OUTPUT_BUFFER_CAPACITY, file),
    }))
}

fn flush_line_stream(stream: &mut OutputStream, pending: &mut Vec<String>) -> Result<(), VmError> {
    if pending.is_empty() {
        return Ok(());
    }
    stream
        .writer
        .write_all(pending[0].as_bytes())
        .and_then(|_| {
            for line in pending.iter().skip(1) {
                stream.writer.write_all(b"\n")?;
                stream.writer.write_all(line.as_bytes())?;
            }
            stream.writer.write_all(b"\n")
        })
        .and_then(|_| stream.writer.flush())
        .map_err(|source| VmError::OutputIo {
            path: stream.path.clone(),
            source,
        })?;
    pending.clear();
    Ok(())
}

fn flush_console_stream(
    stream: &mut OutputStream,
    pending: &mut Vec<String>,
) -> Result<(), VmError> {
    if pending.is_empty() {
        return Ok(());
    }
    stream
        .writer
        .write_all(pending[0].as_bytes())
        .and_then(|_| {
            for chunk in pending.iter().skip(1) {
                stream.writer.write_all(chunk.as_bytes())?;
            }
            Ok(())
        })
        .and_then(|_| stream.writer.flush())
        .map_err(|source| VmError::OutputIo {
            path: stream.path.clone(),
            source,
        })?;
    pending.clear();
    Ok(())
}

fn default_jsonl_path(path: Option<&Path>) -> Option<PathBuf> {
    let path = path?;
    Some(match path.extension() {
        Some(_) => path.with_extension("jsonl"),
        None => PathBuf::from(format!("{}.jsonl", path.display())),
    })
}

fn default_human_log_path(path: Option<&Path>) -> Option<PathBuf> {
    let path = path?;
    Some(match path.extension() {
        Some(_) => path.with_extension("human.log"),
        None => PathBuf::from(format!("{}.human.log", path.display())),
    })
}

fn should_write_human_log(marker: &str) -> bool {
    matches!(
        marker,
        "API_CALL"
            | "API_RET"
            | "API_HOTSPOT"
            | "ARTIFACT_HIDE"
            | "ENTRY_INVOKE"
            | "FILE_CHDIR"
            | "FILE_COPY"
            | "FILE_DELETE"
            | "IMAGE_MODIFIED_DUMP"
            | "FILE_MKDIR"
            | "FILE_RENAME"
            | "FILE_RMDIR"
            | "FILE_TRUNCATE"
            | "FILE_ACCESS_DENIED"
            | "FILE_OPEN"
            | "FILE_WRITE"
            | "HTTP_CONNECT"
            | "HTTP_REQUEST"
            | "MEM_ALLOC"
            | "MEM_EXEC_CHAIN"
            | "MEM_EXEC_EXIT_DUMP"
            | "MEM_PROTECT"
            | "MEM_PROTECT_DUMP"
            | "MEM_WRITE"
            | "MEM_WRITE_DUMP"
            | "PROCESS_SPAWN"
            | "REG_CREATE_KEY"
            | "REG_DELETE_KEY"
            | "REG_DELETE_VALUE"
            | "REG_OPEN_KEY"
            | "REG_QUERY_VALUE"
            | "REG_SET_VALUE"
            | "REMOTE_THREAD_RECORD"
            | "REMOTE_THREAD_STAGE"
            | "REMOTE_THREAD_STAGE_FAIL"
            | "SERVICE_CONTROL"
            | "SERVICE_OPEN"
            | "SERVICE_OPEN_MANAGER"
            | "SERVICE_START"
            | "SOCKET_CONNECT"
            | "SOCKET_CREATE"
            | "SOCKET_RECV"
            | "SOCKET_SEND"
            | "THREAD_CREATE"
            | "THREAD_START_DUMP"
            | "THREAD_RESUME_DUMP"
            | "EMU_STOP"
            | "RUN_STOP"
            | "PROCESS_EXIT"
            | "INSTRUCTION_BUDGET"
            | "USER32_HOTSPOT"
            | "UNSUPPORTED_IMPORT"
            | "UNSUPPORTED_HOOK"
            | "UNSUPPORTED_RUNTIME"
    )
}

fn is_api_marker(marker: &str) -> bool {
    matches!(marker, "API_CALL" | "API_RET")
}

fn is_native_marker(marker: &str) -> bool {
    marker.starts_with("NATIVE_")
}

fn format_args(args: &[ApiLogArg]) -> String {
    args.iter()
        .map(|arg| format!("{}={}", arg.name, arg.text))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_line_value(value: &Value) -> String {
    match value {
        Value::String(text) => {
            serde_json::to_string(text).unwrap_or_else(|_| format!("\"{text}\""))
        }
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::Null => "null".to_string(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{json, Map, Value};

    use super::{AddressRef, ApiLogArg, ApiLogger};
    use crate::config::EngineConfig;
    use crate::hooks::base::HookDefinition;

    #[test]
    fn api_logger_writes_trace_console_and_generic_events() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../.codex_tmp/tests")
            .join(format!("api_logger_{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut config = EngineConfig::for_tests(root.clone());
        config.trace_api_calls = true;
        config.api_log_path = Some(root.join("trace.api.log"));
        config.api_jsonl_path = Some(root.join("trace.api.jsonl"));
        config.console_output_path = Some(root.join("trace.console.log"));
        let mut logger = ApiLogger::new(&config).unwrap();

        let definition = HookDefinition::synthetic("kernel32.dll", "GetCommandLineW");
        let args = Vec::<ApiLogArg>::new();
        let call_id = logger
            .log_api_call(
                0x1337,
                0x1001,
                7,
                41,
                &definition,
                0x1000_0010,
                Some(0x401000),
                0x7600_0000,
                &args,
                Some(AddressRef {
                    va: 0x1000_0010,
                    owner: "kernel32.dll+0x10".to_string(),
                    module: Some("kernel32.dll".to_string()),
                    module_base: Some(0x1000_0000),
                    rva: Some(0x10),
                    module_path: None,
                    region: None,
                    region_base: None,
                    region_offset: None,
                }),
                Some(AddressRef {
                    va: 0x401000,
                    owner: "getmidm2.exe+0x1000".to_string(),
                    module: Some("getmidm2.exe".to_string()),
                    module_base: Some(0x400000),
                    rva: Some(0x1000),
                    module_path: None,
                    region: None,
                    region_base: None,
                    region_offset: None,
                }),
            )
            .unwrap();
        logger
            .log_api_return(
                0x1337,
                0x1001,
                8,
                42,
                call_id,
                &definition,
                0x1000_0010,
                0x7600_0000,
                0x2000_1000,
                0,
                None,
                Some(AddressRef::unknown(0x1000_0010)),
            )
            .unwrap();
        logger
            .log_console_output(0x1337, 0x1001, 9, 43, "stdout", "hello trace", 0xFFFF_FFF5)
            .unwrap();
        let mut fields = Map::new();
        fields.insert("phase".to_string(), json!("native"));
        fields.insert("error".to_string(), json!("boom"));
        logger
            .log_event("EMU_STOP", 0x1337, 0x1001, 10, 44, fields)
            .unwrap();
        logger.flush().unwrap();

        let api_log = fs::read_to_string(root.join("trace.api.log")).unwrap();
        assert!(api_log.contains("[API_CALL]"));
        assert!(api_log.contains("[API_RET]"));
        assert!(api_log.contains("[CONSOLE_OUT]"));
        assert!(api_log.contains("[EMU_STOP]"));

        let human_log = fs::read_to_string(root.join("trace.api.human.log")).unwrap();
        assert!(human_log.contains("[API_CALL]"));
        assert!(human_log.contains("[API_RET]"));
        assert!(human_log.contains("[EMU_STOP]"));
        assert!(!human_log.contains("[CONSOLE_OUT]"));

        let console_log = fs::read_to_string(root.join("trace.console.log")).unwrap();
        assert!(console_log.contains("hello trace"));

        let jsonl = fs::read_to_string(root.join("trace.api.jsonl")).unwrap();
        let markers = jsonl
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .map(|record| record["marker"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert!(markers.contains(&"API_CALL".to_string()));
        assert!(markers.contains(&"API_RET".to_string()));
        assert!(markers.contains(&"CONSOLE_OUT".to_string()));
        assert!(markers.contains(&"EMU_STOP".to_string()));
    }

    #[test]
    fn api_logger_disables_trace_when_no_trace_sink_is_configured() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../.codex_tmp/tests")
            .join(format!("api_logger_nosink_{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut config = EngineConfig::for_tests(root);
        config.trace_api_calls = true;
        config.api_log_to_console = false;
        config.api_log_path = None;
        config.api_jsonl_path = None;
        config.api_human_log_path = None;

        let logger = ApiLogger::new(&config).unwrap();
        assert!(!logger.trace_enabled());
        assert!(!logger.enabled());
    }

    #[test]
    fn api_logger_human_only_sink_filters_non_human_runtime_markers() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../.codex_tmp/tests")
            .join(format!("api_logger_human_only_{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut config = EngineConfig::for_tests(root.clone());
        config.trace_api_calls = true;
        config.api_log_path = None;
        config.api_jsonl_path = None;
        config.api_human_log_path = Some(root.join("trace.api.human.log"));

        let logger = ApiLogger::new(&config).unwrap();
        assert!(logger.trace_enabled());
        assert!(logger.writes_marker("API_CALL"));
        assert!(logger.writes_marker("RUN_STOP"));
        assert!(logger.writes_marker("ENTRY_INVOKE"));
        assert!(logger.writes_marker("THREAD_CREATE"));
        assert!(logger.writes_marker("FILE_OPEN"));
        assert!(logger.writes_marker("FILE_WRITE"));
        assert!(logger.writes_marker("FILE_DELETE"));
        assert!(logger.writes_marker("PROCESS_SPAWN"));
        assert!(logger.writes_marker("SOCKET_CONNECT"));
        assert!(logger.writes_marker("SOCKET_SEND"));
        assert!(logger.writes_marker("MEM_PROTECT"));
        assert!(logger.writes_marker("REG_SET_VALUE"));
        assert!(logger.writes_marker("SERVICE_START"));
        assert!(logger.writes_marker("HTTP_REQUEST"));
        assert!(!logger.writes_marker("NATIVE_BLOCK"));
        assert!(!logger.native_trace_sampling_enabled());
    }

    #[test]
    fn api_logger_can_disable_native_markers_while_preserving_api_markers() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../.codex_tmp/tests")
            .join(format!("api_logger_split_trace_{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut config = EngineConfig::for_tests(root.clone());
        config.trace_api_calls = true;
        config.trace_native_events = false;
        config.api_log_path = Some(root.join("trace.api.log"));
        config.api_jsonl_path = Some(root.join("trace.api.jsonl"));

        let logger = ApiLogger::new(&config).unwrap();
        assert!(logger.trace_enabled());
        assert!(logger.writes_marker("API_CALL"));
        assert!(logger.writes_marker("RUN_STOP"));
        assert!(!logger.writes_marker("NATIVE_BLOCK"));
        assert!(!logger.native_trace_sampling_enabled());
    }
}
