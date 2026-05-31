use super::*;

#[derive(Debug, Clone)]
struct ProcessRuntimeProfile {
    identity: SyntheticProcessIdentity,
    current_directory: String,
}

mod memory_ops;
mod process_ops;
