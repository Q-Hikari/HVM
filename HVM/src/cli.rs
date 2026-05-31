use clap::{Parser, Subcommand};

/// Parses the top-level HVM CLI.
#[derive(Debug, Parser)]
#[command(name = "hvm-hikari-virtual-engine")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Enumerates the supported PE inspection and execution commands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    Inspect {
        path: String,
    },
    Samples {
        #[arg(long, default_value = "Sample")]
        dir: String,
    },
    Run {
        #[arg(long)]
        config: String,
    },
    /// Run a single sample through the virtual sandbox and produce structured JSON output.
    Analyze {
        /// Path to the sample PE file to analyze.
        #[arg(long)]
        sample: String,

        /// Environment profile name or path (e.g. "win10_21h2_x64", "win7_sp1_x64").
        #[arg(long, default_value = "win10_21h2_x64")]
        profile: String,

        /// Maximum number of instructions to execute.
        #[arg(long, default_value_t = 50_000_000)]
        max_instructions: u64,

        /// Execution timeout in seconds (0 = no timeout, rely on max_instructions).
        #[arg(long, default_value_t = 120)]
        timeout: u64,

        /// Path to write the structured JSON result.
        #[arg(long)]
        output: String,

        /// Optional working directory (defaults to current directory).
        #[arg(long)]
        workdir: Option<String>,
    },
    /// Batch-analyze all PE files in a directory.
    Batch {
        /// Directory containing samples to analyze.
        #[arg(long)]
        dir: String,

        /// Environment profile name or path.
        #[arg(long, default_value = "win10_21h2_x64")]
        profile: String,

        /// Maximum number of instructions per sample.
        #[arg(long, default_value_t = 50_000_000)]
        max_instructions: u64,

        /// Execution timeout per sample in seconds (0 = no timeout).
        #[arg(long, default_value_t = 120)]
        timeout: u64,

        /// Output directory for result JSON files.
        #[arg(long)]
        output_dir: String,

        /// Optional working directory.
        #[arg(long)]
        workdir: Option<String>,
    },
}
