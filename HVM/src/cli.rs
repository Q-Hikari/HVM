use clap::{Parser, Subcommand};

/// Parses the top-level Rust CLI that will replace the Python entrypoint.
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
}
