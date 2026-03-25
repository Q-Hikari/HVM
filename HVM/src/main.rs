use clap::Parser;
use hvm::cli::Cli;
use hvm::cli::Commands;
use hvm::config::load_config;
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
            let report = inspect_pe(std::path::Path::new(&path))?;
            print!("{}", render_inspect(&report));
            Ok(())
        }
        Commands::Samples { dir } => {
            let samples = discover_samples(std::path::Path::new(&dir))?;
            print!("{}", render_sample_catalog(&samples));
            Ok(())
        }
        Commands::Run { config } => {
            let config = load_config(std::path::Path::new(&config))?;
            let mut engine = VirtualExecutionEngine::new(config)?;
            let result = engine.run()?;
            println!();
            print!("{}", render_run_summary(&result));
            Ok(())
        }
    }
}
