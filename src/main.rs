mod share;
mod party;
mod network;
mod gcm;
mod chida;

use std::{path::PathBuf, time::Duration};

use clap::{Parser, Subcommand, ArgAction};
use network::ConnectedParty;

use crate::chida::ImplVariant;

#[derive(Parser)]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    /// Benchmarks the Oblivious AES protocol from Chida et al., "High-Throughput Secure AES Computation" in WAHC'18.
    ChidaBenchmark {
        #[arg(long, help="The number of parallel AES calls to benchmark.")]
        simd: usize,
        #[arg(long="simple", action=ArgAction::SetTrue, help="If set, benchmarks the baseline implementation (cf. ImplVariant::Simple). If not set (default), benchmarks the optimized implementation in Chida et al.")]
        use_simple: bool
    }
}

fn main() {
    let cli = Cli::parse();

    let (party_index, config) = network::Config::from_file(&cli.config).unwrap();

    match cli.command {
        Commands::ChidaBenchmark { simd, use_simple } => {
            let variant = if use_simple { ImplVariant::Simple } else { ImplVariant::Optimized };
            println!("Using {:?}", variant);
            let connected = ConnectedParty::bind_and_connect(party_index, config, Some(Duration::from_secs_f32(1.0))).unwrap();
            println!("Connected!");
            chida::chida_benchmark(connected, simd, variant);
        }
    }
}
