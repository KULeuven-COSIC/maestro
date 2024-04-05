#![allow(dead_code)]
mod share;
mod party;
mod network;
mod dec;
mod chida;
mod furukawa;
mod aes;
mod wollut16;
mod gf4_circuit;
mod lut256;

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
    },
    /// Benchmarks the Oblivious AES protocol from Chida et al., "High-Throughput Secure AES Computation" in WAHC'18 in the **malicious** setting using the
    /// protocol from Furukawa et al with bucket-cut-and-choose and post-sacrifice to check correctness of multiplications.
    MalChidaBenchmark {
        #[arg(long, help="The number of parallel AES calls to benchmark.")]
        simd: usize,
    },
    /// Benchmarks the LUT-16 variant with semi-honest security
    LUT16Benchmark {
        #[arg(long, help="The number of parallel AES calls to benchmark.")]
        simd: usize,
    },
    /// Benchmarks the GF(2^4) circuit variant with semi-honest security
    GF4CircuitBenchmark {
        #[arg(long, help="The number of parallel AES calls to benchmark.")]
        simd: usize,
    },
    /// Benchmarks the LUT-256 variant with semi-honest security
    LUT256Benchmark {
        #[arg(long, help="The number of parallel AES calls to benchmark.")]
        simd: usize,
    }
}

fn main() {
    let cli = Cli::parse();

    let (party_index, config) = network::Config::from_file(&cli.config).unwrap();

    match cli.command {
        Commands::ChidaBenchmark { simd, use_simple } => {
            let variant = if use_simple { ImplVariant::Simple } else { ImplVariant::Optimized };
            println!("Using {:?}", variant);
            let connected = ConnectedParty::bind_and_connect(party_index, config, Some(Duration::from_secs(60))).unwrap();
            println!("Connected!");
            chida::chida_benchmark(connected, simd, variant);
        },
        Commands::MalChidaBenchmark { simd } => {
            let connected = ConnectedParty::bind_and_connect(party_index, config, Some(Duration::from_secs(60))).unwrap();
            println!("Connected!");
            furukawa::furukawa_benchmark(connected, simd);
        },
        Commands::LUT16Benchmark { simd } => {
            let connected = ConnectedParty::bind_and_connect(party_index, config, Some(Duration::from_secs(60))).unwrap();
            println!("Connected!");
            wollut16::wollut16_benchmark(connected, simd);
        },
        Commands::GF4CircuitBenchmark { simd } => {
            let connected = ConnectedParty::bind_and_connect(party_index, config, Some(Duration::from_secs(60))).unwrap();
            println!("Connected!");
            gf4_circuit::gf4_circuit_benchmark(connected, simd);
        },
        Commands::LUT256Benchmark { simd } => {
            let connected = ConnectedParty::bind_and_connect(party_index, config, Some(Duration::from_secs(60))).unwrap();
            println!("Connected!");
            lut256::lut256_benchmark(connected, simd);
        }
    }
}
