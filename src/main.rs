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
mod benchmark;

use std::{path::PathBuf, time::Duration};

use benchmark::BenchmarkProtocol;
use chida::ChidaBenchmark;
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use crate::{furukawa::MalChidaBenchmark, gf4_circuit::GF4CircuitBenchmark, lut256::LUT256Benchmark, wollut16::LUT16Benchmark};
use itertools::Itertools;
use network::ConnectedParty;

use crate::chida::ImplVariant;

#[derive(Parser)]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    #[command(subcommand)]
    command: Commands
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq, Hash)]
pub enum ProtocolVariant {
    Chida, MalChida, Lut16, GF4Circuit, Lut256
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
    },
    /// Benchmarks one or more protocols with runtime and communication data written to CSV file
    Benchmark {
        #[arg(long, help="The number of parallel AES calls to benchmark.")]
        simd: usize,
        #[arg(long, help="The number repetitions of the protocol execution")]
        rep: usize,
        #[arg(long, help="Path to write benchmark result data as CSV. Default: result.csv", default_value="result.csv")]
        csv: PathBuf,
        #[arg(value_enum)]
        target: Vec<ProtocolVariant>
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
        },
        Commands::Benchmark { simd, rep, csv, target } => {
            // check non-empty and distinct targets
            if target.is_empty() {
                let all_targets: Vec<_> = ProtocolVariant::value_variants().iter().map(|prot| prot.to_possible_value().unwrap().get_name().to_string()).collect();
                println!("List of targets is empty: choose any number of targets: {:?}", all_targets);
                return;
            }
            if !target.iter().all_unique() {
                println!("Duplicate targets in argument {:?}", target);
                return;
            }
            let mut boxed: Vec<Box<dyn BenchmarkProtocol>> = Vec::new();
            for v in target {
                boxed.push(Box::new(v));
            }
            benchmark::benchmark_protocols(party_index, &config, rep, simd, boxed, csv).unwrap();
        }
    }
}

impl ProtocolVariant {
    fn get_protocol(&self) -> &dyn BenchmarkProtocol {
        match self {
            ProtocolVariant::Chida => &ChidaBenchmark,
            ProtocolVariant::MalChida => &MalChidaBenchmark,
            ProtocolVariant::GF4Circuit => &GF4CircuitBenchmark,
            ProtocolVariant::Lut16 => &LUT16Benchmark,
            ProtocolVariant::Lut256 => &LUT256Benchmark,
        }
    }
}

impl BenchmarkProtocol for ProtocolVariant {
    fn protocol_name(&self) -> String {
        self.get_protocol().protocol_name()
    }
    fn run(&self, conn: ConnectedParty, simd: usize) -> benchmark::BenchmarkResult {
        self.get_protocol().run(conn, simd)
    }
}