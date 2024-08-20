#![doc = include_str!("../../README.md")]

#[macro_use]
mod utils;
mod benchmark;

use benchmark::{chida::ChidaBenchmark, furukawa::{MalChidaBenchmark, MalChidaRecursiveCheckBenchmark}, gf4_circuit::GF4CircuitBenchmark, gf4_circuit_malsec::{GF4CircuitASBenchmark, GF4CircuitASBucketBeaverBenchmark, GF4CircuitASRecBeaverBenchmark, GF4CircuitAllCheckASBenchmark}, lut256::{LUT256Benchmark, Lut256SSBenchmark, Lut256SSMalBenchmark}, wollut16::LUT16Benchmark, wollut16_malsec::{MalLUT16AllCheckBenchmark, MalLUT16Benchmark, MalLUT16BitStringBenchmark, MalLUT16GF4P4Benchmark, MalLUT16PrepCheckBenchmark}};
use itertools::Itertools;
use rep3_core::network::{self, ConnectedParty};
use std::path::PathBuf;

use utils::{BenchmarkProtocol, BenchmarkResult};
use clap::{Parser, ValueEnum};

#[derive(Parser)]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,

    #[arg(
        long,
        value_name = "N_THREADS",
        help = "The number of worker threads. Set to 0 to indicate the number of cores on the machine. Optional, default single-threaded"
    )]
    threads: Option<usize>,

    #[arg(long, help = "The number of parallel AES calls to benchmark.")]
    simd: usize,

    #[arg(long, help = "The number repetitions of the protocol execution")]
    rep: usize,

    #[arg(long, help = "Path to write benchmark result data as CSV. Default: result.csv", default_value = "result.csv")]
    csv: PathBuf,
    
    #[arg(value_enum)]
    target: Vec<ProtocolVariant>,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq, Hash)]
pub enum ProtocolVariant {
    Chida,
    MalChida,
    MalChidaRecCheck,
    Lut16,
    GF4Circuit,
    Lut256,
    Lut256Ss,
    MalLut256Ss,
    MalLut16,
    MalLut16PrepCheck,
    MalLut16AllCheck,
    MalLut16Bitstring,
    MalLut16GF4p4,
    MalGF4Circuit,
    MalGF4CircuitAllCheck,
    MalGF4CircuitBucketBeaverCheck,
    MalGF4CircuitRecBeaverCheck,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    let (party_index, config) = network::Config::from_file(&cli.config).unwrap();

    // check non-empty and distinct targets
    if cli.target.is_empty() {
        let all_targets: Vec<_> = ProtocolVariant::value_variants()
            .iter()
            .map(|prot| prot.to_possible_value().unwrap().get_name().to_string())
            .collect();
        return Err(format!("List of targets is empty: choose any number of targets: {:?}", all_targets));
    }
    if !cli.target.iter().all_unique() {
        return Err(format!("Duplicate targets in argument {:?}", cli.target));
    }
    let mut boxed: Vec<Box<dyn BenchmarkProtocol>> = Vec::new();
    for v in cli.target {
        boxed.push(Box::new(v));
    }
    utils::benchmark_protocols(party_index, &config, cli.rep, cli.simd, cli.threads, boxed, cli.csv).unwrap();
    Ok(())
}

impl ProtocolVariant {
    fn get_protocol(&self) -> &dyn BenchmarkProtocol {
        match self {
            ProtocolVariant::Chida => &ChidaBenchmark,
            ProtocolVariant::MalChida => &MalChidaBenchmark,
            ProtocolVariant::MalChidaRecCheck => &MalChidaRecursiveCheckBenchmark,
            ProtocolVariant::GF4Circuit => &GF4CircuitBenchmark,
            ProtocolVariant::Lut16 => &LUT16Benchmark,
            ProtocolVariant::Lut256 => &LUT256Benchmark,
            ProtocolVariant::Lut256Ss => &Lut256SSBenchmark,
            ProtocolVariant::MalLut256Ss => &Lut256SSMalBenchmark,
            ProtocolVariant::MalLut16 => &MalLUT16Benchmark,
            ProtocolVariant::MalLut16Bitstring => &MalLUT16BitStringBenchmark,
            ProtocolVariant::MalLut16GF4p4 => &MalLUT16GF4P4Benchmark,
            ProtocolVariant::MalGF4Circuit => &GF4CircuitASBenchmark,
            ProtocolVariant::MalLut16PrepCheck => &MalLUT16PrepCheckBenchmark,
            ProtocolVariant::MalLut16AllCheck => &MalLUT16AllCheckBenchmark,
            ProtocolVariant::MalGF4CircuitAllCheck => &GF4CircuitAllCheckASBenchmark,
            ProtocolVariant::MalGF4CircuitBucketBeaverCheck => &GF4CircuitASBucketBeaverBenchmark,
            ProtocolVariant::MalGF4CircuitRecBeaverCheck => &GF4CircuitASRecBeaverBenchmark,
        }
    }
}

impl BenchmarkProtocol for ProtocolVariant {
    fn protocol_name(&self) -> String {
        self.get_protocol().protocol_name()
    }
    fn run(
        &self,
        conn: ConnectedParty,
        simd: usize,
        n_worker_threads: Option<usize>,
    ) -> BenchmarkResult {
        self.get_protocol().run(conn, simd, n_worker_threads)
    }
}
