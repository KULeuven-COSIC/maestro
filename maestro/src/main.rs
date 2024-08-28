#![doc = include_str!("../../README.md")]

#![allow(dead_code)]
pub mod aes;
pub mod chida;
pub mod furukawa;
pub mod gf4_circuit;
pub mod lut256;
pub mod share;
pub mod wollut16;
pub mod wollut16_malsec;
pub mod gf4_circuit_malsec;
pub mod util;
pub mod rep3_core;
#[macro_use]
pub mod benchmark;


use crate::benchmark::{chida::ChidaBenchmark, furukawa::{MalChidaBenchmark, MalChidaRecursiveCheckBenchmark}, gf4_circuit::GF4CircuitBenchmark, gf4_circuit_malsec::GF4CircuitASBenchmark, lut256::{LUT256Benchmark, Lut256SSBenchmark, Lut256SSMalBenchmark, Lut256SSMalOhvCheckBenchmark}, wollut16::LUT16Benchmark, wollut16_malsec::{MalLUT16BitStringBenchmark, MalLUT16OhvBenchmark}};
use crate::benchmark::gf4_circuit_malsec::GF4CircuitASGF4p4Benchmark;
use itertools::Itertools;
use crate::rep3_core::network::{self, ConnectedParty};
use std::path::PathBuf;

use crate::benchmark::utils::{BenchmarkProtocol, BenchmarkResult};
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
    
    #[arg(long, help="If set, benchmark all protocol variants and ignore specified targets.", default_value_t = false)]
    all: bool,

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
    MalLut256SsOpt,
    // MalLut16,
    // MalLut16PrepCheck,
    // MalLut16AllCheck,
    MalLut16Bitstring,
    MalLut16Ohv,
    MalGF4Circuit,
    MalGF4CircuitOpt,
    // MalGF4CircuitAllCheck,
    // MalGF4CircuitBucketBeaverCheck,
    // MalGF4CircuitRecBeaverCheck,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    let (party_index, config) = network::Config::from_file(&cli.config).unwrap();

    let mut boxed: Vec<Box<dyn BenchmarkProtocol>> = Vec::new();
    if !cli.all {
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
        
        for v in cli.target {
            boxed.push(Box::new(v));
        }
    }else{
        // add all protocols to boxed
        for v in ProtocolVariant::value_variants() {
            boxed.push(Box::new(v.clone()));
        }
    }
    
    benchmark::utils::benchmark_protocols(party_index, &config, cli.rep, cli.simd, cli.threads, boxed, cli.csv).unwrap();
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
            ProtocolVariant::MalLut256SsOpt => &Lut256SSMalOhvCheckBenchmark,
            // ProtocolVariant::MalLut16 => &MalLUT16Benchmark,
            ProtocolVariant::MalLut16Bitstring => &MalLUT16BitStringBenchmark,
            ProtocolVariant::MalLut16Ohv => &MalLUT16OhvBenchmark,
            ProtocolVariant::MalGF4Circuit => &GF4CircuitASBenchmark,
            ProtocolVariant::MalGF4CircuitOpt => &GF4CircuitASGF4p4Benchmark
            // ProtocolVariant::MalLut16PrepCheck => &MalLUT16PrepCheckBenchmark,
            // ProtocolVariant::MalLut16AllCheck => &MalLUT16AllCheckBenchmark,
            // ProtocolVariant::MalGF4CircuitAllCheck => &GF4CircuitAllCheckASBenchmark,
            // ProtocolVariant::MalGF4CircuitBucketBeaverCheck => &GF4CircuitASBucketBeaverBenchmark,
            // ProtocolVariant::MalGF4CircuitRecBeaverCheck => &GF4CircuitASRecBeaverBenchmark,
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
