#![doc = include_str!("../README.md")]
#![allow(dead_code)]
pub mod aes;
mod gcm;
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
mod conversion;

use crate::benchmark::{chida::ChidaBenchmark, furukawa::{MalChidaBenchmark, MalChidaRecursiveCheckBenchmark}, gf4_circuit::GF4CircuitBenchmark, gf4_circuit_malsec::GF4CircuitASBenchmark, lut256::{LUT256Benchmark, Lut256SSBenchmark, Lut256SSMalBenchmark, Lut256SSMalOhvCheckBenchmark}, wollut16::LUT16Benchmark, wollut16_malsec::{MalLUT16BitStringBenchmark, MalLUT16OhvBenchmark}};
use crate::benchmark::gf4_circuit_malsec::GF4CircuitASGF4p4Benchmark;
use aes::AesVariant;
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

    #[arg(long, help = "The number of parallel AES calls to benchmark. You can pass multiple values.", num_args = 1..)]
    simd: Vec<usize>,

    #[arg(long, help = "The number repetitions of the protocol execution")]
    rep: usize,

    #[arg(long, help = "Path to write benchmark result data as CSV. Default: result.csv", default_value = "result.csv")]
    csv: PathBuf,
    
    #[arg(long, help="If set, benchmark all protocol variants and ignore specified targets.", default_value_t = false)]
    all: bool,

    #[arg(long, help="If set, the benchmark will compute AES-256, otherwise AES-128 is computed", default_value_t = false)]
    aes256: bool,

    #[arg(value_enum)]
    target: Vec<ProtocolVariant>,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq, Hash)]
pub enum ProtocolVariant {
    /// Implementation of the semi-honest oblivious AES protocol by Chida et al., "High-Throughput Secure AES Computation" in WAHC'18 (<https://doi.org/10.1145/3267973.3267977>).
    /// 
    /// - Security: Semi-honest
    /// - Preprocessing: none
    /// - SubBytes step: GF(2^8) inversion from Algortihm 5 of Chida et al.'s paper
    /// - Multiplication check: n/a
    Chida,
    /// Implementation of the actively secure variant of [ProtocolVariant::Chida].
    /// This uses bucket cut-and-choose to check the correctness of multiplications by Furukawa et al.,
    /// "High-Throughput Secure Three-Party Computation for Malicious Adversaries and an Honest Majority"
    /// (<https://eprint.iacr.org/2016/944>).
    /// 
    /// - Security: active
    /// - Preprocessing: bucket cut-and-choose
    /// - SubBytes step: GF(2^8) inversion from Algorithm 3 of Chida et al.'s paper[^note]
    /// - Multiplication check: sacrificing a correct beaver triple from the preprocessing phase
    /// 
    /// [^note]: Chida et al., "High-Throughput Secure AES Computation" in WAHC'18 (<https://doi.org/10.1145/3267973.3267977>)
    MalChida,
    /// Implementation of the actively secure variant of [ProtocolVariant::Chida] with the inner product check (Verify)
    /// described in the MAESTRO paper.
    /// 
    /// - Security: active
    /// - Preprocessing: none
    /// - SubBytes step: GF(2^8) inversion from Algorithm 3 of Chida et al.'s paper[^note]
    /// - Multiplication check: Protocol 2 (Verify)
    MalChidaRecCheck,
    /// Implementation of the semi-honest variant of Protocol 3 using the lookup table protocol for length-16 one-hot vectors.
    /// 
    /// - Security: semi-honest
    /// - Preprocessing: Generate length-16 random one-hot vectors (Protocol 9)
    /// - SubBytes step: GF(2^8) via tower GF(2^4)^2 (Protocol 3) and Protocol 4
    /// - Multiplication check: n/a
    Lut16,
    /// Implementation of the semi-honest variant of Protocol 3 where GF(2^4) inversion is computed via the powers z^-1 = z^2 * z^4 * z^8.
    /// 
    /// - Security: semi-honest
    /// - Preprocessing: none
    /// - SubBytes step: GF(2^8) via tower GF(2^4)^2 (Protocol 3)
    /// - Multiplication check: n/a
    GF4Circuit,
    /// Implementation of the semi-honest variant described in Sect. 3.5.2
    /// 
    /// - Security: semi-honest
    /// - Preprocessing: generate length-256 random one-hot vectors (Protocol 5)
    /// - SubBytes step: GF(2^8) inversion via length-256 table lookup (Protocol 4)
    /// - Multiplication check: n/a
    Lut256,
    /// Implementation of the semi-honest variant described in Sect. 3.5.3
    /// 
    /// - Security: semi-honest
    /// - Preprocessing: generate 2x16 random one-hot vectors (Protocol 9 variant)
    /// - SubBytes step: GF(2^8) inversion via length-256 table lookup (Protocol 6)
    /// - Multiplication check: n/a
    Lut256Ss,
    /// Implementation of the actively secure variant described in Sect. 3.5.3
    /// 
    /// - Security: active
    /// - Preprocessing: generate 2x16 random one-hot vectors (Protocol 9 variant)
    /// - SubBytes step: GF(2^8) inversion via length-256 table lookup (Protocol 6)
    /// - Multiplication check: Protocol 7 (VerifySbox)
    MalLut256Ss,
    /// Implementation of the actively secure variant described in Sect. 3.5.3
    /// 
    /// - Security: active
    /// - Preprocessing: generate 2x16 random one-hot vectors (Protocol 9 variant) with reduced number of multiplication checks
    /// - SubBytes step: GF(2^8) inversion via length-256 table lookup (Protocol 6)
    /// - Multiplication check: Protocol 2 (Verify) + Protocol 7 (VerifySbox)
    MalLut256SsOpt,
    /// Implementation of the actively secure variant of Protocol 3 using the lookup table protocol for length-16 one-hot vectors.
    /// 
    /// - Security: active
    /// - Preprocessing: Generate length-16 random one-hot vectors (Protocol 9)
    /// - SubBytes step: GF(2^8) via tower GF(2^4)^2 (Protocol 3) and Protocol 4
    /// - Multiplication check: Protocol 2 (Verify)
    MalLut16Bitstring,
    /// Implementation of the actively secure variant of Protocol 3 using the lookup table protocol for length-16 one-hot vectors.
    /// 
    /// - Security: active
    /// - Preprocessing: Generate length-16 random one-hot vectors (Protocol 9) with reduced number of multiplication checks
    /// - SubBytes step: GF(2^8) via tower GF(2^4)^2 (Protocol 3) and Protocol 4 with reduced number of multiplication checks
    /// - Multiplication check: Protocol 2 (Verify)
    MalLut16Ohv,
    /// Implementation of the actively secure variant of Protocol 3 where GF(2^4) inversion is computed via the powers z^-1 = z^2 * z^4 * z^8.
    /// 
    /// - Security: active
    /// - Preprocessing: none
    /// - SubBytes step: GF(2^8) via tower GF(2^4)^2 (Protocol 3)
    /// - Multiplication check: Protocol 2 (Verify)
    MalGF4Circuit,
    /// Implementation of the actively secure variant of Protocol 3 where GF(2^4) inversion is computed via the powers z^-1 = z^2 * z^4 * z^8.
    /// 
    /// - Security: active
    /// - Preprocessing: none
    /// - SubBytes step: GF(2^8) via tower GF(2^4)^2 (Protocol 3) with reduced number of multiplication checks
    /// - Multiplication check: Protocol 2 (Verify)
    MalGF4CircuitOpt,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    let (party_index, config) = network::Config::from_file(&cli.config).unwrap();

    if cli.simd.is_empty() {
        return Err("simd parameter required".to_string());
    }
    if !cli.simd.iter().all_unique() {
        return Err(format!("Duplicate simd values in argument {:?}", cli.simd));
    }

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

    let variant = if cli.aes256 {
        AesVariant::Aes256
    }else{
        AesVariant::Aes128
    };
    
    benchmark::utils::benchmark_protocols(party_index, &config, variant, cli.rep, cli.simd, cli.threads, boxed, cli.csv).unwrap();
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
            ProtocolVariant::MalLut16Bitstring => &MalLUT16BitStringBenchmark,
            ProtocolVariant::MalLut16Ohv => &MalLUT16OhvBenchmark,
            ProtocolVariant::MalGF4Circuit => &GF4CircuitASBenchmark,
            ProtocolVariant::MalGF4CircuitOpt => &GF4CircuitASGF4p4Benchmark
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
        variant: AesVariant,
        simd: usize,
        n_worker_threads: Option<usize>,
        prot_str: Option<String>,
    ) -> BenchmarkResult {
        self.get_protocol().run(conn, variant, simd, n_worker_threads, prot_str)
    }
}
