use std::time::{Duration, Instant};
use crate::aes::AesVariant;
use crate::rep3_core::{network::ConnectedParty, party::CombinedCommStats};
use crate::{aes::{self, ss::{GF8InvBlackBoxSS, GF8InvBlackBoxSSMal}, GF8InvBlackBox}, lut256::{lut256_ss::{Lut256SSMalParty, Lut256SSParty}, LUT256Party}};

use crate::benchmark::utils::{BenchmarkProtocol, BenchmarkResult};

use super::impl_benchmark_protocol;

impl_benchmark_protocol!(
    LUT256Benchmark,  // benchmark struct name
    "lut256", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>| LUT256Party::setup(conn, n_worker_threads, prot_str).unwrap(), // setup
    |party: &mut LUT256Party| party, // get ABB<GF8>
    |party: &mut LUT256Party, simd: usize, variant: AesVariant| party.do_preprocessing(0, simd, variant), // do preprocessing
    None // no finalize
);

pub struct Lut256SSBenchmark;

impl BenchmarkProtocol for Lut256SSBenchmark {
    fn protocol_name(&self) -> String {
        "lut256_ss".to_string()
    }
    fn run(&self, conn: ConnectedParty, variant: AesVariant, simd: usize, n_worker_threads: Option<usize>, prot_str: Option<String>) -> BenchmarkResult {
        assert_eq!(AesVariant::Aes128, variant, "Only AES-128 is supported for {}", self.protocol_name());
        let mut party = Lut256SSParty::setup(conn, n_worker_threads, prot_str).unwrap();
        let _setup_comm_stats = party.main_party_mut().io().reset_comm_stats();
        println!("After setup");
            
        let start_prep = Instant::now();
        party.do_preprocessing(0, simd).unwrap();
        let prep_duration = start_prep.elapsed();
        let prep_comm_stats = party.main_party_mut().io().reset_comm_stats();
        println!("After pre-processing");

        // create random input for benchmarking purposes
        let input = aes::ss::random_state(party.main_party_mut(), simd);
        // create random key states for benchmarking purposes
        let ks = aes::random_keyschedule(party.main_party_mut(), variant);
    
        let start = Instant::now();
        let output = aes::ss::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
        let duration = start.elapsed();
        println!("After online");
        let online_comm_stats = party.main_party_mut().io().reset_comm_stats();
        let _ = aes::ss::output(&mut party, output).unwrap();
        println!("After output");
        party.main_party_mut().teardown().unwrap();
        println!("After teardown");
    
        BenchmarkResult::new(
            prep_duration,
            duration,
            Duration::from_secs(0),
            prep_comm_stats,
            online_comm_stats,
            CombinedCommStats::empty(),
            party.main_party_mut().get_additional_timers(),
        )
    }
}

fn lut256_ss_mal_run_benchmark(conn: ConnectedParty, simd: usize, use_ohv_check: bool, n_worker_threads: Option<usize>, prot_str: Option<String>) -> BenchmarkResult {
    let mut party = Lut256SSMalParty::setup(conn, use_ohv_check, n_worker_threads, prot_str).unwrap();
    let _setup_comm_stats = party.main_party_mut().io().reset_comm_stats();
    println!("After setup");
    
    let start_prep = Instant::now();
    party.do_preprocessing(0, simd).unwrap();
    let prep_duration = start_prep.elapsed();
    let prep_comm_stats = party.main_party_mut().io().reset_comm_stats();
    println!("After pre-processing");

    // create random input for benchmarking purposes
    let input = aes::random_state(party.main_party_mut(), simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(party.main_party_mut(), AesVariant::Aes128);

    let start = Instant::now();
    let output = aes::ss::aes128_no_keyschedule_mal(&mut party, input, &ks).unwrap();
    let duration = start.elapsed();
    println!("After online");
    let online_comm_stats = party.main_party_mut().io().reset_comm_stats();
    let finalize_start = Instant::now();
    party.finalize().unwrap();
    let finalize_time = finalize_start.elapsed();
    let finalize_comm_stats = party.main_party_mut().io().reset_comm_stats();
    println!("After finalize");
    let output = output.to_bytes();
    let (output_i, output_ii): (Vec<_>, Vec<_>) = output.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
    let _ = party.output(&output_i, &output_ii).unwrap();
    println!("After output");
    party.main_party_mut().teardown().unwrap();
    println!("After teardown");

    BenchmarkResult::new(
        prep_duration,
        duration,
        finalize_time,
        prep_comm_stats,
        online_comm_stats,
        finalize_comm_stats,
        party.main_party_mut().get_additional_timers(),
    )
}

pub struct Lut256SSMalBenchmark;
impl BenchmarkProtocol for Lut256SSMalBenchmark {
    fn protocol_name(&self) -> String {
        "mal-lut256-ss".to_string()
    }
    fn run(&self, conn: ConnectedParty, variant: AesVariant, simd: usize, n_worker_threads: Option<usize>, prot_str: Option<String>) -> BenchmarkResult {
        assert_eq!(AesVariant::Aes128, variant, "Only AES-128 is supported for {}", self.protocol_name());
        lut256_ss_mal_run_benchmark(conn, simd, false, n_worker_threads, prot_str)
    }
}

pub struct Lut256SSMalOhvCheckBenchmark;
impl BenchmarkProtocol for Lut256SSMalOhvCheckBenchmark {
    fn protocol_name(&self) -> String {
        "mal-lut256-ss-opt".to_string()
    }
    fn run(&self, conn: ConnectedParty, variant: AesVariant, simd: usize, n_worker_threads: Option<usize>, prot_str: Option<String>) -> BenchmarkResult {
        assert_eq!(AesVariant::Aes128, variant, "Only AES-128 is supported for {}", self.protocol_name());
        lut256_ss_mal_run_benchmark(conn, simd, true, n_worker_threads, prot_str)
    }
}