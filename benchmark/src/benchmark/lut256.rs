use std::time::{Duration, Instant};

use maestro::{aes::{self, ss::GF8InvBlackBoxSS, GF8InvBlackBox}, lut256::{lut256_ss::Lut256SSParty, LUT256Party}, network::ConnectedParty, party::CombinedCommStats};

use crate::utils::{BenchmarkProtocol, BenchmarkResult};

impl_benchmark_protocol!(
    LUT256Benchmark,  // benchmark struct name
    "lut256", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| LUT256Party::setup(conn, n_worker_threads).unwrap(), // setup
    |party: &mut LUT256Party| party, // get ABB<GF8>
    |party: &mut LUT256Party, simd: usize| party.do_preprocessing(0, simd), // do preprocessing
    None // no finalize
);

pub struct Lut256SSBenchmark;

impl BenchmarkProtocol for Lut256SSBenchmark {
    fn protocol_name(&self) -> String {
        "lut256_ss".to_string()
    }
    fn run(&self, conn: ConnectedParty, simd: usize, n_worker_threads: Option<usize>) -> BenchmarkResult {
            let mut party = Lut256SSParty::setup(conn, n_worker_threads).unwrap();
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
            let ks = aes::random_keyschedule(party.main_party_mut());
    
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