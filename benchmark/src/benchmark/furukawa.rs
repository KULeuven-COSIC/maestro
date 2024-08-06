use std::time::{Duration, Instant};

use maestro::{aes::{self, aes128_no_keyschedule}, furukawa::FurukawaParty, network::ConnectedParty, party::CombinedCommStats};

use crate::utils::{BenchmarkProtocol, BenchmarkResult};

pub struct MalChidaBenchmark;
pub struct MalChidaRecursiveCheckBenchmark;

fn run(conn: ConnectedParty, simd: usize, n_worker_threads: Option<usize>, use_recursive_check: bool) -> BenchmarkResult {
    let mut party = FurukawaParty::setup(conn, n_worker_threads, use_recursive_check).unwrap();
    let _setup_comm_stats = party.io().reset_comm_stats();
    let inputs = aes::random_state(&mut party.inner, simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(&mut party.inner);

    println!("After setup");

    let start = Instant::now();
    party.do_preprocessing(0, simd).unwrap();
    let prep_duration = start.elapsed();
    let prep_comm_stats = party.io().reset_comm_stats();

    println!("After pre-processing");

    let start = Instant::now();
    let output = aes128_no_keyschedule(&mut party, inputs, &ks).unwrap();
    party.finalize().unwrap();
    let online_duration = start.elapsed();
    println!("After online");
    let online_comm_stats = party.io().reset_comm_stats();
    // let post_sacrifice_duration = start.elapsed();
    let _ = aes::output(&mut party, output).unwrap();
    println!("After output");
    party.inner.teardown().unwrap();
    println!("After teardown");

    // if we use the recursive check, there is no preprocessing
    let prep_duration = if use_recursive_check { Duration::from_secs(0) } else { prep_duration };
    let prep_comm_stats = if use_recursive_check { CombinedCommStats::empty() } else { prep_comm_stats };

    BenchmarkResult::new(
        prep_duration,
        online_duration,
        prep_comm_stats,
        online_comm_stats,
        party.inner.get_additional_timers(),
    )
}

impl BenchmarkProtocol for MalChidaBenchmark {
    fn protocol_name(&self) -> String {
        "mal-chida".to_string()
    }
    fn run(
        &self,
        conn: ConnectedParty,
        simd: usize,
        n_worker_threads: Option<usize>,
    ) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, false)
    }
}

impl BenchmarkProtocol for MalChidaRecursiveCheckBenchmark {
    fn protocol_name(&self) -> String {
        "mal-chida-rec-check".to_string()
    }
    fn run(
        &self,
        conn: ConnectedParty,
        simd: usize,
        n_worker_threads: Option<usize>,
    ) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, true)
    }
}