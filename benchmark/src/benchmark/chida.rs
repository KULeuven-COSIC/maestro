use std::time::Instant;

use maestro::{aes, chida::{ChidaBenchmarkParty, ImplVariant}, network::ConnectedParty, party::CombinedCommStats};

use crate::utils::{BenchmarkProtocol, BenchmarkResult};

pub struct ChidaBenchmark;

impl BenchmarkProtocol for ChidaBenchmark {
    fn protocol_name(&self) -> String {
        "chida".to_string()
    }
    fn run(
        &self,
        conn: ConnectedParty,
        simd: usize,
        n_worker_threads: Option<usize>,
    ) -> BenchmarkResult {
        let mut party =
            ChidaBenchmarkParty::setup(conn, ImplVariant::Optimized, n_worker_threads).unwrap();
        let _setup_comm_stats = party.inner.0.io().reset_comm_stats();
        let input = aes::random_state(party.inner.as_party_mut(), simd);
        // create random key states for benchmarking purposes
        let ks = aes::random_keyschedule(party.inner.as_party_mut());
        println!("After setup");

        let start = Instant::now();
        let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
        let duration = start.elapsed();
        println!("After online");
        let online_comm_stats = party.inner.0.io().reset_comm_stats();
        let _ = aes::output(&mut party.inner, output).unwrap();
        println!("After output");
        party.inner.0.teardown().unwrap();
        println!("After teardown");

        BenchmarkResult::new(
            Duration::from_secs(0),
            duration,
            CombinedCommStats::empty(),
            online_comm_stats,
            party.inner.0.get_additional_timers(),
        )
    }
}
