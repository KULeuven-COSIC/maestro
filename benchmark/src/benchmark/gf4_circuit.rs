pub struct GF4CircuitBenchmark;

impl BenchmarkProtocol for GF4CircuitBenchmark {
    fn protocol_name(&self) -> String {
        "gf4-circuit".to_string()
    }
    fn run(
        &self,
        conn: ConnectedParty,
        simd: usize,
        n_worker_threads: Option<usize>,
    ) -> BenchmarkResult {
        let mut party = GF4CircuitSemihonestParty::setup(conn, n_worker_threads).unwrap();
        let _setup_comm_stats = party.io().reset_comm_stats();
        println!("After setup");

        let input = aes::random_state(party.0.as_party_mut(), simd);
        // create random key states for benchmarking purposes
        let ks = aes::random_keyschedule(party.0.as_party_mut());

        let start = Instant::now();
        let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
        let duration = start.elapsed();
        println!("After online");
        let online_comm_stats = party.io().reset_comm_stats();
        let _ = aes::output(&mut party.0, output).unwrap();
        println!("After output");
        party.0.teardown().unwrap();
        println!("After teardown");

        BenchmarkResult::new(
            Duration::from_secs(0),
            duration,
            CombinedCommStats::empty(),
            online_comm_stats,
            party.0.get_additional_timers(),
        )
    }
}