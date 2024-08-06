pub struct LUT16Benchmark;

impl BenchmarkProtocol for LUT16Benchmark {
    fn protocol_name(&self) -> String {
        "lut16".to_string()
    }
    fn run(
        &self,
        conn: ConnectedParty,
        simd: usize,
        n_worker_threads: Option<usize>,
    ) -> BenchmarkResult {
        let mut party = WL16Party::setup(conn, n_worker_threads).unwrap();
        let _setup_comm_stats = party.io().reset_comm_stats();
        println!("After setup");
        let start_prep = Instant::now();
        party.do_preprocessing(0, simd).unwrap();
        let prep_duration = start_prep.elapsed();
        let prep_comm_stats = party.io().reset_comm_stats();
        println!("After pre-processing");

        let input = aes::random_state(party.inner.as_party_mut(), simd);
        // create random key states for benchmarking purposes
        let ks = aes::random_keyschedule(party.inner.as_party_mut());

        let start = Instant::now();
        let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
        let duration = start.elapsed();
        let online_comm_stats = party.io().reset_comm_stats();
        println!("After online");
        let _ = aes::output(&mut party.inner, output).unwrap();
        println!("After output");
        party.inner.teardown().unwrap();
        println!("After teardown");

        BenchmarkResult::new(
            prep_duration,
            duration,
            prep_comm_stats,
            online_comm_stats,
            party.inner.get_additional_timers(),
        )
    }
}