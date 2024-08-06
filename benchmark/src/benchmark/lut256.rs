pub struct Lut256SSBenchmark;

impl BenchmarkProtocol for Lut256SSBenchmark {
    fn protocol_name(&self) -> String {
        "lut256_ss".to_string()
    }
    fn run(
            &self,
            conn: ConnectedParty,
            simd: usize,
            n_worker_threads: Option<usize>,
        ) -> BenchmarkResult {
            let mut party = Lut256SSParty::setup(conn, n_worker_threads).unwrap();
            let _setup_comm_stats = party.inner.io().reset_comm_stats();
            println!("After setup");
            let start_prep = Instant::now();
            party.do_preprocessing(0, simd).unwrap();
            let prep_duration = start_prep.elapsed();
            let prep_comm_stats = party.inner.io().reset_comm_stats();
            println!("After pre-processing");
            let input = aes::ss::random_state(&mut party.inner, simd);
            // create random key states for benchmarking purposes
            let ks = aes::random_keyschedule(&mut party.inner);
    
            let start = Instant::now();
            let output = aes::ss::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
            let duration = start.elapsed();
            println!("After online");
            let online_comm_stats = party.inner.io().reset_comm_stats();
            let _ = aes::ss::output(&mut party, output).unwrap();
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

pub struct LUT256Benchmark;

impl BenchmarkProtocol for LUT256Benchmark {
    fn protocol_name(&self) -> String {
        "lut256".to_string()
    }
    fn run(
        &self,
        conn: ConnectedParty,
        simd: usize,
        n_worker_threads: Option<usize>,
    ) -> BenchmarkResult {
        let mut party = LUT256Party::setup(conn, n_worker_threads).unwrap();
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
        println!("After online");
        let online_comm_stats = party.io().reset_comm_stats();
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