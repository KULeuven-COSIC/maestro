pub struct MalLUT16Benchmark;
pub struct MalLUT16PrepCheckBenchmark;

pub struct MalLUT16AllCheckBenchmark;

pub struct MalLUT16BitStringBenchmark;

fn run(conn: ConnectedParty, simd: usize, n_worker_threads: Option<usize>, check_after_prep: bool, check_after_sbox: bool, use_bitstring_check: bool) -> BenchmarkResult {
    let mut party = WL16ASParty::setup(conn, check_after_prep, check_after_sbox, use_bitstring_check, n_worker_threads).unwrap();
    let _setup_comm_stats = party.io().reset_comm_stats();
    println!("After setup");
    let start_prep = Instant::now();
    party.do_preprocessing(0, simd).unwrap();
    let prep_duration = start_prep.elapsed();
    let prep_comm_stats = party.io().reset_comm_stats();
    println!("After pre-processing");

    let input = aes::random_state(&mut party.inner, simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(&mut party.inner);

    let start = Instant::now();
    let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
    println!("After AES: {}s", start.elapsed().as_secs_f64());
    // check all multipliction triples
    party.finalize().unwrap();
    let duration = start.elapsed();
    let online_comm_stats = party.io().reset_comm_stats();
    println!("After online");
    let _ = aes::output(&mut party, output).unwrap();
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

impl BenchmarkProtocol for MalLUT16Benchmark {
    fn protocol_name(&self) -> String {
        "mal-lut16".to_string()
    }
    fn run(&self, conn: ConnectedParty, simd: usize, n_worker_threads: Option<usize>) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, false, false, false)
    }
}

impl BenchmarkProtocol for MalLUT16PrepCheckBenchmark {
    fn protocol_name(&self) -> String {
        "mal-lut16-prep-check".to_string()
    }
    fn run(&self, conn: ConnectedParty, simd: usize, n_worker_threads: Option<usize>) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, true, false, false)
    }
}

impl BenchmarkProtocol for MalLUT16AllCheckBenchmark {
    fn protocol_name(&self) -> String {
        "mal-lut16-all-check".to_string()
    }
    fn run(&self, conn: ConnectedParty, simd: usize, n_worker_threads: Option<usize>) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, true, true, false)
    }
}

impl BenchmarkProtocol for MalLUT16BitStringBenchmark {
    fn protocol_name(&self) -> String {
        "mal-lut16-bitstring".to_string()
    }
    fn run(&self, conn: ConnectedParty, simd: usize, n_worker_threads: Option<usize>) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, false, false, true)
    }
}