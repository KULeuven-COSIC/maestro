pub struct GF4CircuitASBenchmark;
pub struct GF4CircuitAllCheckASBenchmark;

pub struct GF4CircuitASBucketBeaverBenchmark;
pub struct GF4CircuitASRecBeaverBenchmark;

fn run(
    conn: ConnectedParty,
    simd: usize,
    n_worker_threads: Option<usize>,
    check_type: MultCheckType,
) -> BenchmarkResult {
    let mut party = GF4CircuitASParty::setup(conn, n_worker_threads, check_type).unwrap();
    let _setup_comm_stats = party.io().reset_comm_stats();
    println!("After setup");

    let input = aes::random_state(&mut party.inner, simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(&mut party.inner);
    
    let start_prep = Instant::now();
    party.do_preprocessing(0, simd).unwrap();
    let mut prep_duration = start_prep.elapsed();
    let mut prep_comm_stats = party.io().reset_comm_stats();
    println!("After preprocessing");

    let start = Instant::now();
    let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
    party.finalize().unwrap();
    let duration = start.elapsed();
    println!("After online");
    let online_comm_stats = party.io().reset_comm_stats();
    let _ = aes::output(&mut party, output).unwrap();
    println!("After output");
    party.inner.teardown().unwrap();
    println!("After teardown");

    if let MultCheckType::Recursive { .. } = check_type {
        // in this case, there is no preprocessing
        prep_duration = Duration::from_secs(0);
        prep_comm_stats = CombinedCommStats::empty();
    }

    BenchmarkResult::new(
        prep_duration,
        duration,
        prep_comm_stats,
        online_comm_stats,
        party.inner.get_additional_timers(),
    )
}

impl BenchmarkProtocol for GF4CircuitASBenchmark {
    fn protocol_name(&self) -> String {
        "mal-gf4-circuit".to_string()
    }

    fn run(
            &self,
            conn: ConnectedParty,
            simd: usize,
            n_worker_threads: Option<usize>,
        ) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, MultCheckType::Recursive { check_after_sbox: false })
    }
    
}

impl BenchmarkProtocol for GF4CircuitAllCheckASBenchmark {
    fn protocol_name(&self) -> String {
        "mal-gf4-circuit-all-check".to_string()
    }

    fn run(
            &self,
            conn: ConnectedParty,
            simd: usize,
            n_worker_threads: Option<usize>,
        ) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, MultCheckType::Recursive { check_after_sbox: false })
    }
}

impl BenchmarkProtocol for GF4CircuitASBucketBeaverBenchmark {
    fn protocol_name(&self) -> String {
        "mal-gf4-circuit-bucket-beaver".to_string()
    }

    fn run(
            &self,
            conn: ConnectedParty,
            simd: usize,
            n_worker_threads: Option<usize>,
        ) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, MultCheckType::BucketBeaver)
    }
}

impl BenchmarkProtocol for GF4CircuitASRecBeaverBenchmark {
    fn protocol_name(&self) -> String {
        "mal-gf4-circuit-recursive-beaver".to_string()
    }

    fn run(
            &self,
            conn: ConnectedParty,
            simd: usize,
            n_worker_threads: Option<usize>,
        ) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, MultCheckType::RecursiveBeaver)
    }
}