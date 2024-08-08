use rep3_core::network::ConnectedParty;
use maestro::{aes::GF8InvBlackBox, gf4_circuit_malsec::{GF4CircuitASParty, MultCheckType}, util::ArithmeticBlackBox};

impl_benchmark_protocol!(
    GF4CircuitASBenchmark, // benchmark struct name
    "mal-gf4-circuit", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| GF4CircuitASParty::setup(conn, n_worker_threads, MultCheckType::Recursive { check_after_sbox: false }).unwrap(), // setup
    |party: &mut GF4CircuitASParty| party, // get ABB<GF8>
    None, // no preprocessing
    |party: &mut GF4CircuitASParty| party.finalize() // do finalize checks
);

impl_benchmark_protocol!(
    GF4CircuitAllCheckASBenchmark, // benchmark struct name
    "mal-gf4-circuit-all-check", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| GF4CircuitASParty::setup(conn, n_worker_threads, MultCheckType::Recursive { check_after_sbox: true }).unwrap(), // setup
    |party: &mut GF4CircuitASParty| party, // get ABB<GF8>
    None, // no preprocessing
    |party: &mut GF4CircuitASParty| party.finalize() // do finalize checks
);

impl_benchmark_protocol!(
    GF4CircuitASBucketBeaverBenchmark, // benchmark struct name
    "mal-gf4-circuit-bucket-beaver", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| GF4CircuitASParty::setup(conn, n_worker_threads, MultCheckType::BucketBeaver).unwrap(), // setup
    |party: &mut GF4CircuitASParty| party, // get ABB<GF8>
    |party: &mut GF4CircuitASParty, simd: usize| party.do_preprocessing(0, simd), // do preprocessing
    |party: &mut GF4CircuitASParty| party.finalize() // do finalize checks
);

impl_benchmark_protocol!(
    GF4CircuitASRecBeaverBenchmark, // benchmark struct name
    "mal-gf4-circuit-recursive-beaver", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| GF4CircuitASParty::setup(conn, n_worker_threads, MultCheckType::RecursiveBeaver).unwrap(), // setup
    |party: &mut GF4CircuitASParty| party, // get ABB<GF8>
    |party: &mut GF4CircuitASParty, simd: usize| party.do_preprocessing(0, simd), // do preprocessing
    |party: &mut GF4CircuitASParty| party.finalize() // do finalize checks
);