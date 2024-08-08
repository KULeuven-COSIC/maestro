use rep3_core::network::ConnectedParty;
use maestro::{aes::GF8InvBlackBox, util::ArithmeticBlackBox, wollut16_malsec::WL16ASParty};

impl_benchmark_protocol!(
    MalLUT16Benchmark, // benchmark struct name
    "mal-lut16", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| WL16ASParty::setup(conn, false, false, false, n_worker_threads).unwrap(), // setup
    |party: &mut WL16ASParty| party, // get ABB<GF8>
    |party: &mut WL16ASParty, simd: usize| party.do_preprocessing(0, simd), // do preprocessing
    |party: &mut WL16ASParty| party.finalize() // do finalize checks
);

impl_benchmark_protocol!(
    MalLUT16PrepCheckBenchmark, // benchmark struct name
    "mal-lut16-prep-check", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| WL16ASParty::setup(conn, true, false, false, n_worker_threads).unwrap(), // setup
    |party: &mut WL16ASParty| party, // get ABB<GF8>
    |party: &mut WL16ASParty, simd: usize| party.do_preprocessing(0, simd), // do preprocessing
    |party: &mut WL16ASParty| party.finalize() // do finalize checks
);

impl_benchmark_protocol!(
    MalLUT16AllCheckBenchmark, // benchmark struct name
    "mal-lut16-all-check", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| WL16ASParty::setup(conn, true, true, false, n_worker_threads).unwrap(), // setup
    |party: &mut WL16ASParty| party, // get ABB<GF8>
    |party: &mut WL16ASParty, simd: usize| party.do_preprocessing(0, simd), // do preprocessing
    |party: &mut WL16ASParty| party.finalize() // do finalize checks
);

impl_benchmark_protocol!(
    MalLUT16BitStringBenchmark, // benchmark struct name
    "mal-lut16-bitstring", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| WL16ASParty::setup(conn, false, false, true, n_worker_threads).unwrap(), // setup
    |party: &mut WL16ASParty| party, // get ABB<GF8>
    |party: &mut WL16ASParty, simd: usize| party.do_preprocessing(0, simd), // do preprocessing
    |party: &mut WL16ASParty| party.finalize() // do finalize checks
);