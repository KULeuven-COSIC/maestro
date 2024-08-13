use rep3_core::network::ConnectedParty;
use maestro::gf4_circuit::GF4CircuitSemihonestParty;


impl_benchmark_protocol!(
    GF4CircuitBenchmark,  // benchmark struct name
    "gf4-circuit", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| GF4CircuitSemihonestParty::setup(conn, n_worker_threads).unwrap(), // setup
    |party: &mut GF4CircuitSemihonestParty| party, // get ABB<GF8>
    None, // no preprocessing
    None // no finalize
);