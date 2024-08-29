use crate::rep3_core::network::ConnectedParty;
use crate::gf4_circuit::GF4CircuitSemihonestParty;

use super::impl_benchmark_protocol;


impl_benchmark_protocol!(
    GF4CircuitBenchmark,  // benchmark struct name
    "gf4-circuit", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>| GF4CircuitSemihonestParty::setup(conn, n_worker_threads, prot_str).unwrap(), // setup
    |party: &mut GF4CircuitSemihonestParty| party, // get ABB<GF8>
    None, // no preprocessing
    None // no finalize
);