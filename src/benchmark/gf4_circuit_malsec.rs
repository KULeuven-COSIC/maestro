use crate::rep3_core::network::ConnectedParty;
use crate::{gf4_circuit_malsec::{GF4CircuitASParty, MultCheckType}, util::ArithmeticBlackBox};

use super::impl_benchmark_protocol;

impl_benchmark_protocol!(
    GF4CircuitASBenchmark, // benchmark struct name
    "mal-gf4-circuit", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>| GF4CircuitASParty::setup(conn, n_worker_threads, prot_str, MultCheckType::Recursive { check_after_sbox: false, use_gf4p4_check: false }).unwrap(), // setup
    |party: &mut GF4CircuitASParty| party, // get ABB<GF8>
    None, // no preprocessing
    |party: &mut GF4CircuitASParty| party.finalize() // do finalize checks
);

impl_benchmark_protocol!(
    GF4CircuitASGF4p4Benchmark, // benchmark struct name
    "mal-gf4-circuit-gf4p4", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>| GF4CircuitASParty::setup(conn, n_worker_threads, prot_str, MultCheckType::Recursive { check_after_sbox: false, use_gf4p4_check: true }).unwrap(), // setup
    |party: &mut GF4CircuitASParty| party, // get ABB<GF8>
    None, // no preprocessing
    |party: &mut GF4CircuitASParty| party.finalize() // do finalize checks
);