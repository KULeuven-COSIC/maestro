
use crate::rep3_core::network::ConnectedParty;
use crate::chida::{ChidaBenchmarkParty, ImplVariant};

use super::impl_benchmark_protocol;


impl_benchmark_protocol!(
    ChidaBenchmark,  // benchmark struct name
    "chida", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| ChidaBenchmarkParty::setup(conn, ImplVariant::Optimized, n_worker_threads).unwrap(), // setup
    |party: &mut ChidaBenchmarkParty| party, // get ABB<GF8>
    None, // no preprocessing
    None // no finalize
);