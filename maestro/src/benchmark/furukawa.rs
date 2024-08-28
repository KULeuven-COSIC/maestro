
use crate::rep3_core::network::ConnectedParty;
use crate::{aes::GF8InvBlackBox, furukawa::FurukawaParty, share::gf8::GF8, util::ArithmeticBlackBox};

use super::impl_benchmark_protocol;


impl_benchmark_protocol!(
    MalChidaBenchmark, // benchmark struct name
    "mal-chida", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| FurukawaParty::<GF8>::setup(conn, n_worker_threads, false).unwrap(), // setup
    |party: &mut FurukawaParty::<GF8>| party, // get ABB<GF8>
    |party: &mut FurukawaParty::<GF8>, simd: usize| party.do_preprocessing(0, simd), // do preprocessing
    |party: &mut FurukawaParty::<GF8>| party.finalize() // do finalize checks
);

impl_benchmark_protocol!(
    MalChidaRecursiveCheckBenchmark, // benchmark struct name
    "mal-chida-rec-check", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| FurukawaParty::<GF8>::setup(conn, n_worker_threads, true).unwrap(), // setup
    |party: &mut FurukawaParty::<GF8>| party, // get ABB<GF8>
    None, // no preprocessing
    |party: &mut FurukawaParty::<GF8>| party.finalize() // do finalize checks
);