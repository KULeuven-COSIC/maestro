use crate::aes::AesVariant;
use crate::rep3_core::network::ConnectedParty;
use crate::{aes::GF8InvBlackBox, wollut16::WL16Party};

use super::impl_benchmark_protocol;

impl_benchmark_protocol!(
    LUT16Benchmark,  // benchmark struct name
    "lut16", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>| WL16Party::setup(conn, n_worker_threads, prot_str).unwrap(), // setup
    |party: &mut WL16Party| party, // get ABB<GF8>
    |party: &mut WL16Party, simd: usize, variant: AesVariant| party.do_preprocessing(0, simd, variant), // do preprocessing
    None // no finalize
);