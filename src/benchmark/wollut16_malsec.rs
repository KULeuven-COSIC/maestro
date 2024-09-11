use crate::aes::AesVariant;
use crate::rep3_core::network::ConnectedParty;
use crate::{aes::GF8InvBlackBox, util::ArithmeticBlackBox, wollut16_malsec::{PrepCheckType, WL16ASParty}};

use super::impl_benchmark_protocol;

impl_benchmark_protocol!(
    MalLUT16BitStringBenchmark, // benchmark struct name
    "mal-lut16-bitstring", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>| WL16ASParty::setup(conn, false, false, PrepCheckType::BitString, true, n_worker_threads, prot_str).unwrap(), // setup
    |party: &mut WL16ASParty| party, // get ABB<GF8>
    |party: &mut WL16ASParty, simd: usize, variant: AesVariant| party.do_preprocessing(0, simd, variant), // do preprocessing
    |party: &mut WL16ASParty| party.finalize() // do finalize checks
);

impl_benchmark_protocol!(
    MalLUT16OhvBenchmark, // benchmark struct name
    "mal-lut16-ohv", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>| WL16ASParty::setup(conn, false, false, PrepCheckType::OhvCheck, true, n_worker_threads, prot_str).unwrap(), // setup
    |party: &mut WL16ASParty| party, // get ABB<GF8>
    |party: &mut WL16ASParty, simd: usize, variant: AesVariant| party.do_preprocessing(0, simd, variant), // do preprocessing
    |party: &mut WL16ASParty| party.finalize() // do finalize checks
);