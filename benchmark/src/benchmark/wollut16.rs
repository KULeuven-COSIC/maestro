use maestro::{aes::GF8InvBlackBox, network::ConnectedParty, wollut16::WL16Party};

impl_benchmark_protocol!(
    LUT16Benchmark,  // benchmark struct name
    "lut16", // protocol name
    |conn: ConnectedParty, n_worker_threads: Option<usize>| WL16Party::setup(conn, n_worker_threads).unwrap(), // setup
    |party: &mut WL16Party| party, // get ABB<GF8>
    |party: &mut WL16Party, simd: usize| party.do_preprocessing(0, simd), // do preprocessing
    None // no finalize
);