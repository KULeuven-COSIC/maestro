



// Actively secure party to run AES-GCM
// pub struct GcmParty {
//     inner: MainParty,
//     broadcast_context: BroadcastContext,
//     gf4_triples_to_check: MulTripleVector<BsGF4>,
//     gf128_triples_to_check: MulTripleVector<GF128>,
// }

// impl GcmParty {
//     pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>) -> MpcResult<Self> {
//         MainParty::setup(connected, n_worker_threads).map(|party| Self {
//             inner: party,
//             broadcast_context: BroadcastContext::new(),
//             gf4_triples_to_check: MulTripleVector::new(),
//             gf128_triples_to_check: MulTripleVector::new(),
//         })
//     }

//     pub fn verify_multiplications(&mut self) -> MpcResult<()> {

//     }
// }