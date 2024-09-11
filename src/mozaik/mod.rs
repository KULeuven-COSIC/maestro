use crate::{gf4_circuit::GF4CircuitSemihonestParty, rep3_core::{network::ConnectedParty, party::error::MpcResult}, util::ArithmeticBlackBox};

/// Semi-honest security
pub struct MozaikParty(GF4CircuitSemihonestParty);

impl MozaikParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, prot_string: Option<String>) -> MpcResult<Self> {
        GF4CircuitSemihonestParty::setup(connected, n_worker_threads, prot_string).map(|party| Self(party))
    }
}

impl<F: Field> ArithmeticBlackBox<F> for MozaikParty {
    
}