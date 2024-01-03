use crate::chida::online::{AesState, VectorAesState};
use crate::network::ConnectedParty;
use crate::party::error::MpcResult;
use crate::party::Party;
use crate::share::field::GF8;

mod online;

// Party for Chida et al. semi-honest protocol
pub struct ChidaParty(Party);

impl ChidaParty {
    pub fn setup(connected: ConnectedParty) -> Self {
        Self(Party::setup_semi_honest(connected))
    }

    pub fn random_state(&mut self, size: usize) -> VectorAesState {
        VectorAesState::from_rss_vec(self.0.generate_random(size * 16))
    }

    pub fn aes128_no_keyschedule(&mut self, blocks: VectorAesState, keyschedule: &Vec<AesState>) -> MpcResult<VectorAesState> {
        online::aes128_no_keyschedule(&mut self.0, blocks, keyschedule)
    }

    pub fn output(&mut self, blocks: VectorAesState) -> MpcResult<Vec<GF8>> {
        let shares = blocks.to_rss_vec();
        online::output_round(&mut self.0, &shares, &shares, &shares)
    }
}