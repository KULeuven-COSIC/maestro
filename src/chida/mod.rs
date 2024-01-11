use std::time::Instant;

use crate::chida::online::{AesKeyState, VectorAesState};
use crate::network::ConnectedParty;
use crate::party::error::MpcResult;
use crate::party::Party;
use crate::share::RssShare;
use crate::share::field::GF8;

mod online;
pub use self::online::ImplVariant;

// Party for Chida et al. semi-honest protocol
pub struct ChidaParty(Party);

impl ChidaParty {
    pub fn setup(connected: ConnectedParty) -> Self {
        Self(Party::setup_semi_honest(connected))
    }

    pub fn random_state(&mut self, size: usize) -> VectorAesState {
        VectorAesState::from_bytes(self.0.generate_random(size * 16))
    }

    pub fn aes128_no_keyschedule(&mut self, blocks: VectorAesState, keyschedule: &Vec<AesKeyState>, variant: ImplVariant) -> MpcResult<VectorAesState> {
        online::aes128_no_keyschedule(&mut self.0, blocks, keyschedule, variant)
    }

    pub fn aes128_keyschedule(&mut self, key: Vec<RssShare<GF8>>, variant: ImplVariant) -> MpcResult<Vec<AesKeyState>> {
        online::aes128_keyschedule(&mut self.0, key, variant)
    }

    pub fn output(&mut self, blocks: VectorAesState) -> MpcResult<Vec<GF8>> {
        let shares = blocks.to_bytes();
        online::output_round(&mut self.0, &shares, &shares, &shares)
    }
}

// simd: how many parallel AES calls
pub fn chida_benchmark(connected: ConnectedParty, simd: usize, variant: ImplVariant) {
    let mut party = ChidaParty::setup(connected);
    let input = party.random_state(simd);
    // create random key states for benchmarking purposes
    let ks: Vec<_> = (0..11).map(|_| {
        let rk = party.0.generate_random(16);
        AesKeyState::from_rss_vec(rk)
    })
    .collect();

    let start = Instant::now();
    let _output = party.aes128_no_keyschedule(input, &ks, variant).unwrap();
    party.0.teardown();
    let duration = start.elapsed();
    println!("Finished benchmark");
    
    println!("Party {}: Chida et al. with SIMD={} took {}s", party.0.i, simd, duration.as_secs_f64());
    party.0.print_comm_statistics();
}