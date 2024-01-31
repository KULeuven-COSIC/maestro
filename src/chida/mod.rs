//! This module implements the semi-honest oblivious AES protocol by Chida et al., "High-Throughput Secure AES Computation" in WAHC'18 (https://doi.org/10.1145/3267973.3267977).
//! 
//! The implementation has two variants, [ImplVariant::Simple] and [ImplVariant::Optimized].
//! These variants differ in the implementation of the `sub_bytes` step of the AES round function. Both variants send the same number of bytes to each party and require the same number of communication rounds.
//! 
//! The [ImplVariant::Simple] implements the GF(2^8) inversion protocol given in Figure 6 using multiplication from Araki et al.[^note].
//! 
//! The [ImplVariant::Optimized] implements the proposed multiplication protocol from Chida et al. including the optimized field operations via local table lookups.
//! Thus, the [ImplVariant::Optimized] should improve local computation but does not improve communication complexity.
//! 
//! [^note]: Araki et al. "High-Throughput Semi-Honest Secure Three-Party Computation with an Honest Majority" in CCS'16 (https://eprint.iacr.org/2016/768)

use std::time::Instant;

use crate::chida::online::{AesKeyState, VectorAesState};
use crate::network::ConnectedParty;
use crate::party::error::MpcResult;
use crate::party::Party;
use crate::share::RssShare;
use crate::share::field::GF8;

pub mod online;
pub use self::online::ImplVariant;

///

// Party for Chida et al. semi-honest protocol
pub struct ChidaParty {
    inner: Party,
}

impl ChidaParty {
    pub fn setup(connected: ConnectedParty) -> Self {
        let party = Party::setup_semi_honest(connected);
        Self {
            inner: party,
        }
    }

    pub fn inner(&self) -> &Party {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut Party {
        &mut self.inner
    }

    pub fn random_state(&mut self, size: usize) -> VectorAesState {
        VectorAesState::from_bytes(self.inner.generate_random(size * 16))
    }

    pub fn aes128_no_keyschedule(&mut self, blocks: VectorAesState, keyschedule: &Vec<AesKeyState>, variant: ImplVariant) -> MpcResult<VectorAesState> {
        online::aes128_no_keyschedule(self.inner_mut(), blocks, keyschedule, variant)
    }

    pub fn aes128_keyschedule(&mut self, key: Vec<RssShare<GF8>>, variant: ImplVariant) -> MpcResult<Vec<AesKeyState>> {
        online::aes128_keyschedule(self.inner_mut(), key, variant)
    }

    pub fn output(&mut self, blocks: VectorAesState) -> MpcResult<Vec<GF8>> {
        let shares = blocks.to_bytes();
        online::output_round(&mut self.inner, &shares, &shares, &shares)
    }
}

// simd: how many parallel AES calls
pub fn chida_benchmark(connected: ConnectedParty, simd: usize, variant: ImplVariant) {
    let mut party = ChidaParty::setup(connected);
    let input = party.random_state(simd);
    // create random key states for benchmarking purposes
    let ks: Vec<_> = (0..11).map(|_| {
        let rk = party.inner.generate_random(16);
        AesKeyState::from_rss_vec(rk)
    })
    .collect();

    let start = Instant::now();
    let output = party.aes128_no_keyschedule(input, &ks, variant).unwrap();
    let duration = start.elapsed();
    let _ = party.output(output).unwrap();
    party.inner.teardown();
    
    println!("Finished benchmark");
    
    println!("Party {}: Chida et al. with SIMD={} took {}s", party.inner.i, simd, duration.as_secs_f64());
    party.inner.print_comm_statistics();
}