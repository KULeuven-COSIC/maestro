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

use crate::aes::{self, ImplVariant};

use crate::network::ConnectedParty;
use crate::party::error::MpcResult;
use crate::party::Party;

pub mod online;
///

// Party for Chida et al. semi-honest protocol
pub struct ChidaParty(Party);

impl ChidaParty {
    pub fn setup(connected: ConnectedParty) -> MpcResult<Self> {
        Party::setup(connected).map(|party| Self(party))
    }

    pub fn inner_mut(&mut self) -> &mut Party {
        &mut self.0
    }
}

// simd: how many parallel AES calls
pub fn chida_benchmark(connected: ConnectedParty, simd: usize, variant: ImplVariant) {
    let mut party = ChidaParty::setup(connected).unwrap();
    let input = aes::random_state(&mut party, simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(&mut party);

    let start = Instant::now();
    let output = aes::aes128_no_keyschedule(&mut party, input, &ks, variant).unwrap();
    let duration = start.elapsed();
    let _ = aes::output(&mut party, output).unwrap();
    party.0.teardown().unwrap();
    
    println!("Finished benchmark");
    
    println!("Party {}: Chida et al. with SIMD={} took {}s", party.0.i, simd, duration.as_secs_f64());
    party.0.print_comm_statistics();
}
