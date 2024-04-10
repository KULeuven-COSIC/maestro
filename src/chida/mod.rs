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

use crate::aes::{self};

use crate::network::ConnectedParty;
use crate::party::error::MpcResult;
use crate::party::{CombinedCommStats, Party};

pub mod online;

#[derive(Clone, Copy, Debug)]
pub enum ImplVariant {
    Simple,     // uses the gf8 inversion as in Figure 6
    Optimized   // uses gf8 inversion as in Algorithm 5
}

// Party for Chida et al. semi-honest protocol
pub struct ChidaParty(Party);

impl ChidaParty {
    pub fn setup(connected: ConnectedParty) -> MpcResult<Self> {
        Party::setup(connected).map(|party| Self(party))
    }

    pub fn party_index(&self) -> usize {
        self.0.i
    }

    pub fn print_statistics(&self) {
        self.0.print_statistics()
    }

    pub fn teardown(&mut self) -> MpcResult<()> {
        self.0.teardown()
    }
}
/// [ChidaParty] paired with an [ImplVariant]
pub struct ChidaBenchmarkParty {
    inner: ChidaParty,
    variant: ImplVariant,
}

impl ChidaBenchmarkParty {
    pub fn setup(connected: ConnectedParty, variant: ImplVariant) -> MpcResult<Self> {
        ChidaParty::setup(connected).map(|party| Self{
            inner: party,
            variant
        })
    }
}

// simd: how many parallel AES calls
pub fn chida_benchmark(connected: ConnectedParty, simd: usize, variant: ImplVariant) {
    let mut party = ChidaBenchmarkParty::setup(connected, variant).unwrap();
    let setup_comm_stats = party.inner.0.io().reset_comm_stats();
    let input = aes::random_state(&mut party.inner, simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(&mut party.inner);

    let start = Instant::now();
    let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
    let duration = start.elapsed();
    let online_comm_stats = party.inner.0.io().reset_comm_stats();
    let _ = aes::output(&mut party.inner, output).unwrap();
    party.inner.0.teardown().unwrap();
    
    println!("Finished benchmark");
    
    println!("Party {}: Chida et al. with SIMD={} took {}s", party.inner.0.i, simd, duration.as_secs_f64());

    println!("Setup:");
    setup_comm_stats.print_comm_statistics(party.inner.party_index());
    println!("Pre-Processing:");
    CombinedCommStats::empty().print_comm_statistics(party.inner.party_index());
    println!("Online Phase:");
    online_comm_stats.print_comm_statistics(party.inner.party_index());
    party.inner.print_statistics();
}
