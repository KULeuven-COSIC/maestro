//! This module implements the *semi-honest* oblivious AES protocol by Chida et al., "High-Throughput Secure AES Computation" in WAHC'18 (<https://doi.org/10.1145/3267973.3267977>).
//!
//! The implementation has two variants, [ImplVariant::Simple] and [ImplVariant::Optimized].
//! These variants differ in the implementation of the `sub_bytes` step of the AES round function. Both variants send the same number of bytes to each party and require the same number of communication rounds.
//!
//! The [ImplVariant::Simple] implements the `GF(2^8)` inversion protocol given in Figure 6 using multiplication from Araki et al.[^note].
//!
//! The [ImplVariant::Optimized] implements the proposed multiplication protocol from Chida et al. including the optimized field operations via local table lookups.
//! Thus, the [ImplVariant::Optimized] should improve local computation but does not improve communication complexity.
//!
//! [^note]: Araki et al. "High-Throughput Semi-Honest Secure Three-Party Computation with an Honest Majority" in CCS'16 (<https://eprint.iacr.org/2016/768>).

use std::time::Duration;

use crate::{aes::{self}, rep3_core::{network::ConnectedParty, party::{error::MpcResult, MainParty}}};

pub mod online;

#[derive(Clone, Copy, Debug)]
pub enum ImplVariant {
    Simple,    // uses the gf8 inversion as in Figure 6
    Optimized, // uses gf8 inversion as in Algorithm 5
}

// Party for Chida et al. semi-honest protocol
pub struct ChidaParty(MainParty);

impl ChidaParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads, prot_str).map(Self)
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

    pub fn get_additional_timers(&self) -> Vec<(String, Duration)> {
        self.0.get_additional_timers()
    }

    pub fn as_party_mut(&mut self) -> &mut MainParty {
        &mut self.0
    }

    pub fn has_multi_threading(&self) -> bool {
        self.0.has_multi_threading()
    }

    pub fn num_worker_threads(&self) -> usize {
        self.0.num_worker_threads()
    }
}
/// [ChidaParty] paired with an [ImplVariant]
pub struct ChidaBenchmarkParty {
    inner: ChidaParty,
    variant: ImplVariant,
}

impl ChidaBenchmarkParty {
    pub fn setup(
        connected: ConnectedParty,
        variant: ImplVariant,
        n_worker_threads: Option<usize>,
        prot_str: Option<String>
    ) -> MpcResult<Self> {
        ChidaParty::setup(connected, n_worker_threads, prot_str).map(|party| Self {
            inner: party,
            variant,
        })
    }

    pub fn party_index(&self) -> usize {
        self.inner.party_index()
    }
}
