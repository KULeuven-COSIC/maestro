//! This module implements the *semi-honest* oblivious AES protocol "LUT 256".
//!
//! The core is a sub-protocol to compute the SBOX using a lookup table.
//! This table lookup requires a pre-processed random one-hot vector of size `256`.
//!
//! This module notably contains [LUT256Party] the party wrapper for the protocol. [LUT256Party] also implements [ArithmeticBlackBox]
//!

use std::time::Duration;

use crate::rep3_core::{network::{task::IoLayerOwned, ConnectedParty}, party::error::MpcResult};

use crate::{
    chida::ChidaParty,
    share::gf8::GF8, util::ArithmeticBlackBox,
};
mod lut256_tables;
pub mod offline;
mod online;
pub mod lut256_ss;

/// A random one-hot vector of size `256`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RndOhv([u64; 4]);

/// The party wrapper for the LUT 256 protocol.
pub struct LUT256Party {
    inner: ChidaParty,
    prep_ohv: Vec<RndOhv256Output>,
    lut_time: Duration,
}

/// Output of the random one-hot vector pre-processing.
///
/// Contains a (2,3)-sharing of a size `256` one-hot vector `RndOhv` and a (2,3)-sharing of the corresponding `GF8` element that indicates
/// the position of 1 in the vector.
pub struct RndOhv256Output {
    /// share i of one-hot vector
    pub si: RndOhv,
    /// share i+1 of one-hot vector
    pub sii: RndOhv,
    /// (2,3) sharing of the position of the 1 in the vector
    pub random_si: GF8,
    pub random_sii: GF8,
}

/// Output of the random one-hot vector pre-processing.
///
/// Contains a (3,3)-sharing of a size `256` one-hot vector `RndOhv` and a (2,3)-sharing of the corresponding `GF8` element that indicates
/// the position of 1 in the vector.
pub struct RndOhv256OutputSS {
    pub ohv: RndOhv,
    /// (2,3) sharing of the position of the 1 in the vector
    pub random_si: GF8,
    pub random_sii: GF8,
}

impl LUT256Party {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>) -> MpcResult<Self> {
        ChidaParty::setup(connected, n_worker_threads, prot_str).map(|party| Self {
            inner: party,
            prep_ohv: Vec::new(),
            lut_time: Duration::from_secs(0),
        })
    }

    pub fn io(&self) -> &IoLayerOwned {
        <ChidaParty as ArithmeticBlackBox<GF8>>::io(&self.inner)
    }
}

impl RndOhv {
    pub fn new(table: [u64; 4]) -> Self {
        Self(table)
    }

    pub fn lut(&self, offset: usize, table: &[[[u64; 4]; 8]; 256]) -> GF8 {
        let table = &table[offset];
        let mut res = 0u8;
        for (i, bit_table) in table.iter().enumerate().take(8) {
            let part_0 = self.0[0] & bit_table[0];
            let part_1 = self.0[1] & bit_table[1];
            let part_2 = self.0[2] & bit_table[2];
            let part_3 = self.0[3] & bit_table[3];
            let bit = part_0.count_ones()
                ^ part_1.count_ones()
                ^ part_2.count_ones()
                ^ part_3.count_ones();
            res |= ((bit & 0x1) << i) as u8;
        }
        GF8(res)
    }
}

#[cfg(test)]
mod test {
    use crate::rep3_core::{
        network::ConnectedParty,
        test::{localhost_connect, TestSetup},
    };

    use super::LUT256Party;

    pub fn localhost_setup_lut256<
        T1: Send,
        F1: Send + FnOnce(&mut LUT256Party) -> T1,
        T2: Send,
        F2: Send + FnOnce(&mut LUT256Party) -> T2,
        T3: Send,
        F3: Send + FnOnce(&mut LUT256Party) -> T3,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        n_worker_threads: Option<usize>,
    ) -> (
        (T1, LUT256Party),
        (T2, LUT256Party),
        (T3, LUT256Party),
    ) {
        fn adapter<T, Fx: FnOnce(&mut LUT256Party) -> T>(
            conn: ConnectedParty,
            f: Fx,
            n_worker_threads: Option<usize>,
        ) -> (T, LUT256Party) {
            let mut party = LUT256Party::setup(conn, n_worker_threads, None).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(
            move |conn_party| adapter(conn_party, f1, n_worker_threads),
            move |conn_party| adapter(conn_party, f2, n_worker_threads),
            move |conn_party| adapter(conn_party, f3, n_worker_threads),
        )
    }

    pub struct LUT256Setup;
    impl TestSetup<LUT256Party> for LUT256Setup {
        fn localhost_setup<
            T1: Send,
            F1: Send + FnOnce(&mut LUT256Party) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut LUT256Party) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut LUT256Party) -> T3,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, LUT256Party),
            (T2, LUT256Party),
            (T3, LUT256Party),
        ) {
            localhost_setup_lut256(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<
            T1: Send,
            F1: Send + FnOnce(&mut LUT256Party) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut LUT256Party) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut LUT256Party) -> T3,
        >(
            n_threads: usize,
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, LUT256Party),
            (T2, LUT256Party),
            (T3, LUT256Party),
        ) {
            localhost_setup_lut256(f1, f2, f3, Some(n_threads))
        }
    }
}
