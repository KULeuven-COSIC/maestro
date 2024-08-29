//! This module implements the *semi-honest* oblivious AES protocol "WOL LUT 16".
//!
//! The core is a sub-protocol (`Protocol 2`) to compute multiplicative inverses in `GF(2^8)`.
//! This works as follows:
//! 1) Use the WOL[^note] transform to convert the element `GF(2^8)` to `GF(2^4)^2`.
//! 2) Compute the inverse of the `GF(2^4)^2` element using a single inversion in `GF(2^4)`. To compute the `GF(2^4)` inversion a pre-processed lookup table of 16-bits is used.
//! 3) Use the reverse WOL transform to convert the result to `GF(2^8)`.
//! 
//! The *maliciously-secure* variant of this protocol is found in [crate::wollut16_malsec].
//!
//! This module notably contains [WL16Party] the party wrapper for the protocol. [WL16Party] also implements [ArithmeticBlackBox]
//!
//! [^note]: Wolkerstorfer et al. "An ASIC Implementation of the AES S-Boxes" in CT-RSA 2002, <https://doi.org/10.1007/3-540-45760-7_6>.


use crate::{
    chida::ChidaParty,
    share::gf4::GF4, util::{mul_triple_vec::NoMulTripleRecording, ArithmeticBlackBox},
};
use crate::rep3_core::{network::{task::IoLayerOwned, ConnectedParty},
party::error::MpcResult};

pub mod offline;
pub mod online;

/// The party wrapper for the WOLLUT16 protocol.
pub struct WL16Party {
    inner: ChidaParty,
    prep_ohv: Vec<RndOhv16Output>,
    opt: bool,
}

/// A random one-hot vector of size 16.
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct RndOhv16(u16);

/// Output of the random one-hot vector pre-processing.
///
/// Contains a (2,3)-sharing of a size 16 one-hot vector `RndOhv16` and a (2,3)-sharing of the corresponding `GF4` element that indicates
/// the position of 1 in the vector.
pub struct RndOhv16Output {
    /// share i of one-hot vector
    pub si: RndOhv16,
    /// share i+1 of one-hot vector
    pub sii: RndOhv16,
    /// (2,3) sharing of the position of the 1 in the vector
    pub random_si: GF4,
    pub random_sii: GF4,
}

impl WL16Party {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, prot_str: Option<String>) -> MpcResult<Self> {
        ChidaParty::setup(connected, n_worker_threads, prot_str).map(|party| Self {
            inner: party,
            prep_ohv: Vec::new(),
            opt: true,
        })
    }

    pub fn prepare_rand_ohv(&mut self, mut n: usize) -> MpcResult<()> {
        if self.opt {
            n = if n % 2 == 0 { n } else { n + 1 };
        }
        let mut new = if self.inner.has_multi_threading() {
            offline::generate_random_ohv16_mt(self.inner.as_party_mut(), &mut NoMulTripleRecording, n)?
        } else {
            offline::generate_random_ohv16(self.inner.as_party_mut(), &mut NoMulTripleRecording, n)?
        };
        if self.prep_ohv.is_empty() {
            self.prep_ohv = new;
        } else {
            self.prep_ohv.append(&mut new);
        }
        Ok(())
    }

    pub fn io(&self) -> &IoLayerOwned {
        <ChidaParty as ArithmeticBlackBox<GF4>>::io(&self.inner)
    }
}

impl RndOhv16 {
    pub fn new(table: u16) -> Self {
        Self(table)
    }

    /// tables contains table\[offset ^ i\] at position offset
    /// table\[offset ^ i\]\[j\] is the j-th bit of the lookup
    #[inline]
    pub fn lut(&self, offset: usize, tables: &[[u16; 4]; 16]) -> GF4 {
        let table = &tables[offset];
        self.lut_table(table)
    }

    #[inline]
    fn lut_table(&self, table: &[u16; 4]) -> GF4 {
        let b0 = self.0 & table[0];
        let b1 = self.0 & table[1];
        let b2 = self.0 & table[2];
        let b3 = self.0 & table[3];
        let res = (b0.count_ones() & 0x1)
            | (b1.count_ones() & 0x1) << 1
            | (b2.count_ones() & 0x1) << 2
            | (b3.count_ones() & 0x1) << 3;
        GF4::new_unchecked(res as u8)
    }

    #[inline]
    pub fn lut_rss(
        offset: usize,
        rnd_ohv_si: &Self,
        rnd_ohv_sii: &Self,
        tables: &[[u16; 4]; 16],
    ) -> (GF4, GF4) {
        let table = &tables[offset];
        (rnd_ohv_si.lut_table(table), rnd_ohv_sii.lut_table(table))
    }
}

#[cfg(test)]
mod test {
    use crate::rep3_core::{
        network::ConnectedParty,
        test::{localhost_connect, TestSetup},
    };

    use super::WL16Party;

    pub fn localhost_setup_wl16<
        T1: Send,
        F1: Send + FnOnce(&mut WL16Party) -> T1,
        T2: Send,
        F2: Send + FnOnce(&mut WL16Party) -> T2,
        T3: Send,
        F3: Send + FnOnce(&mut WL16Party) -> T3,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        n_worker_threads: Option<usize>,
    ) -> (
        (T1, WL16Party),
        (T2, WL16Party),
        (T3, WL16Party),
    ) {
        fn adapter<T, Fx: FnOnce(&mut WL16Party) -> T>(
            conn: ConnectedParty,
            f: Fx,
            n_worker_threads: Option<usize>,
        ) -> (T, WL16Party) {
            let mut party = WL16Party::setup(conn, n_worker_threads, None).unwrap();
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

    pub struct WL16Setup;
    impl TestSetup<WL16Party> for WL16Setup {
        fn localhost_setup<
            T1: Send,
            F1: Send + FnOnce(&mut WL16Party) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut WL16Party) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut WL16Party) -> T3,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, WL16Party),
            (T2, WL16Party),
            (T3, WL16Party),
        ) {
            localhost_setup_wl16(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<
            T1: Send,
            F1: Send + FnOnce(&mut WL16Party) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut WL16Party) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut WL16Party) -> T3,
        >(
            n_threads: usize,
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, WL16Party),
            (T2, WL16Party),
            (T3, WL16Party),
        ) {
            localhost_setup_wl16(f1, f2, f3, Some(n_threads))
        }
    }
}
