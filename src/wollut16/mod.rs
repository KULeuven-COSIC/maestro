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
//! This module notably contains
//!   - [wollut16_benchmark] that implements the AES benchmark
//!   - [WL16Party] the party wrapper for the protocol. [WL16Party] also implements [ArithmeticBlackBox]
//!
//! [^note]: Wolkerstorfer et al. "An ASIC Implementation of the AES S-Boxes" in CT-RSA 2002, <https://doi.org/10.1007/3-540-45760-7_6>.

use std::time::Instant;

use crate::{
    aes::{self, GF8InvBlackBox},
    benchmark::{BenchmarkProtocol, BenchmarkResult},
    chida::ChidaParty,
    network::{task::IoLayerOwned, ConnectedParty},
    party::{error::MpcResult, ArithmeticBlackBox, NoMulTripleRecording},
    share::gf4::GF4,
};

pub mod offline;
pub mod online;

/// The party wrapper for the WOLLUT16 protocol.
pub struct WL16Party {
    inner: ChidaParty,
    prep_ohv: Vec<RndOhvOutput>,
    opt: bool,
}

/// A random one-hot vector of size 16.
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct RndOhv16(u16);

/// Output of the random one-hot vector pre-processing.
///
/// Contains a (2,3)-sharing of a size 16 one-hot vector `RndOhv16` and a (3,3)-sharing of the corresponding `GF4` element that indicates
/// the position of 1 in the vector.
pub struct RndOhvOutput {
    /// share i of one-hot vector
    pub si: RndOhv16,
    /// share i+1 of one-hot vector
    pub sii: RndOhv16,
    /// (3,3) sharing of the position of the 1 in the vector
    pub random: GF4,
}

impl WL16Party {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>) -> MpcResult<Self> {
        ChidaParty::setup(connected, n_worker_threads).map(|party| Self {
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

/// This function implements the AES benchmark.
///
/// The arguments are
/// - `connected` - the local party
/// - `simd` - number of parallel AES calls
/// - `n_worker_threads` - number of worker threads
pub fn wollut16_benchmark(connected: ConnectedParty, simd: usize, n_worker_threads: Option<usize>) {
    let mut party = WL16Party::setup(connected, n_worker_threads).unwrap();
    let setup_comm_stats = party.io().reset_comm_stats();
    let start_prep = Instant::now();
    party.do_preprocessing(0, simd).unwrap();
    let prep_duration = start_prep.elapsed();
    let prep_comm_stats = party.io().reset_comm_stats();

    let input = aes::random_state(party.inner.as_party_mut(), simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(party.inner.as_party_mut());

    let start = Instant::now();
    let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
    let duration = start.elapsed();
    let online_comm_stats = party.io().reset_comm_stats();
    let _ = aes::output(&mut party.inner, output).unwrap();
    party.inner.teardown().unwrap();

    println!("Finished benchmark");

    println!(
        "Party {}: LUT-16 with SIMD={} took {}s (pre-processing) and {}s (online phase)",
        party.inner.party_index(),
        simd,
        prep_duration.as_secs_f64(),
        duration.as_secs_f64()
    );
    println!("Setup:");
    setup_comm_stats.print_comm_statistics(party.inner.party_index());
    println!("Pre-Processing:");
    prep_comm_stats.print_comm_statistics(party.inner.party_index());
    println!("Online Phase:");
    online_comm_stats.print_comm_statistics(party.inner.party_index());
    party.inner.print_statistics();
}

pub struct LUT16Benchmark;

impl BenchmarkProtocol for LUT16Benchmark {
    fn protocol_name(&self) -> String {
        "lut16".to_string()
    }
    fn run(
        &self,
        conn: ConnectedParty,
        simd: usize,
        n_worker_threads: Option<usize>,
    ) -> BenchmarkResult {
        let mut party = WL16Party::setup(conn, n_worker_threads).unwrap();
        let _setup_comm_stats = party.io().reset_comm_stats();
        println!("After setup");
        let start_prep = Instant::now();
        party.do_preprocessing(0, simd).unwrap();
        let prep_duration = start_prep.elapsed();
        let prep_comm_stats = party.io().reset_comm_stats();
        println!("After pre-processing");

        let input = aes::random_state(party.inner.as_party_mut(), simd);
        // create random key states for benchmarking purposes
        let ks = aes::random_keyschedule(party.inner.as_party_mut());

        let start = Instant::now();
        let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
        let duration = start.elapsed();
        let online_comm_stats = party.io().reset_comm_stats();
        println!("After online");
        let _ = aes::output(&mut party.inner, output).unwrap();
        println!("After output");
        party.inner.teardown().unwrap();
        println!("After teardown");

        BenchmarkResult::new(
            prep_duration,
            duration,
            prep_comm_stats,
            online_comm_stats,
            party.inner.get_additional_timers(),
        )
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
    use std::thread::JoinHandle;

    use crate::{
        network::ConnectedParty,
        party::test::{localhost_connect, TestSetup},
    };

    use super::WL16Party;

    pub fn localhost_setup_wl16<
        T1: Send + 'static,
        F1: Send + FnOnce(&mut WL16Party) -> T1 + 'static,
        T2: Send + 'static,
        F2: Send + FnOnce(&mut WL16Party) -> T2 + 'static,
        T3: Send + 'static,
        F3: Send + FnOnce(&mut WL16Party) -> T3 + 'static,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        n_worker_threads: Option<usize>,
    ) -> (
        JoinHandle<(T1, WL16Party)>,
        JoinHandle<(T2, WL16Party)>,
        JoinHandle<(T3, WL16Party)>,
    ) {
        fn adapter<T, Fx: FnOnce(&mut WL16Party) -> T>(
            conn: ConnectedParty,
            f: Fx,
            n_worker_threads: Option<usize>,
        ) -> (T, WL16Party) {
            let mut party = WL16Party::setup(conn, n_worker_threads).unwrap();
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
            T1: Send + 'static,
            F1: Send + FnOnce(&mut WL16Party) -> T1 + 'static,
            T2: Send + 'static,
            F2: Send + FnOnce(&mut WL16Party) -> T2 + 'static,
            T3: Send + 'static,
            F3: Send + FnOnce(&mut WL16Party) -> T3 + 'static,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            std::thread::JoinHandle<(T1, WL16Party)>,
            std::thread::JoinHandle<(T2, WL16Party)>,
            std::thread::JoinHandle<(T3, WL16Party)>,
        ) {
            localhost_setup_wl16(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<
            T1: Send + 'static,
            F1: Send + FnOnce(&mut WL16Party) -> T1 + 'static,
            T2: Send + 'static,
            F2: Send + FnOnce(&mut WL16Party) -> T2 + 'static,
            T3: Send + 'static,
            F3: Send + FnOnce(&mut WL16Party) -> T3 + 'static,
        >(
            n_threads: usize,
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            JoinHandle<(T1, WL16Party)>,
            JoinHandle<(T2, WL16Party)>,
            JoinHandle<(T3, WL16Party)>,
        ) {
            localhost_setup_wl16(f1, f2, f3, Some(n_threads))
        }
    }
}
