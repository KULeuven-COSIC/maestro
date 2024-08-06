//! This module implements the *maliciously-secure* oblivious AES protocol "WOL LUT 16".
//! 
//! The core is a sub-protocol (`Protocol 3`) to compute multiplicative inverses in `GF(2^8)`.
//! This works as follows:
//! 1) Use the WOL[^note] transform to convert the element `GF(2^8)` to `GF(2^4)^2`.
//! 2) Compute the inverse of the `GF(2^4)^2` element using a single inversion in `GF(2^4)`. To compute the `GF(2^4)` inversion a pre-processed lookup table of 16-bits is used.
//! 3) Use the reverse WOL transform to convert the result to `GF(2^8)`.
//! 
//! The main difference to the *semi-honest* WOL LUT 16 in [crate::wollut16] is that we in addition have a verification phase for multiplication triples generated during the protocol execution.
//! TODO: Add brief text on consistency check for views of different parties.
//!
//! This module notably contains
//!   - [WL16ASParty] the party wrapper for the protocol.
//!
//! [^note]: Wolkerstorfer et al. "An ASIC Implementation of the AES S-Boxes" in CT-RSA 2002, <https://doi.org/10.1007/3-540-45760-7_6>.

use std::time::Instant;

use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::{
    aes::{self, GF8InvBlackBox}, network::{task::IoLayerOwned, ConnectedParty}, party::{broadcast::{Broadcast, BroadcastContext}, error::{MpcError, MpcResult}, ArithmeticBlackBox, MainParty, MulTripleRecorder, MulTripleVector, Party}, share::{bs_bool16::BsBool16, gf2p64::GF2p64, gf4::BsGF4, gf8::GF8, RssShare}, wollut16::RndOhvOutput
};

pub mod mult_verification;
mod offline;
pub mod online;

/// Party for WOLLUT16 with active security
pub struct WL16ASParty{
    inner: MainParty,
    prep_ohv: Vec<RndOhvOutput>,
    check_after_prep: bool,
    check_after_sbox: bool,
    use_bitstring_check: bool,
    // Multiplication triples that need checking at the end
    gf4_triples_to_check: MulTripleVector<BsGF4>,
    gf2_triples_to_check: MulTripleVector<BsBool16>,
    gf64_triples_to_check: MulTripleVector<GF2p64>,
    broadcast_context: BroadcastContext,
}

impl WL16ASParty {
    pub fn setup(connected: ConnectedParty, check_after_prep: bool, check_after_sbox: bool, use_bitstring_check: bool, n_worker_threads: Option<usize>) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads).map(|party| Self {
            inner: party,
            prep_ohv: Vec::new(),
            check_after_prep,
            check_after_sbox,
            use_bitstring_check,
            gf4_triples_to_check: MulTripleVector::new(),
            gf2_triples_to_check: MulTripleVector::new(),
            gf64_triples_to_check: MulTripleVector::new(),
            broadcast_context: BroadcastContext::new(),
        })
    }

    fn prepare_rand_ohv(&mut self, n: usize) -> MpcResult<()> {
        let mut new = if self.inner.has_multi_threading() && self.inner.num_worker_threads() <= n {
            offline::generate_random_ohv16_mt(self, n, self.use_bitstring_check)?
        }else{
            offline::generate_random_ohv16(self, n, self.use_bitstring_check)?
        };
        if self.check_after_prep {
            self.verify_multiplications()?;
        }
        if self.prep_ohv.is_empty() {
            self.prep_ohv = new;
        } else {
            self.prep_ohv.append(&mut new);
        }
        Ok(())
    }

    fn verify_multiplications(&mut self) -> MpcResult<()> {
        let t = Instant::now();
        let res = if self.inner.has_multi_threading() {
            mult_verification::verify_multiplication_triples_mt(&mut self.inner, &mut self.broadcast_context, &mut self.gf4_triples_to_check, &mut self.gf2_triples_to_check, &mut self.gf64_triples_to_check, false)
        }else{
            mult_verification::verify_multiplication_triples(&mut self.inner, &mut self.broadcast_context, &mut self.gf4_triples_to_check, &mut self.gf2_triples_to_check, &mut self.gf64_triples_to_check, false)
        };
        match res {
            Ok(true) => {
                println!("verify_multiplications: {}s", t.elapsed().as_secs_f64());
                Ok(())
            },
            Ok(false) => Err(MpcError::MultCheck),
            Err(err) => Err(err)
        }
    }
}

impl ArithmeticBlackBox<GF8> for WL16ASParty {
    type Digest = Sha256;
    type Rng = ChaCha20Rng;

    #[inline]
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }

    fn io(&self) -> &IoLayerOwned {
        self.inner.io()
    }

    fn pre_processing(&mut self, _n_multiplications: usize) -> MpcResult<()> {
        unimplemented!()
    }

    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=GF8> {
        self.inner.generate_alpha(n)
    }

    fn generate_random(&mut self, n: usize) -> Vec<RssShare<GF8>> {
        self.inner.generate_random(n)
    }

    fn input_round(&mut self, _my_input: &[GF8]) -> MpcResult<(Vec<RssShare<GF8>>, Vec<RssShare<GF8>>, Vec<RssShare<GF8>>)> {
        unimplemented!()
    }

    fn mul(&mut self, _ci: &mut [GF8], _cii: &mut [GF8], _ai: &[GF8], _aii: &[GF8], _bi: &[GF8], _bii: &[GF8]) -> MpcResult<()> {
        unimplemented!()
    }

    fn output_round(&mut self, si: &[GF8], sii: &[GF8]) -> MpcResult<Vec<GF8>> {
        let output = self.inner.open_rss(&mut self.broadcast_context, si, sii)?;
        let context = std::mem::replace(&mut self.broadcast_context, BroadcastContext::new());
        self.inner.compare_view(context)?;
        Ok(output)
    }

    fn finalize(&mut self) -> MpcResult<()> {
        self.verify_multiplications()?;
        let context = std::mem::replace(&mut self.broadcast_context, BroadcastContext::new());
        self.inner.compare_view(context)
    }
}

fn div16_ceil(n: usize) -> usize {
    if n % 16 == 0 {
        n / 16
    }else{
        n / 16 + 1
    }
}

impl GF8InvBlackBox for WL16ASParty {
    #[inline]
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }

    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        let n_rnd_ohv_ks = 4 * 10 * n_keys; // 4 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_rnd_ohv = 16 * 10 * n_blocks; // 16 S-boxes per round, 10 rounds, 1 LUT per S-box
        if self.use_bitstring_check {
            self.gf64_triples_to_check.reserve_for_more_triples(div16_ceil(n_rnd_ohv_ks+n_rnd_ohv)*16*3);
        }else{
            self.gf2_triples_to_check.reserve_for_more_triples(10 * n_blocks + div16_ceil(n_rnd_ohv_ks));
        }
        
        self.prepare_rand_ohv(n_rnd_ohv + n_rnd_ohv_ks)?;
        

        let n_mul_ks = (4 * 10 * n_keys * 3)/2; // 4 S-boxes per round, 10 rounds, 3 mult. per S-box (but 2 GF4 elements are packed together)
        let n_mul = (16 * 10 * n_blocks * 3)/2; // 16 S-boxes per round, 10 rounds, 3 mult. per S-box (but 2 GF4 elements are packed together)
        // allocate more memory for triples
        self.gf4_triples_to_check.reserve_for_more_triples(n_mul_ks + n_mul);
        Ok(())
    }

    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        debug_assert_eq!(si.len(), sii.len());
        if self.prep_ohv.len() < si.len() {
            panic!("Not enough pre-processed random one-hot vectors available. Use WL16ASParty::prepare_rand_ohv to generate them.");
        }
        let remainning = self.prep_ohv.len() - si.len();
        if self.inner.has_multi_threading() && self.inner.num_worker_threads() <= si.len() {
            online::gf8_inv_layer_mt(&mut self.inner, &mut self.gf4_triples_to_check, si, sii, &self.prep_ohv[remainning..])?
        }else{
            online::gf8_inv_layer(&mut self.inner, &mut self.gf4_triples_to_check, si, sii, &self.prep_ohv[remainning..])?
        }
        // remove used pre-processing material
        self.prep_ohv.truncate(remainning);
        self.inner.io().wait_for_completion();
        if self.check_after_sbox {
            self.verify_multiplications()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::thread::JoinHandle;

    use crate::{
        network::ConnectedParty,
        party::test::{localhost_connect, TestSetup},
    };

    use super::WL16ASParty;

    pub fn localhost_setup_wl16as<T1: Send + 'static, F1: Send + FnOnce(&mut WL16ASParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut WL16ASParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut WL16ASParty) -> T3 + 'static>(f1: F1, f2: F2, f3: F3, n_worker_threads: Option<usize>) -> (JoinHandle<(T1,WL16ASParty)>, JoinHandle<(T2,WL16ASParty)>, JoinHandle<(T3,WL16ASParty)>) {
        fn adapter<T, Fx: FnOnce(&mut WL16ASParty)->T>(conn: ConnectedParty, f: Fx, n_worker_threads: Option<usize>) -> (T,WL16ASParty) {
            let mut party = WL16ASParty::setup(conn, false, false, false, n_worker_threads).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(move |conn_party| adapter(conn_party, f1, n_worker_threads), move |conn_party| adapter(conn_party, f2, n_worker_threads), move |conn_party| adapter(conn_party, f3, n_worker_threads))
    }

    pub struct WL16ASSetup;
    impl TestSetup<WL16ASParty> for WL16ASSetup {
        fn localhost_setup<T1: Send + 'static, F1: Send + FnOnce(&mut WL16ASParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut WL16ASParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut WL16ASParty) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (std::thread::JoinHandle<(T1,WL16ASParty)>, std::thread::JoinHandle<(T2,WL16ASParty)>, std::thread::JoinHandle<(T3,WL16ASParty)>) {
            localhost_setup_wl16as(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<T1: Send + 'static, F1: Send + FnOnce(&mut WL16ASParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut WL16ASParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut WL16ASParty) -> T3 + 'static>(n_threads: usize, f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,WL16ASParty)>, JoinHandle<(T2,WL16ASParty)>, JoinHandle<(T3,WL16ASParty)>) {
            localhost_setup_wl16as(f1, f2, f3, Some(n_threads))
        }
    }
}
