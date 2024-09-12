//! This module implements the *maliciously-secure* oblivious AES protocol "WOL LUT 16".
//! 
//! The core is a sub-protocol (`Protocol 3`) to compute multiplicative inverses in `GF(2^8)`.
//! This works as follows:
//! 1) Use the WOL[^note] transform to convert the element `GF(2^8)` to `GF(2^4)^2`.
//! 2) Compute the inverse of the `GF(2^4)^2` element using a single inversion in `GF(2^4)`. To compute the `GF(2^4)` inversion a pre-processed lookup table of 16-bits is used.
//! 3) Use the reverse WOL transform to convert the result to `GF(2^8)`.
//! 
//! The main difference to the *semi-honest* WOL LUT 16 in [crate::wollut16] is that we in addition have a verification phase for multiplication triples generated during the protocol execution.
//! All openings and broadcasts are efficiently checked by hashing the (expected) transcript of the protocol and comparing the hash.
//!
//! This module notably contains
//!   - [WL16ASParty] the party wrapper for the protocol.
//!
//! [^note]: Wolkerstorfer et al. "An ASIC Implementation of the AES S-Boxes" in CT-RSA 2002, <https://doi.org/10.1007/3-540-45760-7_6>.
use crate::{
    aes::{AesVariant, GF8InvBlackBox}, share::{bs_bool16::BsBool16, gf2p64::GF2p64, gf4::BsGF4, gf8::GF8}, util::{mul_triple_vec::{BsBool16Encoder, BsGF4Encoder, GF2p64Encoder, GF4p4TripleEncoder, GF4p4TripleVector, MulTripleRecorder, MulTripleVector, Ohv16TripleEncoder, Ohv16TripleVector}, ArithmeticBlackBox}, wollut16::{self, RndOhv16Output}
};
use crate::rep3_core::{
    network::{task::IoLayerOwned, ConnectedParty}, party::{broadcast::{Broadcast, BroadcastContext}, error::{MpcError, MpcResult}, MainParty, Party}, share::RssShare
};

pub mod mult_verification;
mod offline;
pub mod online;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PrepCheckType {
    /// Checks 11 GF(2) multiplications separately
    Simple,
    /// Checks GF(2) * GF(2^k) multiplications
    BitString,
    /// Checks 11 GF(2) multiplications via 2 GF(2^l) triples
    OhvCheck,
}

/// Party for WOLLUT16 with active security
pub struct WL16ASParty{
    inner: MainParty,
    prep_ohv: Vec<RndOhv16Output>,
    check_after_prep: bool,
    check_after_sbox: bool,
    prep_check: PrepCheckType,
    use_gf4p4_check: bool, // whether to use the trick to check 3 multiplications at once during the online phase
    // Multiplication triples that need checking at the end
    gf4_triples_to_check: MulTripleVector<BsGF4>,
    gf2_triples_to_check: MulTripleVector<BsBool16>,  // used in PrepCheckType::Simple
    gf64_triples_to_check: MulTripleVector<GF2p64>, // used in PrepCheckType::BitString
    gf4p4_triples_to_check: GF4p4TripleVector,
    ohv_triples_to_check: Ohv16TripleVector, // used in PrepCheckType::OhvCheck
    broadcast_context: BroadcastContext,
}

impl WL16ASParty {
    pub fn setup(connected: ConnectedParty, check_after_prep: bool, check_after_sbox: bool, prep_check: PrepCheckType, use_gf4p4_check: bool, n_worker_threads: Option<usize>, prot_str: Option<String>) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads, prot_str).map(|party| Self {
            inner: party,
            prep_ohv: Vec::new(),
            check_after_prep,
            check_after_sbox,
            prep_check,
            use_gf4p4_check,
            gf4_triples_to_check: MulTripleVector::new(),
            gf2_triples_to_check: MulTripleVector::new(),
            gf64_triples_to_check: MulTripleVector::new(),
            gf4p4_triples_to_check: GF4p4TripleVector::new(),
            ohv_triples_to_check: Ohv16TripleVector::new(),
            broadcast_context: BroadcastContext::new(),
        })
    }

    fn prepare_rand_ohv(&mut self, n: usize) -> MpcResult<()> {
        let mut new = if self.inner.has_multi_threading() && self.inner.num_worker_threads() <= n {
            match &self.prep_check {
                PrepCheckType::Simple => offline::generate_random_ohv16_mt(self, n, false)?,
                PrepCheckType::BitString => offline::generate_random_ohv16_mt(self, n, true)?,
                PrepCheckType::OhvCheck => wollut16::offline::generate_ohv16_opt_check_mt(&mut self.inner, &mut self.ohv_triples_to_check, n)?,
            }
        }else{
            match &self.prep_check {
                PrepCheckType::Simple => offline::generate_random_ohv16(self, n, false)?,
                PrepCheckType::BitString => offline::generate_random_ohv16(self, n, true)?,
                PrepCheckType::OhvCheck => wollut16::offline::generate_ohv16_opt_check(&mut self.inner, &mut self.ohv_triples_to_check, n)?,
            }
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
        // let t = Instant::now();
        let res = if self.inner.has_multi_threading() {
            mult_verification::verify_multiplication_triples_mt(&mut self.inner, &mut self.broadcast_context, &mut [&mut BsGF4Encoder(&mut self.gf4_triples_to_check), &mut BsBool16Encoder(&mut self.gf2_triples_to_check), &mut GF2p64Encoder(&mut self.gf64_triples_to_check), &mut Ohv16TripleEncoder(&mut self.ohv_triples_to_check), &mut GF4p4TripleEncoder(&mut self.gf4p4_triples_to_check)], false)
        }else{
            mult_verification::verify_multiplication_triples(&mut self.inner, &mut self.broadcast_context, &mut [&mut BsGF4Encoder(&mut self.gf4_triples_to_check), &mut BsBool16Encoder(&mut self.gf2_triples_to_check), &mut GF2p64Encoder(&mut self.gf64_triples_to_check), &mut Ohv16TripleEncoder(&mut self.ohv_triples_to_check), &mut GF4p4TripleEncoder(&mut self.gf4p4_triples_to_check)], false)
        };
        match res {
            Ok(true) => {
                // println!("verify_multiplications: {}s", t.elapsed().as_secs_f64());
                Ok(())
            },
            Ok(false) => Err(MpcError::MultCheck),
            Err(err) => Err(err)
        }
    }
}

impl ArithmeticBlackBox<GF8> for WL16ASParty {

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

    fn output_to(&mut self, to_p1: &[RssShare<GF8>], to_p2: &[RssShare<GF8>], to_p3: &[RssShare<GF8>]) -> MpcResult<Vec<GF8>> {
        let output = self.inner.open_rss_to_multiple(&mut self.broadcast_context, to_p1, to_p2, to_p3)?;
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

    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize, variant: AesVariant) -> MpcResult<()> {
        let n_rnd_ohv_ks = variant.n_ks_sboxes() * n_keys; // 1 LUT per S-box
        let n_rnd_ohv = 16 * variant.n_rounds() * n_blocks; // 16 S-boxes per round, X rounds, 1 LUT per S-box
        match &self.prep_check {
            PrepCheckType::Simple => self.gf2_triples_to_check.reserve_for_more_triples(10 * n_blocks + div16_ceil(n_rnd_ohv_ks)),
            PrepCheckType::BitString => self.gf64_triples_to_check.reserve_for_more_triples(div16_ceil(n_rnd_ohv_ks+n_rnd_ohv)*16*3),
            PrepCheckType::OhvCheck => self.ohv_triples_to_check.reserve_for_more_triples(div16_ceil(n_rnd_ohv + n_rnd_ohv_ks)),
        }
        
        self.prepare_rand_ohv(n_rnd_ohv + n_rnd_ohv_ks)?;
        

        if self.use_gf4p4_check {
            let n_mul_ks = (4 * 10 * n_keys)/2; // 4 S-boxes per round, 10 rounds, 1 mult. per S-box (but 2 GF4 elements are packed together)
            let n_mul = (16 * 10 * n_blocks)/2; // 16 S-boxes per round, 10 rounds, 1 mult. per S-box (but 2 GF4 elements are packed together)
            // allocate more memory for triples
            self.gf4p4_triples_to_check.reserve_for_more_triples(n_mul_ks + n_mul);
        }else{
            let n_mul_ks = (4 * 10 * n_keys * 3)/2; // 4 S-boxes per round, 10 rounds, 3 mult. per S-box (but 2 GF4 elements are packed together)
            let n_mul = (16 * 10 * n_blocks * 3)/2; // 16 S-boxes per round, 10 rounds, 3 mult. per S-box (but 2 GF4 elements are packed together)
            // allocate more memory for triples
            self.gf4_triples_to_check.reserve_for_more_triples(n_mul_ks + n_mul);
        }
        Ok(())
    }

    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        debug_assert_eq!(si.len(), sii.len());
        if self.prep_ohv.len() < si.len() {
            panic!("Not enough pre-processed random one-hot vectors available. Use WL16ASParty::prepare_rand_ohv to generate them.");
        }
        let remainning = self.prep_ohv.len() - si.len();
        if self.inner.has_multi_threading() && self.inner.num_worker_threads() <= si.len() {
            if self.use_gf4p4_check {
                online::gf8_inv_layer_gf4p4_check_mt(&mut self.inner, &mut self.gf4p4_triples_to_check, si, sii, &self.prep_ohv[remainning..])?    
            }else{
                online::gf8_inv_layer_mt(&mut self.inner, &mut self.gf4_triples_to_check, si, sii, &self.prep_ohv[remainning..])?
            }
        }else{
            if self.use_gf4p4_check {
                online::gf8_inv_layer_gf4p4_check(&mut self.inner, &mut self.gf4p4_triples_to_check, si, sii, &self.prep_ohv[remainning..])?
            }else{
                online::gf8_inv_layer(&mut self.inner, &mut self.gf4_triples_to_check, si, sii, &self.prep_ohv[remainning..])?
            }            
        }
        // remove used pre-processing material
        self.prep_ohv.truncate(remainning);
        self.inner.io().wait_for_completion();
        if self.check_after_sbox {
            self.verify_multiplications()?;
        }
        Ok(())
    }

    fn main_party_mut(&mut self) -> &mut MainParty {
        &mut self.inner
    }
}

#[cfg(test)]
mod test {
    use std::marker::PhantomData;

    use crate::rep3_core::{
        network::ConnectedParty,
        test::{localhost_connect, TestSetup},
    };

    use super::{PrepCheckType, WL16ASParty};

    pub trait WL16Params {
        const CHECK_AFTER_PREP: bool;
        const CHECK_AFTER_SBOX: bool;
        const PREP_CHECK: PrepCheckType;
        const GF4P4_CHECK: bool;
    }

    pub struct WL16DefaultParams;
    impl WL16Params for WL16DefaultParams {
        const CHECK_AFTER_PREP: bool = false;
        const CHECK_AFTER_SBOX: bool = false;
        const PREP_CHECK: PrepCheckType = PrepCheckType::Simple;
        const GF4P4_CHECK: bool = false;
    }

    pub struct WL16BitString;
    impl WL16Params for WL16BitString {
        const CHECK_AFTER_PREP: bool = false;
        const CHECK_AFTER_SBOX: bool = false;
        const PREP_CHECK: PrepCheckType = PrepCheckType::BitString;
        const GF4P4_CHECK: bool = true;
    }

    pub struct WL16OhvCheck;
    impl WL16Params for WL16OhvCheck {
        const CHECK_AFTER_PREP: bool = false;
        const CHECK_AFTER_SBOX: bool = false;
        const PREP_CHECK: PrepCheckType = PrepCheckType::OhvCheck;
        const GF4P4_CHECK: bool = true;
    }

    pub fn localhost_setup_wl16as<P: WL16Params, T1: Send, F1: Send + FnOnce(&mut WL16ASParty) -> T1, T2: Send, F2: Send + FnOnce(&mut WL16ASParty) -> T2, T3: Send, F3: Send + FnOnce(&mut WL16ASParty) -> T3>(f1: F1, f2: F2, f3: F3, n_worker_threads: Option<usize>) -> ((T1,WL16ASParty), (T2,WL16ASParty), (T3,WL16ASParty)) {
        fn adapter<P: WL16Params, T, Fx: FnOnce(&mut WL16ASParty)->T>(conn: ConnectedParty, f: Fx, n_worker_threads: Option<usize>) -> (T,WL16ASParty) {
            let mut party = WL16ASParty::setup(conn, P::CHECK_AFTER_PREP, P::CHECK_AFTER_SBOX, P::PREP_CHECK, P::GF4P4_CHECK, n_worker_threads, None).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(move |conn_party| adapter::<P,_,_>(conn_party, f1, n_worker_threads), move |conn_party| adapter::<P,_,_>(conn_party, f2, n_worker_threads), move |conn_party| adapter::<P,_,_>(conn_party, f3, n_worker_threads))
    }

    pub struct WL16ASSetup<Params: WL16Params>(PhantomData<Params>);
    impl<Params: WL16Params> TestSetup<WL16ASParty> for WL16ASSetup<Params> {
        fn localhost_setup<T1: Send, F1: Send + FnOnce(&mut WL16ASParty) -> T1, T2: Send, F2: Send + FnOnce(&mut WL16ASParty) -> T2, T3: Send, F3: Send + FnOnce(&mut WL16ASParty) -> T3>(f1: F1, f2: F2, f3: F3) -> ((T1,WL16ASParty), (T2,WL16ASParty), (T3,WL16ASParty)) {
            localhost_setup_wl16as::<Params, _, _, _, _, _, _>(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<T1: Send, F1: Send + FnOnce(&mut WL16ASParty) -> T1, T2: Send, F2: Send + FnOnce(&mut WL16ASParty) -> T2, T3: Send, F3: Send + FnOnce(&mut WL16ASParty) -> T3>(n_threads: usize, f1: F1, f2: F2, f3: F3) -> ((T1,WL16ASParty), (T2,WL16ASParty), (T3,WL16ASParty)) {
            localhost_setup_wl16as::<Params, _, _, _, _, _, _>(f1, f2, f3, Some(n_threads))
        }
    }
}
