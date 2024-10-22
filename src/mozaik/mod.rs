use std::mem;

use itertools::Itertools;

use crate::{aes::{AesVariant, GF8InvBlackBox}, chida, conversion::Z64Bool, furukawa::{InputPhase, OutputPhase}, gcm::gf128::{GF128TripleEncoder, GF128}, gf4_circuit::GF4CircuitSemihonestParty, gf4_circuit_malsec::{gf8_inv_via_gf4_mul_gf4p4_check_mt, gf8_inv_via_gf4_mul_gf4p4_check_no_sync}, rep3_core::{network::{task::IoLayerOwned, ConnectedParty}, party::{broadcast::{Broadcast, BroadcastContext}, error::{MpcError, MpcResult}, MainParty, Party}, share::{HasZero, RssShare, RssShareVec}}, share::{bs_bool16::BsBool16, gf4::BsGF4, gf8::GF8, Field}, util::{mul_triple_vec::{BsBool16Encoder, BsGF4Encoder, GF2p64SubfieldEncoder, GF4p4TripleEncoder, GF4p4TripleVector, MulTripleRecorder, MulTripleVector}, ArithmeticBlackBox}, wollut16_malsec};

/// Semi-honest security
pub struct MozaikParty(GF4CircuitSemihonestParty);

/// Malicious/Active security
pub struct MozaikAsParty {
    inner: MainParty,
    broadcast_context: BroadcastContext,
    gf2_triples_to_check: MulTripleVector<BsBool16>,
    gf8_triples_to_check: MulTripleVector<GF8>,
    gf128_triples_to_check: MulTripleVector<GF128>,
    gf4p4_triples_to_check: GF4p4TripleVector,
    gf4_triples_to_check: MulTripleVector<BsGF4>,
}

impl MozaikParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, prot_string: Option<String>) -> MpcResult<Self> {
        GF4CircuitSemihonestParty::setup(connected, n_worker_threads, prot_string).map(|party| Self(party))
    }
}

impl MozaikAsParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, prot_string: Option<String>) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads, prot_string)
            .map(|party| Self {
                inner: party,
                broadcast_context: BroadcastContext::new(),
                gf2_triples_to_check: MulTripleVector::new(),
                gf8_triples_to_check: MulTripleVector::new(),
                gf128_triples_to_check: MulTripleVector::new(),
                gf4p4_triples_to_check: GF4p4TripleVector::new(),
                gf4_triples_to_check: MulTripleVector::new(),
            })
    }

    fn check_multiplications_and_broadcast(&mut self) -> MpcResult<()> {
        let n_triples = self.gf2_triples_to_check.len();
        if n_triples > 0 {
            let res = if self.inner.has_multi_threading() {
                wollut16_malsec::mult_verification::verify_multiplication_triples_mt(&mut self.inner, &mut self.broadcast_context, &mut [
                    &mut BsBool16Encoder(&mut self.gf2_triples_to_check), 
                    &mut GF2p64SubfieldEncoder(&mut self.gf8_triples_to_check), 
                    &mut GF4p4TripleEncoder(&mut self.gf4p4_triples_to_check), 
                    &mut BsGF4Encoder(&mut self.gf4_triples_to_check),
                    &mut GF128TripleEncoder(&mut self.gf128_triples_to_check),
                ], false)
            }else{
                wollut16_malsec::mult_verification::verify_multiplication_triples(&mut self.inner, &mut self.broadcast_context, &mut [
                    &mut BsBool16Encoder(&mut self.gf2_triples_to_check), 
                    &mut GF2p64SubfieldEncoder(&mut self.gf8_triples_to_check), 
                    &mut GF4p4TripleEncoder(&mut self.gf4p4_triples_to_check), 
                    &mut BsGF4Encoder(&mut self.gf4_triples_to_check),
                    &mut GF128TripleEncoder(&mut self.gf128_triples_to_check),
                ], false)
            };
            match res {
                Ok(true) => (),
                Ok(false) => return Err(MpcError::MultCheck),
                Err(err) => return Err(err),
            }
        }
        // check broadcasts
        let context = mem::take(&mut self.broadcast_context);
        self.inner.compare_view(context)
    }
}

impl<F: Field> ArithmeticBlackBox<F> for MozaikParty {
    fn constant(&self, value: F) -> RssShare<F> {
        ArithmeticBlackBox::<F>::constant(&self.0, value)
    }
    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=F> {
        self.0.generate_alpha(n)
    }
    fn generate_random(&mut self, n: usize) -> RssShareVec<F> {
        self.0.generate_random(n)
    }
    fn io(&self) -> &IoLayerOwned {
        ArithmeticBlackBox::<F>::io(&self.0)
    }
    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        ArithmeticBlackBox::<F>::pre_processing(&mut self.0, n_multiplications)
    }
    fn input_round(&mut self, my_input: &[F]) -> MpcResult<(RssShareVec<F>, RssShareVec<F>, RssShareVec<F>)> {
        ArithmeticBlackBox::<F>::input_round(&mut self.0, my_input)
    }
    fn mul(&mut self, ci: &mut [F], cii: &mut [F], ai: &[F], aii: &[F], bi: &[F], bii: &[F]) -> MpcResult<()> {
        self.0.mul(ci, cii, ai, aii, bi, bii)
    }
    fn finalize(&mut self) -> MpcResult<()> {
        ArithmeticBlackBox::<F>::finalize(&mut self.0)
    }
    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        self.0.output_round(si, sii)
    }
    fn output_to(&mut self, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>> {
        self.0.output_to(to_p1, to_p2, to_p3)
    }
}

impl GF8InvBlackBox for MozaikParty {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        GF8InvBlackBox::constant(&self.0, value)
    }
    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize, variant: AesVariant) -> MpcResult<()> {
        self.0.do_preprocessing(n_keys, n_blocks, variant)
    }
    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        self.0.gf8_inv(si, sii)
    }
    fn main_party_mut(&mut self) -> &mut MainParty {
        self.0.main_party_mut()
    }
}

fn z64bool_to_bs16(src: &[Z64Bool]) -> Vec<BsBool16> {
    let mut v = vec![BsBool16::ZERO; src.len() * 4];
    v.chunks_exact_mut(4).zip_eq(src).for_each(|(dst, src)| {
        dst[0] = BsBool16::new((src.0 & 0xffff) as u16);
        dst[1] = BsBool16::new(((src.0 >> 16) & 0xffff) as u16);
        dst[2] = BsBool16::new(((src.0 >> 32) & 0xffff) as u16);
        dst[3] = BsBool16::new(((src.0 >> 48) & 0xffff) as u16);
    });
    v
}

impl ArithmeticBlackBox<Z64Bool> for MozaikAsParty {
    fn constant(&self, value: Z64Bool) -> RssShare<Z64Bool> {
        self.inner.constant(value)
    }
    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=Z64Bool> {
        self.inner.generate_alpha(n)
    }
    fn generate_random(&mut self, n: usize) -> RssShareVec<Z64Bool> {
        self.inner.generate_random(n)
    }
    fn io(&self) -> &IoLayerOwned {
        self.inner.io()
    }
    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        // we don't need preprocessing for multiplications
        // just reserve space for the triples
        // we unpack 64-bit into 4x16
        self.gf2_triples_to_check.reserve_for_more_triples(n_multiplications * 4);
        Ok(())
    }
    fn input_round(&mut self, my_input: &[Z64Bool]) -> MpcResult<(RssShareVec<Z64Bool>, RssShareVec<Z64Bool>, RssShareVec<Z64Bool>)> {
        let mut inf = InputPhase::new(&mut self.inner);
        let out = inf.input_round(my_input)?;
        inf.end_input_phase()?;
        Ok(out)
    }
    fn mul(&mut self, ci: &mut [Z64Bool], cii: &mut [Z64Bool], ai: &[Z64Bool], aii: &[Z64Bool], bi: &[Z64Bool], bii: &[Z64Bool]) -> MpcResult<()> {
        chida::online::mul_no_sync(&mut self.inner, ci, cii, ai, aii, bi, bii)?;
        // note down triples
        let gf2_ci = z64bool_to_bs16(ci);
        let gf2_cii = z64bool_to_bs16(cii);
        let gf2_ai = z64bool_to_bs16(ai);
        let gf2_aii = z64bool_to_bs16(aii);
        let gf2_bi = z64bool_to_bs16(bi);
        let gf2_bii = z64bool_to_bs16(bii);
        self.gf2_triples_to_check.record_mul_triple(&gf2_ai, &gf2_aii, &gf2_bi, &gf2_bii, &gf2_ci, &gf2_cii);
        self.inner.io().wait_for_completion();
        Ok(())
    }
    fn finalize(&mut self) -> MpcResult<()> {
        self.check_multiplications_and_broadcast()
    }
    fn output_round(&mut self, _si: &[Z64Bool], _sii: &[Z64Bool]) -> MpcResult<Vec<Z64Bool>> {
        unimplemented!()
    }
    fn output_to(&mut self, to_p1: &[RssShare<Z64Bool>], to_p2: &[RssShare<Z64Bool>], to_p3: &[RssShare<Z64Bool>]) -> MpcResult<Vec<Z64Bool>> {
        self.check_multiplications_and_broadcast()?;
        let mut of = OutputPhase::new(&mut self.inner);
        let res = of.output_to_multiple(to_p1, to_p2, to_p3)?;
        of.end_output_phase()?;
        Ok(res)
    }
}

impl ArithmeticBlackBox<GF8> for MozaikAsParty {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }
    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=GF8> {
        self.inner.generate_alpha(n)
    }
    fn generate_random(&mut self, n: usize) -> RssShareVec<GF8> {
        self.inner.generate_random(n)
    }
    fn io(&self) -> &IoLayerOwned {
        self.inner.io()
    }
    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        // we don't need preprocessing for multiplications
        // just reserve space for the triples
        self.gf8_triples_to_check.reserve_for_more_triples(n_multiplications);
        Ok(())
    }
    fn input_round(&mut self, my_input: &[GF8]) -> MpcResult<(RssShareVec<GF8>, RssShareVec<GF8>, RssShareVec<GF8>)> {
        let mut inf = InputPhase::new(&mut self.inner);
        let out = inf.input_round(my_input)?;
        inf.end_input_phase()?;
        Ok(out)
    }
    fn mul(&mut self, ci: &mut [GF8], cii: &mut [GF8], ai: &[GF8], aii: &[GF8], bi: &[GF8], bii: &[GF8]) -> MpcResult<()> {
        chida::online::mul_no_sync(&mut self.inner, ci, cii, ai, aii, bi, bii)?;
        // note down triples
        self.gf8_triples_to_check.record_mul_triple(ai, aii, bi, bii, ci, cii);
        self.inner.io().wait_for_completion();
        Ok(())
    }
    fn finalize(&mut self) -> MpcResult<()> {
        self.check_multiplications_and_broadcast()
    }
    fn output_round(&mut self, _si: &[GF8], _sii: &[GF8]) -> MpcResult<Vec<GF8>> {
        unimplemented!()
    }
    fn output_to(&mut self, to_p1: &[RssShare<GF8>], to_p2: &[RssShare<GF8>], to_p3: &[RssShare<GF8>]) -> MpcResult<Vec<GF8>> {
        self.check_multiplications_and_broadcast()?;
        let mut of = OutputPhase::new(&mut self.inner);
        let res = of.output_to_multiple(to_p1, to_p2, to_p3)?;
        of.end_output_phase()?;
        Ok(res)
    }
}

impl ArithmeticBlackBox<GF128> for MozaikAsParty {
    fn constant(&self, value: GF128) -> RssShare<GF128> {
        self.inner.constant(value)
    }
    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=GF128> {
        self.inner.generate_alpha(n)
    }
    fn generate_random(&mut self, n: usize) -> RssShareVec<GF128> {
        self.inner.generate_random(n)
    }
    fn io(&self) -> &IoLayerOwned {
        self.inner.io()
    }
    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        // we don't need preprocessing for multiplications
        // just reserve space for the triples
        self.gf128_triples_to_check.reserve_for_more_triples(n_multiplications);
        Ok(())
    }
    fn input_round(&mut self, my_input: &[GF128]) -> MpcResult<(RssShareVec<GF128>, RssShareVec<GF128>, RssShareVec<GF128>)> {
        let mut inf = InputPhase::new(&mut self.inner);
        let out = inf.input_round(my_input)?;
        inf.end_input_phase()?;
        Ok(out)
    }
    fn mul(&mut self, ci: &mut [GF128], cii: &mut [GF128], ai: &[GF128], aii: &[GF128], bi: &[GF128], bii: &[GF128]) -> MpcResult<()> {
        chida::online::mul_no_sync(&mut self.inner, ci, cii, ai, aii, bi, bii)?;
        // note down triples
        self.gf128_triples_to_check.record_mul_triple(ai, aii, bi, bii, ci, cii);
        self.inner.io().wait_for_completion();
        Ok(())
    }
    fn finalize(&mut self) -> MpcResult<()> {
        self.check_multiplications_and_broadcast()
    }
    fn output_round(&mut self, si: &[GF128], sii: &[GF128]) -> MpcResult<Vec<GF128>> {
        self.check_multiplications_and_broadcast()?;
        let mut of = OutputPhase::new(&mut self.inner);
        let res = of.output(si, sii)?;
        of.end_output_phase()?;
        Ok(res)
    }
    fn output_to(&mut self, _to_p1: &[RssShare<GF128>], _to_p2: &[RssShare<GF128>], _to_p3: &[RssShare<GF128>]) -> MpcResult<Vec<GF128>> {
        unimplemented!()
    }
}

impl GF8InvBlackBox for MozaikAsParty {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }
    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize, variant: AesVariant) -> MpcResult<()> {
        let n_mul_ks_gf4 = variant.n_ks_sboxes() * n_keys; // 2 mult. per S-box (but 2 GF4 elements are packed together)
        let n_mul_gf4 = (16 * variant.n_rounds() * n_blocks * 2)/2; // 16 S-boxes per round, X rounds, 2 mult. per S-box (but 2 GF4 elements are packed together)
        let n_mul_ks_gf4p4 = variant.n_ks_sboxes() * n_keys; // 1 triple per S-box (but 2 GF4 elements are packed together)
        let n_mul_gf4p4 = 16 * variant.n_rounds() * n_blocks; // 16 S-boxes per round, X rounds, 1 triple per S-box (but 2 GF4 elements are packed together)
        self.gf4_triples_to_check.reserve_for_more_triples(n_mul_gf4 + n_mul_ks_gf4);
        self.gf4p4_triples_to_check.reserve_for_more_triples(n_mul_gf4p4 + n_mul_ks_gf4p4);
        Ok(())
    }
    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        if self.inner.has_multi_threading() && si.len() >= 2 * self.inner.num_worker_threads() {
            gf8_inv_via_gf4_mul_gf4p4_check_mt(&mut self.inner, &mut self.gf4_triples_to_check, &mut self.gf4p4_triples_to_check, si, sii)?
        } else {
            gf8_inv_via_gf4_mul_gf4p4_check_no_sync(&mut self.inner, &mut self.gf4_triples_to_check, &mut self.gf4p4_triples_to_check, si, sii)?;
            self.inner.wait_for_completion();
        }
        Ok(())
    }
    fn main_party_mut(&mut self) -> &mut MainParty {
        &mut self.inner
    }
}