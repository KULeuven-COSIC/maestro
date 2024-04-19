use std::time::Instant;

use itertools::izip;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::{aes::{self, GF8InvBlackBox}, network::task::{Direction, IoLayer}, party::{error::MpcResult, ArithmeticBlackBox}, share::{gf8::GF8, Field, FieldDigestExt, FieldRngExt, RssShare}};

use super::{offline, LUT256Party};


impl GF8InvBlackBox for LUT256Party {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }

    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        let n_rnd_ohv_ks = 4*10 * n_keys; // 4 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_rnd_ohv = 16*10 * n_blocks; // 16 S-boxes per round, 10 rounds, 1 LUT per S-box
        let mut prep = offline::generate_rndohv256(&mut self.inner, n_rnd_ohv + n_rnd_ohv_ks)?;
        if self.prep_ohv.is_empty() {
            self.prep_ohv = prep;
        }else{
            self.prep_ohv.append(&mut prep);
        }
        Ok(())
    }

    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        debug_assert_eq!(si.len(), sii.len());
        if self.prep_ohv.len() < si.len() {
            panic!("Not enough pre-processed random one-hot vectors available. Use LUT256Party::prepare_rand_ohv to generate them.");
        }
        let rnd_ohv = &self.prep_ohv[self.prep_ohv.len()-si.len()..];
        let rcv_ciii = self.io().receive_field(Direction::Previous, si.len());
        let mut c: Vec<_> = si.iter().zip(rnd_ohv).map(|(v,r)| *v + r.random_si).collect();
        self.io().send_field::<GF8>(Direction::Next, &c, si.len());
        izip!(c.iter_mut(), sii.iter(), rnd_ohv).for_each(|(c, sii, r)| *c += *sii + r.random_sii);
        
        let ciii = rcv_ciii.rcv()?;
        let now = Instant::now();
        let (inv_si, inv_sii): (Vec<_>, Vec<_>) = izip!(c, ciii, rnd_ohv).map(|(c,ciii,ohv)| {
            let c = (c+ciii).0 as usize;
            (ohv.si.lut(c, &aes::INV_GF8), ohv.sii.lut(c, &aes::INV_GF8))
        }).unzip();
        let time = now.elapsed();
        self.lut_time += time;
        // remove used pre-processing material
        self.prep_ohv.truncate(self.prep_ohv.len()-si.len());
        // write out result
        si.copy_from_slice(&inv_si);
        sii.copy_from_slice(&inv_sii);
        self.io().wait_for_completion();
        Ok(())
    }
}

impl<F: Field> ArithmeticBlackBox<F> for LUT256Party
where ChaCha20Rng: FieldRngExt<F>, Sha256: FieldDigestExt<F>
{
    type Rng = ChaCha20Rng;
    type Digest = Sha256;

    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        self.inner.pre_processing(n_multiplications)
    }

    fn io(&self) -> &IoLayer {
        self.inner.io()
    }

    fn constant(&self, value: F) -> RssShare<F> {
        self.inner.constant(value)
    }

    fn generate_random(&mut self, n: usize) -> Vec<RssShare<F>> {
        self.inner.generate_random(n)
    }

    fn generate_alpha(&mut self, n: usize) -> Vec<F> {
        self.inner.generate_alpha(n)
    }

    // all parties input the same number of inputs
    fn input_round(&mut self, my_input: &[F]) -> MpcResult<(Vec<RssShare<F>>, Vec<RssShare<F>>, Vec<RssShare<F>>)> {
        self.inner.input_round(my_input)
    }

    fn mul(&mut self, ci: &mut [F], cii: &mut [F], ai: &[F], aii: &[F], bi: &[F], bii: &[F]) -> MpcResult<()> {
        self.inner.mul(ci, cii, ai, aii, bi, bii)
    }

    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        self.inner.output_round(si, sii)
    }

    fn finalize(&mut self) -> MpcResult<()> {
        self.inner.finalize()
    }
}

#[cfg(test)]
mod test {
    use crate::{aes::test::{test_aes128_keyschedule_gf8, test_aes128_no_keyschedule_gf8, test_inv_aes128_no_keyschedule_gf8, test_sub_bytes}, lut256::test::LUT256Setup};

    #[test]
    fn sub_bytes() {
        test_sub_bytes::<LUT256Setup,_>()
    }

    #[test]
    fn aes128_keyschedule_lut16() {
        test_aes128_keyschedule_gf8::<LUT256Setup, _>()
    }

    #[test]
    fn aes_128_no_keyschedule_lut16() {
        test_aes128_no_keyschedule_gf8::<LUT256Setup, _>()
    }

    #[test]
    fn inv_aes128_no_keyschedule_lut16() {
        test_inv_aes128_no_keyschedule_gf8::<LUT256Setup, _>()
    }
}