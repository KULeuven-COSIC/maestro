use std::time::Instant;

use itertools::izip;
use rand_chacha::ChaCha20Rng;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::{ParallelSlice, ParallelSliceMut},
};
use sha2::Sha256;

use crate::{
    aes::GF8InvBlackBox,
    network::task::{Direction, IoLayerOwned},
    party::{error::MpcResult, ArithmeticBlackBox, MainParty},
    share::{gf8::GF8, Field, FieldDigestExt, FieldRngExt, RssShare, RssShareVec},
};

use super::{lut256_tables, offline, LUT256Party, RndOhv256Output};

impl GF8InvBlackBox for LUT256Party {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }

    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        let n_rnd_ohv_ks = 4 * 10 * n_keys; // 4 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_rnd_ohv = 16 * 10 * n_blocks; // 16 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_prep = n_rnd_ohv + n_rnd_ohv_ks;
        let mut prep =
            if self.inner.has_multi_threading() && 2 * n_prep > self.inner.num_worker_threads() {
                offline::generate_rndohv256_mt(self.inner.as_party_mut(), n_prep)?
            } else {
                offline::generate_rndohv256(self.inner.as_party_mut(), n_prep)?
            };
        if self.prep_ohv.is_empty() {
            self.prep_ohv = prep;
        } else {
            self.prep_ohv.append(&mut prep);
        }
        Ok(())
    }

    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        debug_assert_eq!(si.len(), sii.len());
        if self.prep_ohv.len() < si.len() {
            panic!("Not enough pre-processed random one-hot vectors available. Use LUT256Party::prepare_rand_ohv to generate them.");
        }
        let rnd_ohv = &self.prep_ohv[self.prep_ohv.len() - si.len()..];
        let rcv_ciii = self.io().receive_field(Direction::Previous, si.len());
        si.iter_mut()
            .zip(rnd_ohv)
            .for_each(|(v, r)| *v += r.random_si);
        self.io()
            .send_field::<GF8>(Direction::Next, si.iter(), si.len());
        izip!(si.iter_mut(), sii.iter(), rnd_ohv).for_each(|(c, sii, r)| *c += *sii + r.random_sii);

        let ciii = rcv_ciii.rcv()?;
        let now = Instant::now();

        if self.inner.has_multi_threading() && 2 * si.len() > self.inner.num_worker_threads() {
            lut256_mt(self.inner.as_party_mut(), si, sii, ciii, rnd_ohv)?;
        } else {
            lut256(si, sii, &ciii, rnd_ohv);
        }

        let time = now.elapsed();
        self.lut_time += time;
        // remove used pre-processing material
        self.prep_ohv.truncate(self.prep_ohv.len() - si.len());
        self.io().wait_for_completion();
        Ok(())
    }
}

fn lut256_mt(
    party: &mut MainParty,
    si: &mut [GF8],
    sii: &mut [GF8],
    ciii: Vec<GF8>,
    rnd_ohv: &[RndOhv256Output],
) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());
    debug_assert_eq!(si.len(), ciii.len());
    debug_assert_eq!(si.len(), rnd_ohv.len());
    let ranges = party.split_range_equally(si.len());
    let chunk_size = ranges[0].1 - ranges[0].0;

    party.run_in_threadpool(|| {
        si.par_chunks_mut(chunk_size)
            .zip_eq(sii.par_chunks_mut(chunk_size))
            .zip_eq(ciii.par_chunks(chunk_size))
            .zip_eq(rnd_ohv.par_chunks(chunk_size))
            .for_each(|(((si, sii), ciii), rnd_ohv)| {
                lut256(si, sii, ciii, rnd_ohv);
            });
        Ok(())
    })
}

#[inline]
fn lut256(si: &mut [GF8], sii: &mut [GF8], ciii: &[GF8], rnd_ohv: &[RndOhv256Output]) {
    izip!(si.iter_mut(), sii.iter_mut(), ciii, rnd_ohv).for_each(|(si, sii, ciii, ohv)| {
        let c = (*si + *ciii).0 as usize;
        *si = ohv.si.lut(c, &lut256_tables::GF8_INV_BITSLICED_LUT);
        *sii = ohv.sii.lut(c, &lut256_tables::GF8_INV_BITSLICED_LUT);
    });
}

impl<F: Field> ArithmeticBlackBox<F> for LUT256Party
where
    ChaCha20Rng: FieldRngExt<F>,
    Sha256: FieldDigestExt<F>,
{
    type Rng = ChaCha20Rng;
    type Digest = Sha256;

    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        self.inner.pre_processing(n_multiplications)
    }

    fn io(&self) -> &IoLayerOwned {
        self.inner.io()
    }

    fn constant(&self, value: F) -> RssShare<F> {
        self.inner.constant(value)
    }

    fn generate_random(&mut self, n: usize) -> RssShareVec<F> {
        self.inner.generate_random(n)
    }

    fn generate_alpha(&mut self, n: usize) -> Vec<F> {
        self.inner.generate_alpha(n)
    }

    // all parties input the same number of inputs
    fn input_round(
        &mut self,
        my_input: &[F],
    ) -> MpcResult<(RssShareVec<F>, RssShareVec<F>, RssShareVec<F>)> {
        self.inner.input_round(my_input)
    }

    fn mul(
        &mut self,
        ci: &mut [F],
        cii: &mut [F],
        ai: &[F],
        aii: &[F],
        bi: &[F],
        bii: &[F],
    ) -> MpcResult<()> {
        self.inner.mul(ci, cii, ai, aii, bi, bii)
    }

    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        self.inner.output_round(si, sii)
    }

    fn output_to(&mut self, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>> {
        self.inner.output_to(to_p1, to_p2, to_p3)
    }

    fn finalize(&mut self) -> MpcResult<()> {
        self.inner.finalize()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        aes::{
            self,
            test::{
                test_aes128_keyschedule_gf8, test_aes128_no_keyschedule_gf8,
                test_inv_aes128_no_keyschedule_gf8, test_sub_bytes,
            },
        },
        lut256::test::LUT256Setup,
    };

    #[test]
    fn sub_bytes() {
        test_sub_bytes::<LUT256Setup, _>(None)
    }

    #[test]
    fn sub_bytes_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<LUT256Setup, _>(Some(N_THREADS))
    }

    #[test]
    fn aes128_keyschedule_lut256() {
        test_aes128_keyschedule_gf8::<LUT256Setup, _>(None)
    }

    #[test]
    fn aes_128_no_keyschedule_lut256() {
        test_aes128_no_keyschedule_gf8::<LUT256Setup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_lut256_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<LUT256Setup, _>(100, Some(N_THREADS))
    }

    #[test]
    fn inv_aes128_no_keyschedule_lut256() {
        test_inv_aes128_no_keyschedule_gf8::<LUT256Setup, _>(1, None)
    }

    #[test]
    fn inv_aes128_no_keyschedule_lut2566_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<LUT256Setup, _>(100, Some(N_THREADS))
    }

    #[test]
    fn create_table() {
        fn set_bit(vec: &mut [u64; 4], index: usize, b: u8) {
            let b = b as u64;
            if index < 64 {
                vec[0] |= (b & 0x1) << index;
            } else if index < 128 {
                vec[1] |= (b & 0x1) << (index - 64);
            } else if index < 192 {
                vec[2] |= (b & 0x1) << (index - 128);
            } else {
                vec[3] |= (b & 0x1) << (index - 192);
            }
        }

        let mut table = [[[0u64; 4]; 8]; 256];
        for offset in 0..256 {
            for j in 0..8 {
                let mut entry = [0u64; 4];
                for i in 0..256 {
                    let b = (aes::INV_GF8[offset ^ i] >> j) & 0x1;
                    set_bit(&mut entry, i, b);
                    if offset == 0 && j == 0 && i == 1 {
                        println!("b = {}; lookup={}", b, aes::INV_GF8[(offset ^ i) as usize]);
                        println!("entry = {:?}", entry);
                    }
                }
                table[offset as usize][j] = entry;
            }
        }

        println!("const GF8_BITSLICED_LUT: [[[u64; 4]; 8]; 256] = [");
        for i in 0..256 {
            println!("\t{:?},", table[i]);
        }
        println!("];");
    }
}
