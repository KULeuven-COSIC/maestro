//! This module contains the online phase components.
//!

use itertools::{izip, Itertools};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use crate::{
    aes::GF8InvBlackBox, network::task::{Direction, IoLayer}, party::{error::MpcResult, ArithmeticBlackBox}, share::{gf4::{BsGF4, GF4}, gf8::GF8, wol::{wol_inv_map, wol_map}, Field, FieldDigestExt, FieldRngExt, RssShare}
};

#[cfg(feature = "verbose-timing")]
use {std::time::Instant, crate::party::PARTY_TIMER};

use super::{RndOhv16, RndOhvOutput, WL16Party};


/// Computes `<<x * y>>` for `[[x]]` and `[[y]]` over GF4.
/// 
/// This function assumes that all input vectors are of the same length
#[inline]
fn local_multiplication(x_i: &[GF4], x_ii: &[GF4], y_i: &[GF4], y_ii: &[GF4]) -> Vec<GF4> {
    izip!(x_i,x_ii,y_i,y_ii).map(|(&x_i,&x_ii,&y_i,&y_ii)| {
        x_i * y_i + (x_i + x_ii) * (y_i + y_ii) 
    }).collect_vec()
}

/// Computes <<v>> for
/// 
/// This function assumes that all input vectors are of the same length
#[inline]
fn compute_v(ah_i_sq: &[GF4], al_i_sq: &[GF4], ah_mul_al: &[GF4]) -> Vec<GF4> {
    izip!(ah_i_sq,al_i_sq,ah_mul_al).map(|(&ah_i_sq,&al_i_sq,&ah_mul_al)| {
        ah_i_sq.mul_e() + ah_mul_al + al_i_sq
    }).collect_vec()  
}

const GF4_INV: [u8; 16] = [0x00, 0x01, 0x09, 0x0e, 0x0d, 0x0b, 0x07, 0x06, 0x0f, 0x02, 0x0c, 0x05, 0x0a, 0x04, 0x03, 0x08];

const GF4_BITSLICED_LUT: [[u16; 4]; 16] = [
        [18806, 21480, 11736, 38204],
        [34489, 41940, 7908, 27196],
        [5849, 23730, 34674, 26051],
        [10726, 44145, 19377, 39619],
        [37991, 13710, 53901, 22979],
        [26779, 14925, 57678, 42691],
        [24989, 50475, 30759, 22076],
        [37486, 51735, 46107, 43324],
        [30281, 59475, 55341, 15509],
        [47494, 54435, 58398, 15466],
        [55574, 45660, 29319, 50021],
        [58921, 29100, 45387, 50074],
        [26516, 36405, 36306, 50009],
        [39784, 19770, 20193, 50086],
        [40289, 11205, 10104, 15446],
        [28306, 6090, 7092, 15529],
];

/// Placeholder for the LUT protocol
pub fn LUT_layer(party: &mut WL16Party, v: &[GF4]) -> MpcResult<(Vec<GF4>,Vec<GF4>)> {
    if party.prep_ohv.len() < v.len() {
        panic!("Not enough pre-processed random one-hot vectors available. Use WL16Party::prepare_rand_ohv to generate them.");
    }
    #[cfg(feature = "verbose-timing")]
    let lut_open_time = Instant::now();

    let alphas = party.generate_alpha(v.len());

    let rnd_ohv = &party.prep_ohv[party.prep_ohv.len()-v.len()..];
    let rcv_cii = party.io().receive_field(Direction::Next, v.len());
    let rcv_ciii = party.io().receive_field(Direction::Previous, v.len());
    let ci: Vec<_> = izip!(v.iter(), rnd_ohv, alphas).map(|(v, r, alpha)| *v + r.random + alpha).collect();
    party.io().send_field::<GF4>(Direction::Next, &ci, ci.len());
    party.io().send_field::<GF4>(Direction::Previous, &ci, ci.len());
    
    let cii = rcv_cii.rcv()?;
    let ciii = rcv_ciii.rcv()?;
    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER.lock().unwrap().report_time("gf8_inv_layer_lut_open", lut_open_time.elapsed());

    #[cfg(feature = "verbose-timing")]
    let lut_local_time = Instant::now();
    let res = lut_with_rnd_ohv_bitsliced(rnd_ohv, ci, cii, ciii);
    // remove used pre-processing material
    party.prep_ohv.truncate(party.prep_ohv.len()-v.len());

    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER.lock().unwrap().report_time("gf8_inv_layer_lut_local", lut_local_time.elapsed());

    party.io().wait_for_completion();
    Ok(res)
}

#[inline]
pub fn lut_with_rnd_ohv_bitsliced(rnd_ohv: &[RndOhvOutput], ci: Vec<GF4>, cii: Vec<GF4>, ciii: Vec<GF4>) -> (Vec<GF4>, Vec<GF4>) {
    izip!(ci, cii, ciii, rnd_ohv).map(|(ci,cii,ciii,ohv)| {
        let c = (ci + cii + ciii).as_u8() as usize;
        RndOhv16::lut_rss(c, &ohv.si, &ohv.sii, &GF4_BITSLICED_LUT)
    }).unzip()
}

/// Concatenates two vectors
#[inline]
fn append(a: &[GF4], b: &[GF4]) -> Vec<GF4> {
    let mut res = vec![GF4::zero(); a.len() + b.len()];
    res[..a.len()].copy_from_slice(a);
    res[a.len()..].copy_from_slice(b);
    res
}

/// Share conversion protocol <<x>> to [[x]]
fn SS_to_RSS_layer(party: &mut WL16Party, xss_i: &[GF4], x_i: &mut [GF4], x_ii: &mut [GF4]) -> MpcResult<()> {
    debug_assert_eq!(xss_i.len(), x_i.len());
    debug_assert_eq!(xss_i.len(), x_ii.len());
    let alphas:Vec<GF4> = party.inner.generate_alpha(xss_i.len());
    //
    x_i.iter_mut().enumerate().for_each(|(j, y_i)| {
        *y_i = xss_i[j] + alphas[j]
    });
    party.io().send_field::<GF4>(Direction::Previous, x_i.iter(), x_i.len());
    party.io().receive_field_slice(Direction::Next, x_ii).rcv()?;
    party.io().wait_for_completion();
    Ok(())
}

/**
This function implements multiplicative inversion as in `Protocol 2`.

Given a (2,3)-RSS shared vector [[x]] of elements in GF(2^8),
the protocol computes the component-wise multiplicative inverse.

The function inputs are:
- `party` - the local party `P_i``
- `si` - the first component of `[[x]]_i`
- `sii` - the second component of `[[x]]_i`

The output, the share [[x^-1]]_i, is written into `(s_i,s_ii)`.
*/
fn gf8_inv_layer(party: &mut WL16Party, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
    #[cfg(feature = "verbose-timing")]
    let total = Instant::now();

    let n = si.len();
    // Step 1: WOL-conversion
    let (ah_i,al_i): (Vec<GF4>,Vec<GF4>) = si.iter().map(wol_map).unzip();
    let (ah_ii,al_ii): (Vec<GF4>,Vec<GF4>) = sii.iter().map(wol_map).unzip();
    // Steps 2: Locally generate additive sharing of a_h^2 and a_l^2
    let ah_i_sq: Vec<GF4> = ah_i.iter().map(GF4::square).collect();
    let al_i_sq: Vec<GF4> = al_i.iter().map(GF4::square).collect();
    // Step 3: Locally generate additive sharing of ah * al
    let ah_mul_al = local_multiplication(&ah_i, &ah_ii, &al_i, &al_ii);
    // Step 4: Compute additive sharing of v
    let v = compute_v(&ah_i_sq,&al_i_sq,&ah_mul_al);

    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER.lock().unwrap().report_time("gf8_inv_layer_local1", total.elapsed());
    #[cfg(feature = "verbose-timing")]
    let lut_layer_time = Instant::now();

    // Step 5: Compute replicated sharing of v inverse
    let (v_inv_i, v_inv_ii) = LUT_layer(party, &v)?;
    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER.lock().unwrap().report_time("gf8_inv_layer_lut", lut_layer_time.elapsed());
    #[cfg(feature = "verbose-timing")]
    let local2 = Instant::now();


    // Step 6: Locally compute additive sharing of a_h' and a_l'
    let ah_plus_al_i:Vec<_> = ah_i.iter().zip(al_i).map(|(&ah_i,al_i)| ah_i+al_i).collect();
    let ah_plus_al_ii:Vec<_> = ah_ii.iter().zip(al_ii).map(|(&ah_ii,al_ii)| ah_ii+al_ii).collect();
    let a_h_prime_ss = local_multiplication(&ah_i, &ah_ii,&v_inv_i, &v_inv_ii);
    let a_l_prime_ss = local_multiplication(&ah_plus_al_i, &ah_plus_al_ii,&v_inv_i, &v_inv_ii);

    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER.lock().unwrap().report_time("gf8_inv_layer_local2", local2.elapsed());
    #[cfg(feature = "verbose-timing")]
    let ss_rss_timer = Instant::now();

    // Step 7: Generate replicated sharing of a_h' and a_l'
    let mut a_h_a_l_i = vec![GF4::zero(); 2*n];
    let mut a_h_a_l_ii = vec![GF4::zero(); 2*n];
    SS_to_RSS_layer(party, &append(&a_h_prime_ss, &a_l_prime_ss), &mut a_h_a_l_i, &mut a_h_a_l_ii)?;

    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER.lock().unwrap().report_time("gf8_inv_layer_ss_to_rss", ss_rss_timer.elapsed());
    #[cfg(feature = "verbose-timing")]
    let local3 = Instant::now();

    // Step 8: WOL-back-conversion
    si.iter_mut().enumerate().for_each(|(j,s_i)|{
        *s_i = wol_inv_map(&a_h_a_l_i[j],&a_h_a_l_i[j+n])
    });
    sii.iter_mut().enumerate().for_each(|(j,s_i)|{
        *s_i = wol_inv_map(&a_h_a_l_ii[j],&a_h_a_l_ii[j+n])
    });
    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER.lock().unwrap().report_time("gf8_inv_layer_local3", local3.elapsed());

    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER.lock().unwrap().report_time("gf8_inv_layer", total.elapsed());
    Ok(())
}

pub fn wol_bitslice_gf4(x: &[GF8]) -> (Vec<BsGF4>, Vec<BsGF4>) {
    let n = if x.len() % 2 == 0 { x.len() / 2} else { x.len()/2 +1 };
    let mut xh = vec![BsGF4::zero(); n];
    let mut xl = vec![BsGF4::zero(); n];
    for i in 0..(n-1) {
        let (xh1, xl1) = wol_map(&x[2*i]);
        let (xh2, xl2) = wol_map(&x[2*i+1]);
        xh[i] = BsGF4::new(xh1, xh2);
        xl[i] = BsGF4::new(xl1, xl2);
    }
    if n == x.len()/2 {
        let (xh1, xl1) = wol_map(&x[x.len()-2]);
        let (xh2, xl2) = wol_map(&x[x.len()-1]);
        xh[n-1] = BsGF4::new(xh1, xh2);
        xl[n-1] = BsGF4::new(xl1, xl2);
    }else{
        let (xh1, xl1) = wol_map(&x[x.len()-2]);
        xh[n-1] = BsGF4::new(xh1, GF4::zero());
        xl[n-1] = BsGF4::new(xl1, GF4::zero());
    }
    (xh,xl)
}

pub fn un_wol_bitslice_gf4(xh: &[BsGF4], xl: &[BsGF4], x: &mut[GF8]) {
    for i in 0..(x.len()/2) {
        let (xh1, xh2) = xh[i].unpack();
        let (xl1, xl2) = xl[i].unpack();
        x[2*i] = wol_inv_map(&xh1, &xl1);
        x[2*i+1] = wol_inv_map(&xh2, &xl2);
    }
    if xh.len() * 2 != x.len() {
        let (xh1, _) = xh[xh.len()-1].unpack();
        let (xl1, _) = xl[xh.len()-1].unpack();
        x[x.len()-1] = wol_inv_map(&xh1, &xl1);
    }
}

fn gf8_inv_layer_opt(party: &mut WL16Party, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());
    let (mut ah_i, mut al_i) = wol_bitslice_gf4(si);
    let (ah_ii, mut al_ii) = wol_bitslice_gf4(sii);
    let v = izip!(ah_i.iter(), ah_ii.iter(), al_i.iter(), al_ii.iter()).map(|(ahi, ahii, ali, alii)| {
        let e_mul_ah2 = ahi.square_mul_e();
        let al2 = ali.square();
        let ah_mul_al = (*ahi * *ali) + (*ahi + *ahii) * (*ali + *alii);
        e_mul_ah2 + al2 + ah_mul_al
    }).collect();
    let (v_inv_i, v_inv_ii) = lut_layer_opt(party, v)?;

    // local mult
    al_i.iter_mut().zip(ah_i.iter()).for_each(|(l, h)| *l += *h);
    al_ii.iter_mut().zip(ah_ii.iter()).for_each(|(l, h)| *l += *h);
    let mut ah_plus_al_i = al_i;
    let ah_plus_al_ii = al_ii;

    // ah'
    izip!(ah_i.iter_mut(), ah_ii.iter(), v_inv_i.iter(), v_inv_ii.iter()).for_each(|(ahi, ahii, vinvi, vinvii)| {
        *ahi = (*ahi * *vinvi) + (*ahi + *ahii)*(*vinvi + *vinvii);
    });
    let mut ah_prime_ss = ah_i;
    // al'
    izip!(ah_plus_al_i.iter_mut(), ah_plus_al_ii.iter(), v_inv_i.iter(), v_inv_ii.iter()).for_each(|(ali, alii, vinvi, vinvii)| {
        *ali = (*ali * *vinvi) + (*ali + *alii)*(*vinvi + *vinvii);
    });
    let mut al_prime_ss = ah_plus_al_i;

    // re-share
    let mut ah_prime_ii = ah_ii;
    let mut al_prime_ii = ah_plus_al_ii;
    ss_to_rss_layer_opt(party, &mut ah_prime_ss, &mut al_prime_ss, &mut ah_prime_ii, &mut al_prime_ii)?;
    let ah_prime_i = ah_prime_ss;
    let al_prime_i = al_prime_ss;

    // un-bitslice
    un_wol_bitslice_gf4(&ah_prime_i, &al_prime_i, si);
    un_wol_bitslice_gf4(&ah_prime_ii, &al_prime_ii, sii);
    Ok(())
}

fn lut_layer_opt(party: &mut WL16Party, mut v: Vec<BsGF4>) -> MpcResult<(Vec<BsGF4>, Vec<BsGF4>)> {
    let n = 2*v.len();
    if party.prep_ohv.len() < n {
        panic!("Not enough pre-processed random one-hot vectors available. Use WL16Party::prepare_rand_ohv to generate them.");
    }
    #[cfg(feature = "verbose-timing")]
    let lut_open_time = Instant::now();

    let rnd_ohv = &party.prep_ohv[party.prep_ohv.len()-n..];
    let rcv_cii = party.io().receive_field::<BsGF4>(Direction::Next, v.len());
    let rcv_ciii = party.io().receive_field::<BsGF4>(Direction::Previous, v.len());
    v.iter_mut().enumerate().for_each(|(i, dst)| {
        *dst += BsGF4::new(rnd_ohv[2*i].random, rnd_ohv[2*i+1].random);
    });
    let ci = v;
    party.io().send_field::<BsGF4>(Direction::Next, &ci, ci.len());
    party.io().send_field::<BsGF4>(Direction::Previous, &ci, ci.len());
    
    let cii = rcv_cii.rcv()?;
    let ciii = rcv_ciii.rcv()?;
    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER.lock().unwrap().report_time("gf8_inv_layer_lut_open", lut_open_time.elapsed());

    #[cfg(feature = "verbose-timing")]
    let lut_local_time = Instant::now();
    let res = lut_with_rnd_ohv_bitsliced_opt(rnd_ohv, ci, cii, ciii);
    // remove used pre-processing material
    party.prep_ohv.truncate(party.prep_ohv.len()-n);

    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER.lock().unwrap().report_time("gf8_inv_layer_lut_local", lut_local_time.elapsed());

    party.io().wait_for_completion();
    Ok(res)
}

fn ss_to_rss_layer_opt(party: &mut WL16Party, ss1: &mut [BsGF4], ss2: &mut [BsGF4], ss1_ii: &mut [BsGF4], ss2_ii: &mut [BsGF4]) -> MpcResult<()> {
    debug_assert_eq!(ss1.len(), ss2.len());
    debug_assert_eq!(ss1.len(), ss1_ii.len());
    debug_assert_eq!(ss1.len(), ss2_ii.len());
    let n = ss1.len();
    let rcv_ii = party.io().receive_field::<BsGF4>(Direction::Next, 2*n);
    izip!(ss1.iter_mut(), party.generate_alpha(n)).for_each(|(si, alpha)| {
        *si += alpha;
    });
    izip!(ss2.iter_mut(), party.generate_alpha(n)).for_each(|(si, alpha)| {
        *si += alpha;
    });
    party.io().send_field::<BsGF4>(Direction::Previous, ss1.iter().chain(ss2.iter()), 2*n);
    let res = rcv_ii.rcv()?;
    ss1_ii.copy_from_slice(&res[..n]);
    ss2_ii.copy_from_slice(&res[n..]);
    party.io().wait_for_completion();
    Ok(())
}

#[inline]
pub fn lut_with_rnd_ohv_bitsliced_opt(rnd_ohv: &[RndOhvOutput], ci: Vec<BsGF4>, mut cii: Vec<BsGF4>, mut ciii: Vec<BsGF4>) -> (Vec<BsGF4>, Vec<BsGF4>) {
    for i in 0..ci.len() {
        let (c1, c2) = (ci[i]+cii[i]+ciii[i]).unpack();
        let ohv1 = &rnd_ohv[2*i];
        let (lut1_i, lut1_ii) = RndOhv16::lut_rss(c1.as_u8() as usize, &ohv1.si, &ohv1.sii, &GF4_BITSLICED_LUT);
        let ohv2 = &rnd_ohv[2*i+1];
        let (lut2_i, lut2_ii) = RndOhv16::lut_rss(c2.as_u8() as usize, &ohv2.si, &ohv2.sii, &GF4_BITSLICED_LUT);
        cii[i] = BsGF4::new(lut1_i, lut2_i);
        ciii[i] = BsGF4::new(lut1_ii, lut2_ii);
    }
    (cii, ciii)
}

impl GF8InvBlackBox for WL16Party {
    fn constant(&self, value: GF8) -> crate::share::RssShare<GF8> {
        self.inner.constant(value)
    }
    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        let n_rnd_ohv_ks = 4*10 * n_keys; // 4 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_rnd_ohv = 16*10 * n_blocks; // 16 S-boxes per round, 10 rounds, 1 LUT per S-box
        self.prepare_rand_ohv(n_rnd_ohv + n_rnd_ohv_ks)
    }
    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        if self.opt {
            gf8_inv_layer_opt(self, si, sii)
        }else{
            gf8_inv_layer(self, si, sii)
        }
    }
}

impl<F: Field> ArithmeticBlackBox<F> for WL16Party
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
    use itertools::{izip, Itertools};
    use rand::{thread_rng, CryptoRng, Rng};

    use crate::{aes::test::{test_aes128_keyschedule_gf8, test_aes128_no_keyschedule_gf8, test_inv_aes128_no_keyschedule_gf8, test_sub_bytes}, share::{gf4::GF4, gf8::GF8, test::{assert_eq, consistent, secret_share_vector}, Field, FieldRngExt, RssShare}, wollut16::{online::{gf8_inv_layer_opt, GF4_INV}, test::{localhost_setup_wl16, WL16Setup}, WL16Party}};

    use super::{gf8_inv_layer, LUT_layer};

    fn secret_share_additive<R: Rng + CryptoRng, F: Field>(rng: &mut R, it: impl ExactSizeIterator<Item=F>) -> (Vec<F>, Vec<F>, Vec<F>)
    where R: FieldRngExt<F>
    {
        let s1 = rng.generate(it.len());
        let s2 = rng.generate(it.len());
        let s3 = izip!(it, s1.iter(), s2.iter()).map(|(el, r1, r2)| {
            el - *r1 - *r2
        }).collect();
        (s1, s2, s3)
    }

    #[test]
    fn LUT_layer_correct() {
        let inputs: Vec<_> = (0..16).map(|x| GF4::new(x)).collect();
        let mut rng = thread_rng();
        let (in1, in2, in3) = secret_share_additive::<_, GF4>(&mut rng, inputs.clone().into_iter());
        let program = |v: Vec<GF4>| {
            move |p: &mut WL16Party| {
                p.prepare_rand_ohv(v.len()).unwrap();
                let (si,sii) = LUT_layer(p, &v).unwrap();
                si.into_iter().zip(sii).map(|(si,sii)| RssShare::from(si, sii)).collect_vec()
            }
        };
        let (h1,h2,h3) = localhost_setup_wl16(program(in1), program(in2), program(in3));
        let (s1, p1) = h1.join().unwrap();
        let (s2, p2) = h2.join().unwrap();
        let (s3, p3) = h3.join().unwrap();

        assert_eq!(s1.len(), inputs.len());
        assert_eq!(s2.len(), inputs.len());
        assert_eq!(s3.len(), inputs.len());
        // check that no more rnd-ohv are present
        assert_eq!(p1.prep_ohv.len(), 0);
        assert_eq!(p2.prep_ohv.len(), 0);
        assert_eq!(p3.prep_ohv.len(), 0);

        // check correct table lookup
        for (i, (s1, s2, s3)) in izip!(s1, s2, s3).enumerate() {
            consistent(&s1, &s2, &s3);
            assert_eq(s1, s2, s3, GF4::new(GF4_INV[i]));
        }
    }

    const GF8_INV_TABLE: [u8; 256] = [0x00, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5, 0xc7, 0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f, 0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40, 0xee, 0xb2, 0x3a, 0x6e, 0x5a, 0xf1, 0x55, 0x4d, 0xa8, 0xc9, 0xc1, 0x0a, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2, 0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20, 0x6f, 0x77, 0xbb, 0x59, 0x19, 0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69, 0xa7, 0x64, 0xab, 0x13, 0x54, 0x25, 0xe9, 0x09, 0xed, 0x5c, 0x05, 0xca, 0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e, 0x22, 0xf0, 0x51, 0xec, 0x61, 0x17, 0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4, 0x47, 0x91, 0xdf, 0x33, 0x93, 0x21, 0x3b, 0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c, 0xb6, 0x70, 0xd0, 0x06, 0xa1, 0xfa, 0x81, 0x82, 0x83, 0x7e, 0x7f, 0x80, 0x96, 0x73, 0xbe, 0x56, 0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x02, 0xb9, 0xa4, 0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72, 0x2a, 0x14, 0x9f, 0x88, 0xf9, 0xdc, 0x89, 0x9a, 0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48, 0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62, 0x0c, 0xe0, 0x1f, 0xef, 0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57, 0x0b, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0x0f, 0xa9, 0x27, 0x53, 0x04, 0x1b, 0xfc, 0xac, 0xe6, 0x7a, 0x07, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea, 0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b, 0xb1, 0x0d, 0xd6, 0xeb, 0xc6, 0x0e, 0xcf, 0xad, 0x08, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3, 0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8c, 0xdd, 0x9c, 0x7d, 0xa0, 0xcd, 0x1a, 0x41, 0x1c];

    #[test]
    fn gf8_inv_correct() {
        let inputs = (0..=255).map(|x| GF8(x)).collect_vec();
        let mut rng = thread_rng();
        let (s1, s2, s3) = secret_share_vector(&mut rng, inputs.clone().into_iter());
        let program = |v: Vec<RssShare<GF8>>| {
            move |p: &mut WL16Party| {
                p.prepare_rand_ohv(v.len()).unwrap();
                let (mut si, mut sii): (Vec<_>, Vec<_>) = v.into_iter().map(|rss| (rss.si,rss.sii)).unzip();
                gf8_inv_layer(p, &mut si, &mut sii).unwrap();
                si.into_iter().zip(sii).map(|(si,sii)| RssShare::from(si, sii)).collect_vec()
            }
        };

        let (h1,h2,h3) = localhost_setup_wl16(program(s1), program(s2), program(s3));
        let (s1, _) = h1.join().unwrap();
        let (s2, _) = h2.join().unwrap();
        let (s3, _) = h3.join().unwrap();
        assert_eq!(s1.len(), inputs.len());
        assert_eq!(s2.len(), inputs.len());
        assert_eq!(s3.len(), inputs.len());
        for (i, (s1, s2, s3)) in izip!(s1, s2, s3).enumerate() {
            consistent(&s1, &s2, &s3);
            assert_eq(s1, s2, s3, GF8(GF8_INV_TABLE[i]));
        }
    }

    #[test]
    fn gf8_inv_opt_correct() {
        let inputs = (0..=255).map(|x| GF8(x)).collect_vec();
        let mut rng = thread_rng();
        let (s1, s2, s3) = secret_share_vector(&mut rng, inputs.clone().into_iter());
        let program = |v: Vec<RssShare<GF8>>| {
            move |p: &mut WL16Party| {
                p.prepare_rand_ohv(v.len()).unwrap();
                let (mut si, mut sii): (Vec<_>, Vec<_>) = v.into_iter().map(|rss| (rss.si,rss.sii)).unzip();
                gf8_inv_layer_opt(p, &mut si, &mut sii).unwrap();
                si.into_iter().zip(sii).map(|(si,sii)| RssShare::from(si, sii)).collect_vec()
            }
        };

        let (h1,h2,h3) = localhost_setup_wl16(program(s1), program(s2), program(s3));
        let (s1, _) = h1.join().unwrap();
        let (s2, _) = h2.join().unwrap();
        let (s3, _) = h3.join().unwrap();
        assert_eq!(s1.len(), inputs.len());
        assert_eq!(s2.len(), inputs.len());
        assert_eq!(s3.len(), inputs.len());
        for (i, (s1, s2, s3)) in izip!(s1, s2, s3).enumerate() {
            consistent(&s1, &s2, &s3);
            assert_eq(s1, s2, s3, GF8(GF8_INV_TABLE[i]));
        }
    }

    #[test]
    fn sub_bytes() {
        test_sub_bytes::<WL16Setup,_>()
    }

    #[test]
    fn aes128_keyschedule_lut16() {
        test_aes128_keyschedule_gf8::<WL16Setup, _>()
    }

    #[test]
    fn aes_128_no_keyschedule_lut16() {
        test_aes128_no_keyschedule_gf8::<WL16Setup, _>()
    }

    #[test]
    fn inv_aes128_no_keyschedule_lut16() {
        test_inv_aes128_no_keyschedule_gf8::<WL16Setup, _>()
    }

    #[test]
    fn create_table() {
        let mut table = [[0u16; 4]; 16];
        for offset in 0..16 {
            for j in 0..4 {
                let mut entry = 0u16;
                for i in 0..16 {
                    entry |= (((GF4_INV[offset ^ i] >> j) & 0x1) as u16) << i;
                }
                table[offset][j] = entry;
            }
        }

        println!("const GF4_BITSLICED_LUT: [[u16; 4]; 16] = [");
        for i in 0..16 {
            println!("\t{:?},", table[i]);
        }
        println!("];");
    }
}