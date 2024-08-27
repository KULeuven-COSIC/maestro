use itertools::{izip, Itertools};
use rayon::{iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator}, slice::{ParallelSlice, ParallelSliceMut}};

use crate::{
    share::{
        gf4::{BsGF4, GF4},
        gf8::GF8,
        wol::{wol_inv_map, wol_map},
    }, util::mul_triple_vec::{GF4p4TripleRecorder, GF4p4TripleVector, MulTripleRecorder}, wollut16::{RndOhv16, RndOhv16Output}
};

use rep3_core::{
    network::task::Direction,
    party::{error::MpcResult, MainParty, Party}, share::HasZero,
};

/// This protocol implements multiplicative inversion as in `Protocol 3`.
///
/// Given a (2,3)-RSS shared vector `[[x]]`` of elements in `GF(2^8)`,
/// the protocol computes the component-wise multiplicative inverse.
///
/// The function inputs are:
/// - `party` - the local [WL16ASParty] `P_i`
/// - `si` - the first component of `[[x]]_i`
/// - `sii` - the second component of `[[x]]_i`
///
/// The output, the share `[[x^-1]]_i`, is written into `(s_i,s_ii)`.
pub fn gf8_inv_layer<P: Party, Rec: MulTripleRecorder<BsGF4>>(party: &mut P, triple_rec: &mut Rec, si: &mut [GF8], sii: &mut [GF8], rnd_ohv: &[RndOhv16Output]) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());
    // Step 1 WOL conversion
    let (ah_i, al_i) = wol_bitslice_gf4(si);
    let (ah_ii, al_ii) = wol_bitslice_gf4(sii);
    // Step 2 Square (done inline to save memory)
    //let al_i_sq = square_layer(&al_i);
    //let al_ii_sq = square_layer(&al_ii);
    //let ah_i_sq_e = square_and_e_layer(&ah_i);
    //let ah_ii_sq_e = square_and_e_layer(&ah_ii);
    // Step 3 Compute v
    let mut v: Vec<_> = izip!(ah_i.iter(), ah_ii.iter(), al_i.iter(), al_ii.iter())
        .map(|(ahi, ahii, ali, alii)| {
            let e_mul_ah2 = ahi.square_mul_e();
            let al2 = ali.square();
            let ah_mul_al = (*ahi * *ali) + (*ahi + *ahii) * (*ali + *alii);
            e_mul_ah2 + al2 + ah_mul_al
        })
        .collect();
    // Step 4 LUT Layer
    let mut v_ii = vec![BsGF4::ZERO; v.len()];
    let (v_inv_i, v_inv_ii) = lut_layer_opt(party, &mut v, &mut v_ii, rnd_ohv)?;
    // Step 5 local multiplication
    let mut ah_prime: Vec<_> = izip!(ah_i.iter(), ah_ii.iter(), v_inv_i.iter(), v_inv_ii.iter())
        .map(|(ahi, ahii, vinvi, vinvii)| (*ahi * *vinvi) + (*ahi + *ahii) * (*vinvi + *vinvii))
        .collect();
    let mut al_prime: Vec<_> = izip!(
        ah_i.iter(),
        ah_ii.iter(),
        al_i.iter(),
        al_ii.iter(),
        v_inv_i.iter(),
        v_inv_ii.iter()
    )
    .map(|(ahi, ahii, ali, alii, vinvi, vinvii)| {
        let ah_plus_al_i = *ahi + *ali;
        let ah_plus_al_ii = *ahii + *alii;
        (ah_plus_al_i * *vinvi) + (ah_plus_al_i + ah_plus_al_ii) * (*vinvi + *vinvii)
    })
    .collect();
    // Step 6 Resharing
    
    let mut ah_prime_ii = vec![BsGF4::ZERO; v.len()];
    let mut al_prime_ii = vec![BsGF4::ZERO; v.len()];
    ss_to_rss_layer(
        party,
        &mut ah_prime,
        &mut ah_prime_ii,
        &mut al_prime,
        &mut al_prime_ii,
    )?;

    // Step 7 Preparation for multiplication triples for verification
    // Compute [a_h * a_l] := [v] + (e * a_h^2) + a_l^2
    izip!(v.iter_mut(), ah_i.iter(), al_i.iter())
        .for_each(|(vi, ahi, ali)| *vi = *vi + ahi.square_mul_e() + ali.square());
    izip!(v_ii.iter_mut(), ah_ii.iter(), al_ii.iter())
        .for_each(|(vii, ahii, alii)| *vii = *vii + ahii.square_mul_e() + alii.square());
    let a_h_times_a_l_i = v;
    let a_h_times_a_l_ii = v_ii;

    // Add triples to buffer
    // [a_h],[a_l],[a_h * a_l]
    triple_rec.record_mul_triple(&ah_i,&ah_ii, &al_i, &al_ii, &a_h_times_a_l_i, &a_h_times_a_l_ii);
    // [a_h], [v^-1], [a_h']
    triple_rec.record_mul_triple(&ah_i, &ah_ii, &v_inv_i, &v_inv_ii, &ah_prime, &ah_prime_ii);

    let a_h_plus_a_l_i = ah_i.into_iter().zip(al_i).map(|(ah,al)| ah + al).collect_vec();
    let a_h_plus_a_l_ii = ah_ii.into_iter().zip(al_ii).map(|(ah,al)| ah + al).collect_vec();
    // [a_h + a_l], [v^-1], [a_l']
    triple_rec.record_mul_triple(&a_h_plus_a_l_i, &a_h_plus_a_l_ii, &v_inv_i, &v_inv_ii, &al_prime, &al_prime_ii);
    
    // Step 8 WOL-inv conversion
    un_wol_bitslice_gf4(&ah_prime, &al_prime, si);
    un_wol_bitslice_gf4(&ah_prime_ii, &al_prime_ii, sii);
    Ok(())
}

pub fn gf8_inv_layer_mt<Rec: MulTripleRecorder<BsGF4>>(party: &mut MainParty, triple_rec: &mut Rec, si: &mut [GF8], sii: &mut [GF8], rnd_ohv: &[RndOhv16Output]) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());
    debug_assert_eq!(rnd_ohv.len(), si.len());
    
    let ranges = party.split_range_equally_even(si.len());
    let chunk_size = ranges[0].1 - ranges[0].0;
    let threads = party.create_thread_parties_with_additional_data(ranges, |start, end| Some(triple_rec.create_thread_mul_triple_recorder(start, end)));

    
    let observed_triples = party.run_in_threadpool(|| {
        threads.into_par_iter().zip_eq(si.par_chunks_mut(chunk_size)).zip_eq(sii.par_chunks_mut(chunk_size)).zip_eq(rnd_ohv.par_chunks(chunk_size))
            .map(|(((mut thread_party, si), sii), prep_ohv)| {
                let mut triple_rec = thread_party.additional_data.take().unwrap();
                gf8_inv_layer(&mut thread_party, &mut triple_rec, si, sii, prep_ohv).map(|()| triple_rec)
        }).collect::<MpcResult<Vec<_>>>()
    })?;
    // add observed triples
    triple_rec.join_thread_mul_triple_recorders(observed_triples);
    Ok(())
}

/// This protocol implements multiplicative inversion as in `Protocol 3` with reduced number of multiplication checks.
///
/// Given a (2,3)-RSS shared vector `[[x]]`` of elements in `GF(2^8)`,
/// the protocol computes the component-wise multiplicative inverse.
///
/// The function inputs are:
/// - `party` - the local [WL16ASParty] `P_i`
/// - `si` - the first component of `[[x]]_i`
/// - `sii` - the second component of `[[x]]_i`
///
/// The output, the share `[[x^-1]]_i`, is written into `(s_i,s_ii)`.
pub fn gf8_inv_layer_gf4p4_check<P: Party, Rec: GF4p4TripleRecorder>(party: &mut P, triple_rec: &mut Rec, si: &mut [GF8], sii: &mut [GF8], rnd_ohv: &[RndOhv16Output]) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());
    // Step 1 WOL conversion
    let (ah_i, al_i) = wol_bitslice_gf4(si);
    let (ah_ii, al_ii) = wol_bitslice_gf4(sii);
    // Step 3 Compute v
    let mut v: Vec<_> = izip!(ah_i.iter(), ah_ii.iter(), al_i.iter(), al_ii.iter())
        .map(|(ahi, ahii, ali, alii)| {
            let e_mul_ah2 = ahi.square_mul_e();
            let al2 = ali.square();
            let ah_mul_al = (*ahi * *ali) + (*ahi + *ahii) * (*ali + *alii);
            e_mul_ah2 + al2 + ah_mul_al
        })
        .collect();
    // Step 4 LUT Layer
    let mut v_ii = vec![BsGF4::ZERO; v.len()];
    let (v_inv_i, v_inv_ii) = lut_layer_opt(party, &mut v, &mut v_ii, rnd_ohv)?;
    // Step 5 local multiplication
    let mut ah_prime: Vec<_> = izip!(ah_i.iter(), ah_ii.iter(), v_inv_i.iter(), v_inv_ii.iter())
        .map(|(ahi, ahii, vinvi, vinvii)| (*ahi * *vinvi) + (*ahi + *ahii) * (*vinvi + *vinvii))
        .collect();
    let mut al_prime: Vec<_> = izip!(
        ah_i.iter(),
        ah_ii.iter(),
        al_i.iter(),
        al_ii.iter(),
        v_inv_i.iter(),
        v_inv_ii.iter()
    )
    .map(|(ahi, ahii, ali, alii, vinvi, vinvii)| {
        let ah_plus_al_i = *ahi + *ali;
        let ah_plus_al_ii = *ahii + *alii;
        (ah_plus_al_i * *vinvi) + (ah_plus_al_i + ah_plus_al_ii) * (*vinvi + *vinvii)
    })
    .collect();
    // Step 6 Resharing
    let mut ah_prime_ii = vec![BsGF4::ZERO; v.len()];
    let mut al_prime_ii = vec![BsGF4::ZERO; v.len()];
    ss_to_rss_layer(
        party,
        &mut ah_prime,
        &mut ah_prime_ii,
        &mut al_prime,
        &mut al_prime_ii,
    )?;

    // Step 7 Preparation for multiplication triples for verification
    izip!(v, v_ii, ah_i, ah_ii, al_i, al_ii, v_inv_i, v_inv_ii, ah_prime.iter(), ah_prime_ii.iter(), al_prime.iter(), al_prime_ii.iter())
        .for_each(|(vi, vii, ahi, ahii, ali, alii, v_invi, v_invii, ah_prime_i, ah_prime_ii, al_prime_i, al_prime_ii)| {
            // Compute [a_h * a_l] := [v] + (e * a_h^2) + a_l^2
            let ah_times_al_i = vi + ahi.square_mul_e() + ali.square();
            let ah_times_al_ii = vii + ahii.square_mul_e() + alii.square();

            // Store ([ah] + alpha*[al]) * ([al] + alpha*[v_inv]) = [ah * al] + alpha*[ah' + al^2] + alpha^2 * [al' + ah']
            triple_rec.record_mul_triple(ahi, ahii, ali, alii, ali, alii, v_invi, v_invii, ah_times_al_i, ah_times_al_ii, *ah_prime_i + ali.square(), *ah_prime_ii + alii.square(), *al_prime_i + *ah_prime_i, *al_prime_ii + *ah_prime_ii);
    });
    
    // Step 8 WOL-inv conversion
    un_wol_bitslice_gf4(&ah_prime, &al_prime, si);
    un_wol_bitslice_gf4(&ah_prime_ii, &al_prime_ii, sii);
    Ok(())
}

pub fn gf8_inv_layer_gf4p4_check_mt(party: &mut MainParty, triple_rec: &mut GF4p4TripleVector, si: &mut [GF8], sii: &mut [GF8], rnd_ohv: &[RndOhv16Output]) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());
    debug_assert_eq!(rnd_ohv.len(), si.len());
    
    let ranges = party.split_range_equally_even(si.len());
    let mul_triple_lengths = ranges.iter().map(|(start, end)| (end-start)).collect_vec();
    let recorders = triple_rec.create_thread_mul_triple_recorders(&mul_triple_lengths);
    let chunk_size = ranges[0].1 - ranges[0].0;
    let mut threads = party.create_thread_parties_with_additional_data(ranges, |_, _| None);
    threads.iter_mut().zip_eq(recorders).for_each(|(tp, rec)| tp.additional_data = Some(rec));

    
    party.run_in_threadpool(|| {
        threads.into_par_iter().zip_eq(si.par_chunks_mut(chunk_size)).zip_eq(sii.par_chunks_mut(chunk_size)).zip_eq(rnd_ohv.par_chunks(chunk_size))
            .map(|(((mut thread_party, si), sii), prep_ohv)| {
                let mut triple_rec = thread_party.additional_data.take().unwrap();
                gf8_inv_layer_gf4p4_check(&mut thread_party, &mut triple_rec, si, sii, prep_ohv)
        }).collect::<MpcResult<()>>()
    })?;
    Ok(())
}

/// This function implements the WOL-transfer
///
/// The input is a vector of [GF8] elements.
/// The function returns two vectors of [BsGF4] elements.
/// The output vectors are always even. Thus if the input vector is odd, 0 is appended to input vector before the WOL transformation.
pub fn wol_bitslice_gf4(x: &[GF8]) -> (Vec<BsGF4>, Vec<BsGF4>) {
    let n = if x.len() % 2 == 0 {
        x.len() / 2
    } else {
        x.len() / 2 + 1
    };
    let mut xh = vec![BsGF4::ZERO; n];
    let mut xl = vec![BsGF4::ZERO; n];
    for i in 0..(n - 1) {
        let (xh1, xl1) = wol_map(&x[2 * i]);
        let (xh2, xl2) = wol_map(&x[2 * i + 1]);
        xh[i] = BsGF4::new(xh1, xh2);
        xl[i] = BsGF4::new(xl1, xl2);
    }
    if n == x.len() / 2 {
        let (xh1, xl1) = wol_map(&x[x.len() - 2]);
        let (xh2, xl2) = wol_map(&x[x.len() - 1]);
        xh[n - 1] = BsGF4::new(xh1, xh2);
        xl[n - 1] = BsGF4::new(xl1, xl2);
    } else {
        let (xh1, xl1) = wol_map(&x[x.len() - 2]);
        xh[n - 1] = BsGF4::new(xh1, GF4::ZERO);
        xl[n - 1] = BsGF4::new(xl1, GF4::ZERO);
    }
    (xh, xl)
}

/// This function square the given input vector component-wise
#[inline]
fn square_layer(v: &[BsGF4]) -> Vec<BsGF4> {
    v.iter().map(|x| x.square()).collect()
}

/// This function square the given input vector component-wise
#[inline]
fn square_and_e_layer(v: &[BsGF4]) -> Vec<BsGF4> {
    v.iter().map(|x| x.square_mul_e()).collect()
}

/// This protocol implements the preprocessed table lookup to compute [[v^-1]] from <<v>> and also returns [[v]]
fn lut_layer_opt<P: Party>(
    party: &mut P,
    v: &mut [BsGF4],
    v_ii: &mut [BsGF4],
    rnd_ohv: &[RndOhv16Output],
) -> MpcResult<(Vec<BsGF4>, Vec<BsGF4>)> {

    let rcv_cii = party.receive_field::<BsGF4>(Direction::Next, v.len());
    let rcv_ciii = party.receive_field::<BsGF4>(Direction::Previous, v.len());
    v.iter_mut().enumerate().for_each(|(i, dst)| {
        *dst += BsGF4::new(rnd_ohv[2 * i].random_si, rnd_ohv[2 * i + 1].random_si);
    });
    // TODO party_send_all
    party.send_field_slice(Direction::Next, v);
    party.send_field_slice(Direction::Previous, v);

    let cii = rcv_cii.rcv()?;
    let ciii = rcv_ciii.rcv()?;

    let res = lut_with_rnd_ohv_bitsliced_opt(rnd_ohv, v, cii, ciii);
    for i in 0..v.len() {
        let rand_si = BsGF4::new(rnd_ohv[2*i].random_si, rnd_ohv[2*i+1].random_si);
        let rand_sii = BsGF4::new(rnd_ohv[2*i].random_sii, rnd_ohv[2*i+1].random_sii);
        v_ii[i] = v[i] + rand_sii;
        v[i] += rand_si;
    }

    // party.inner.io().wait_for_completion();
    Ok(res)
}

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

/// Performs the table lookup at (ci + cii + ciii) and returns the results as (2,3) sharing in (cii, ciii).
/// Returns the offset (ci + cii + ciii) in ci
#[inline]
pub fn lut_with_rnd_ohv_bitsliced_opt(
    rnd_ohv: &[RndOhv16Output],
    ci: &mut [BsGF4],
    mut cii: Vec<BsGF4>,
    mut ciii: Vec<BsGF4>,
) -> (Vec<BsGF4>, Vec<BsGF4>) {
    for i in 0..ci.len() {
        ci[i] += cii[i] + ciii[i];
        let (c1, c2) = ci[i].unpack();
        let ohv1 = &rnd_ohv[2 * i];
        let (lut1_i, lut1_ii) =
            RndOhv16::lut_rss(c1.as_u8() as usize, &ohv1.si, &ohv1.sii, &GF4_BITSLICED_LUT);
        let ohv2 = &rnd_ohv[2 * i + 1];
        let (lut2_i, lut2_ii) =
            RndOhv16::lut_rss(c2.as_u8() as usize, &ohv2.si, &ohv2.sii, &GF4_BITSLICED_LUT);
        cii[i] = BsGF4::new(lut1_i, lut2_i);
        ciii[i] = BsGF4::new(lut1_ii, lut2_ii);
    }
    (cii, ciii)
}

/// This function implements the resharing protocol from sum shares to replicated shares.
fn ss_to_rss_layer<P: Party>(
    party: &mut P,
    a_i: &mut [BsGF4],
    a_ii: &mut [BsGF4],
    b_i: &mut [BsGF4],
    b_ii: &mut [BsGF4],
) -> MpcResult<()> {
    debug_assert_eq!(a_i.len(), a_ii.len());
    debug_assert_eq!(a_i.len(), b_ii.len());
    debug_assert_eq!(b_i.len(), b_ii.len());
    let n = a_i.len();
    let rcv_ii = party.receive_field::<BsGF4>(Direction::Next, 2 * n);
    izip!(a_i.iter_mut(), party.generate_alpha(n)).for_each(|(si, alpha)| {
        *si += alpha;
    });
    izip!(b_i.iter_mut(), party.generate_alpha(n)).for_each(|(si, alpha)| {
        *si += alpha;
    });
    // TODO party_send_chunks
    party.send_field::<BsGF4>(
        Direction::Previous,
        a_i.iter().chain(b_i.iter()),
        2 * n,
    );
    let res = rcv_ii.rcv()?;
    a_ii.copy_from_slice(&res[..n]);
    b_ii.copy_from_slice(&res[n..]);
    // party.inner.io().wait_for_completion();
    Ok(())
}

pub fn un_wol_bitslice_gf4(xh: &[BsGF4], xl: &[BsGF4], x: &mut [GF8]) {
    for i in 0..(x.len() / 2) {
        let (xh1, xh2) = xh[i].unpack();
        let (xl1, xl2) = xl[i].unpack();
        x[2 * i] = wol_inv_map(&xh1, &xl1);
        x[2 * i + 1] = wol_inv_map(&xh2, &xl2);
    }
    if xh.len() * 2 != x.len() {
        let (xh1, _) = xh[xh.len() - 1].unpack();
        let (xl1, _) = xl[xh.len() - 1].unpack();
        x[x.len() - 1] = wol_inv_map(&xh1, &xl1);
    }
}

#[cfg(test)]
mod test {
    use crate::{aes::test::{test_aes128_keyschedule_gf8, test_aes128_no_keyschedule_gf8, test_inv_aes128_no_keyschedule_gf8, test_sub_bytes}, wollut16_malsec::test::{WL16ASSetup, WL16BitString, WL16DefaultParams, WL16OhvCheck}};


    #[test]
    fn sub_bytes() {
        test_sub_bytes::<WL16ASSetup::<WL16DefaultParams>,_>(None)
    }

    #[test]
    fn sub_bytes_gf4p4_check() {
        test_sub_bytes::<WL16ASSetup::<WL16OhvCheck>,_>(None)
    }

    #[test]
    fn sub_bytes_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<WL16ASSetup::<WL16DefaultParams>,_>(Some(N_THREADS))
    }

    #[test]
    fn sub_bytes_gf4p4_check_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<WL16ASSetup::<WL16OhvCheck>,_>(Some(N_THREADS))
    }

    #[test]
    fn aes128_keyschedule() {
        test_aes128_keyschedule_gf8::<WL16ASSetup::<WL16DefaultParams>, _>(None)
    }

    #[test]
    fn aes_128_no_keyschedule() {
        test_aes128_no_keyschedule_gf8::<WL16ASSetup::<WL16DefaultParams>, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<WL16ASSetup::<WL16DefaultParams>, _>(100, Some(N_THREADS))
    }

    #[test]
    fn inv_aes128_no_keyschedule() {
        test_inv_aes128_no_keyschedule_gf8::<WL16ASSetup::<WL16DefaultParams>, _>(1, None)
    }

    #[test]
    fn inv_aes128_no_keyschedule_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<WL16ASSetup::<WL16DefaultParams>, _>(100, Some(N_THREADS))
    }

    #[test]
    fn aes_128_no_keyschedule_gf4p4() {
        test_aes128_no_keyschedule_gf8::<WL16ASSetup::<WL16OhvCheck>, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_gf4p4_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<WL16ASSetup::<WL16OhvCheck>, _>(100, Some(N_THREADS))
    }

    #[test]
    fn aes_128_no_keyschedule_gf4p4_bitstring() {
        test_aes128_no_keyschedule_gf8::<WL16ASSetup::<WL16BitString>, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_gf4p4_bitstring_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<WL16ASSetup::<WL16BitString>, _>(100, Some(N_THREADS))
    }
}