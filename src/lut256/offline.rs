use std::iter;

use itertools::{izip, repeat_n, Itertools};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{
    chida, share::{bs_bool16::BsBool16, gf8::GF8, Field}, util::{self, mul_triple_vec::{BitStringMulTripleRecorder, MulTripleRecorder, Ohv16TripleRecorder}}, wollut16
};
use crate::rep3_core::{party::{error::MpcResult, MainParty, Party}, share::{HasZero, RssShare}};

use super::{RndOhv256Output, RndOhv256OutputSS};

pub fn generate_rndohv256<Rec: BitStringMulTripleRecorder>(party: &mut MainParty, mul_triple_recorder: &mut Rec, amount: usize) -> MpcResult<Vec<RndOhv256Output>> {
    let n_blocks = amount.div_ceil(16);
    let bits = (0..8)
        .map(|_| party.generate_random(n_blocks))
        .collect_vec();
    let mut res = generate_ohv256_output(party, mul_triple_recorder, bits)?;
    res.truncate(amount);
    party.wait_for_completion();
    Ok(res)
}

pub fn generate_rndohv256_mt<Rec: MulTripleRecorder<F>, F: Field>(
    party: &mut MainParty,
    mul_triple_recorder: &mut Rec,
    amount: usize,
) -> MpcResult<Vec<RndOhv256Output>> 
where Rec::ThreadMulTripleRecorder: BitStringMulTripleRecorder
{
    let n_blocks = if amount % 16 == 0 {
        amount / 16
    } else {
        amount / 16 + 1
    };

    let ranges = party.split_range_equally(n_blocks);
    let thread_parties = party.create_thread_parties_with_additional_data(ranges, |start, end| Some(mul_triple_recorder.create_thread_mul_triple_recorder(start, end)));
    let mut res = Vec::with_capacity(thread_parties.len());
    party.run_in_threadpool(|| {
        thread_parties
            .into_par_iter()
            .map(|mut thread_party| {
                let bits = (0..8)
                    .map(|_| thread_party.generate_random(thread_party.task_size()))
                    .collect_vec();
                let mut recorder = thread_party.additional_data.take().unwrap();
                let out = generate_ohv256_output(&mut thread_party, &mut recorder, bits).unwrap();
                (out, recorder)
            })
            .collect_into_vec(&mut res);
        Ok(())
    })?;
    let (ohv, rec): (Vec<_>, _) = res.into_iter().unzip();
    mul_triple_recorder.join_thread_mul_triple_recorders(rec);

    let res = ohv.into_iter().flatten().take(amount).collect();
    party.wait_for_completion();
    Ok(res)
}

pub fn generate_rndohv256_ss<Rec: MulTripleRecorder<BsBool16>>(party: &mut MainParty, mul_triple_recorder: &mut Rec, amount: usize) -> MpcResult<Vec<RndOhv256OutputSS>> {
    let n_blocks = amount.div_ceil(16);
    let bits = random_8_bits(party, n_blocks);
    let res = generate_ohv256_ss_output(party, mul_triple_recorder, amount, bits)?;
    party.wait_for_completion();
    Ok(res)
}

pub fn generate_rndohv256_ss_ohv_check<Rec: Ohv16TripleRecorder>(party: &mut MainParty, mul_triple_recorder: &mut Rec, amount: usize) -> MpcResult<Vec<RndOhv256OutputSS>> {
    let n_blocks = amount.div_ceil(16);
    let bits = random_8_bits(party, n_blocks);
    let res = generate_rndohv256_ss_ohv_check_output(party, mul_triple_recorder, amount, bits)?;
    party.wait_for_completion();
    Ok(res)
}

fn generate_rndohv256_ss_ohv_check_output<P: Party, Rec: Ohv16TripleRecorder>(party: &mut P, triple_rec: &mut Rec, n: usize, random_bits: [Vec<RssShare<BsBool16>>; 8]) -> MpcResult<Vec<RndOhv256OutputSS>> {
    let n16 = random_bits[0].len();
    debug_assert!(random_bits.iter().all(|v| v.len() == n16));
    debug_assert_eq!(n16, n.div_ceil(16)); // otherwise we produce too many random_bits than actually needed

    let [r0, r1, r2, r3, r4, r5, r6, r7] = random_bits;
    // these two can also be realized in one call to generate_ohv_16_bitslice with double the size
    let lower = wollut16::offline::generate_ohv16_bitslice_opt_check(party, triple_rec, &r0, &r1, &r2, &r3)?;
    let upper = wollut16::offline::generate_ohv16_bitslice_opt_check(party, triple_rec, &r4, &r5, &r6, &r7)?;

    // let ohv16_time = ohv16_time.elapsed();
    Ok(tensor_two_ohv16(party, lower, upper, [r0, r1, r2, r3, r4, r5, r6, r7], n))
}

pub fn generate_rndohv256_ss_mt<Rec: MulTripleRecorder<BsBool16>>(party: &mut MainParty, mul_triple_recorder: &mut Rec, amount: usize) -> MpcResult<Vec<RndOhv256OutputSS>> {
    let n_blocks = amount.div_ceil(16);
    let ranges = party.split_range_equally(n_blocks);
    let thread_parties = party.create_thread_parties_with_additional_data(ranges, |start, end| Some(mul_triple_recorder.create_thread_mul_triple_recorder(start, end)));
    let mut res = Vec::with_capacity(thread_parties.len());
    party.run_in_threadpool(|| {
        thread_parties
            .into_par_iter()
            .map(|mut thread_party| {
                let n_blocks_per_thread = thread_party.task_size();
                let bits = random_8_bits(&mut thread_party, n_blocks_per_thread);
                let mut recorder = thread_party.additional_data.take().unwrap();
                let out = generate_ohv256_ss_output(&mut thread_party, &mut recorder, 16*n_blocks_per_thread, bits).unwrap();
                (out, recorder)
            })
            .collect_into_vec(&mut res);
        Ok(())
    })?;
    let (ohv, rec): (Vec<_>, _) = res.into_iter().unzip();
    mul_triple_recorder.join_thread_mul_triple_recorders(rec);

    let res = ohv.into_iter().flatten().take(amount).collect();
    party.wait_for_completion();
    Ok(res)
}

pub fn generate_rndohv256_ss_ohv_check_mt<Rec: Ohv16TripleRecorder>(party: &mut MainParty, mul_triple_recorder: &mut Rec, amount: usize) -> MpcResult<Vec<RndOhv256OutputSS>> {
    let n_blocks = amount.div_ceil(16);
    let ranges = party.split_range_equally(n_blocks);
    let task_sizes = ranges.iter().map(|(start, end)| 4*(end - start)).collect_vec();
    let slices = mul_triple_recorder.create_thread_mul_triple_recorders(&task_sizes).into_iter().map(|sl| Some(sl)).collect();
    let thread_parties = party.create_thread_parties_with_additiona_data_vec(ranges, slices);
    let mut res = Vec::with_capacity(thread_parties.len());
    party.run_in_threadpool(|| {
        thread_parties
            .into_par_iter()
            .map(|mut thread_party| {
                let n_blocks_per_thread = thread_party.task_size();
                let bits = random_8_bits(&mut thread_party, n_blocks_per_thread);
                let mut rec = thread_party.additional_data.take().unwrap();
                generate_rndohv256_ss_ohv_check_output(&mut thread_party, &mut rec, 16*n_blocks_per_thread, bits).unwrap()
            })
            .collect_into_vec(&mut res);
        Ok(())
    })?;

    let res = res.into_iter().flatten().take(amount).collect();
    party.wait_for_completion();
    Ok(res)
}

fn random_8_bits<P: Party>(party: &mut P, n_blocks: usize) -> [Vec<RssShare<BsBool16>>; 8] {
    [
        party.generate_random(n_blocks), party.generate_random(n_blocks), party.generate_random(n_blocks), party.generate_random(n_blocks),
        party.generate_random(n_blocks), party.generate_random(n_blocks), party.generate_random(n_blocks), party.generate_random(n_blocks)
    ]
}

fn tensor_two_ohv16<P: Party>(party: &mut P, lower: [Vec<RssShare<BsBool16>>; 16], upper: [Vec<RssShare<BsBool16>>; 16], random_bits: [Vec<RssShare<BsBool16>>; 8], n: usize) -> Vec<RndOhv256OutputSS> {
    // tensor prod
    let mut bits = Vec::with_capacity(256);
    for upper_bit in upper {
        bits.extend(lower.iter().map(|lower_bit| {
            let bit: Vec<BsBool16> = izip!(party.generate_alpha::<BsBool16>(lower_bit.len()), &upper_bit, lower_bit).map(|(alpha, x, y)| {
                alpha + x.si * y.si + (x.si + x.sii)*(y.si + y.sii)
            }).collect_vec();
            bit
        }));
    }

    let ohvs = util::un_bitslice::un_bitslice_ss(&bits);
    let rand = un_bitslice8(&random_bits);
    ohvs.into_iter().zip(rand).map(|(ohv, rand)| RndOhv256OutputSS {
        ohv,
        random_si: rand.si,
        random_sii: rand.sii,
    })
    .take(n)
    .collect()
}

fn generate_ohv256_ss_output<P: Party, Rec: MulTripleRecorder<BsBool16>>(party: &mut P, triple_rec: &mut Rec, n: usize, random_bits: [Vec<RssShare<BsBool16>>; 8]) -> MpcResult<Vec<RndOhv256OutputSS>> {
    let n16 = random_bits[0].len();
    debug_assert!(random_bits.iter().all(|v| v.len() == n16));
    debug_assert_eq!(n16, n.div_ceil(16));

    let [r0, r1, r2, r3, r4, r5, r6, r7] = random_bits;
    
    // these two can also be realized in one call to generate_ohv_16_bitslice with double the size
    let lower = wollut16::offline::generate_ohv16_bitslice(party, triple_rec, &r0, &r1, &r2, &r3)?;
    let upper = wollut16::offline::generate_ohv16_bitslice(party, triple_rec, &r4, &r5, &r6, &r7)?;

    // let ohv16_time = ohv16_time.elapsed();
    Ok(tensor_two_ohv16(party, lower, upper, [r0, r1, r2, r3, r4, r5, r6, r7], n))
}

/// bits are in lsb-first order
fn generate_ohv256_output<P: Party, Rec: BitStringMulTripleRecorder>(
    party: &mut P,
    mul_triple_recorder: &mut Rec,
    bits: Vec<Vec<RssShare<BsBool16>>>,
) -> MpcResult<Vec<RndOhv256Output>> {
    debug_assert_eq!(bits.len(), 8);
    let rand = un_bitslice8(&bits);
    let ohv256 = generate_ohv(party, mul_triple_recorder, bits, 256)?;
    let output = util::un_bitslice::un_bitslice(&ohv256);
    Ok(rand
        .into_iter()
        .zip(output)
        .map(|(rand_rss, (ohv_si, ohv_sii))| RndOhv256Output {
            random_si: rand_rss.si,
            random_sii: rand_rss.sii,
            si: ohv_si,
            sii: ohv_sii,
        })
        .collect())
}

/// bits are in lsb-first order
pub fn generate_ohv<P: Party, Rec: BitStringMulTripleRecorder>(
    party: &mut P,
    mul_triple_recorder: &mut Rec,
    mut bits: Vec<Vec<RssShare<BsBool16>>>,
    n: usize,
) -> MpcResult<Vec<Vec<RssShare<BsBool16>>>> {
    if n == 2 {
        debug_assert_eq!(bits.len(), 1);
        let b = bits[0].clone();
        let b_prime = b
            .iter()
            .map(|rss| *rss + party.constant(BsBool16::ONE))
            .collect();
        Ok(vec![b_prime, b])
    } else {
        let msb = bits.remove(bits.len() - 1);
        let f = generate_ohv(party, mul_triple_recorder, bits, n / 2)?;
        // Mult
        let e_rest = simple_mul(party, mul_triple_recorder, &msb, &f[..=f.len() - 2])?;
        let mut sum_e = Vec::with_capacity(msb.len());
        for i in 0..msb.len() {
            let mut sum = RssShare::from(BsBool16::ZERO, BsBool16::ZERO);
            e_rest.iter().for_each(|v| sum += v[i]);
            sum_e.push(sum);
        }
        let mut e_last = sum_e;
        e_last
            .iter_mut()
            .zip(msb)
            .for_each(|(e_sum, v_k)| *e_sum = v_k - *e_sum);
        let mut res = Vec::with_capacity(n);
        izip!(f, e_rest.iter().chain(iter::once(&e_last))).for_each(|(f, e)| {
            debug_assert_eq!(f.len(), e.len());
            res.push(
                f.into_iter()
                    .zip(e)
                    .map(|(el_f, el_e)| el_f - *el_e)
                    .collect_vec(),
            );
        });
        res.extend(e_rest.into_iter().chain(iter::once(e_last)));
        Ok(res)
    }
}

fn simple_mul<P: Party, Rec: BitStringMulTripleRecorder>(
    party: &mut P,
    mul_triple_recorder: &mut Rec,
    msb: &Vec<RssShare<BsBool16>>,
    other: &[Vec<RssShare<BsBool16>>],
) -> MpcResult<Vec<Vec<RssShare<BsBool16>>>> {
    let ai_bit = msb.iter().map(|rss| rss.si).collect_vec();
    let aii_bit = msb.iter().map(|rss| rss.sii).collect_vec();
    let ai = repeat_n(&ai_bit, other.len())
        .flat_map(|vec| vec.iter().copied())
        .collect_vec();
    let aii = repeat_n(&aii_bit, other.len())
        .flat_map(|vec| vec.iter().copied())
        .collect_vec();
    let bi = other
        .iter()
        .flat_map(|rss_vec| rss_vec.iter().map(|rss| rss.si))
        .collect_vec();
    let bii = other
        .iter()
        .flat_map(|rss_vec| rss_vec.iter().map(|rss| rss.sii))
        .collect_vec();
    let mut ci = vec![BsBool16::ZERO; other.len() * msb.len()];
    let mut cii = vec![BsBool16::ZERO; other.len() * msb.len()];
    chida::online::mul_no_sync(party, &mut ci, &mut cii, &ai, &aii, &bi, &bii)?;
    mul_triple_recorder.record_bit_bitstring_triple(msb.len(), &ai_bit, &aii_bit, &bi, &bii, &ci, &cii);
    let drain_ci = ci.into_iter();
    let drain_cii = cii.into_iter();
    let res = izip!(
        drain_ci.chunks(msb.len()).into_iter(),
        drain_cii.chunks(msb.len()).into_iter()
    )
    .map(|(ci, cii)| {
        izip!(ci, cii)
            .map(|(si, sii)| RssShare::from(si, sii))
            .collect_vec()
    })
    .collect_vec();
    Ok(res)
}

fn un_bitslice8(bs: &[Vec<RssShare<BsBool16>>]) -> Vec<RssShare<GF8>> {
    debug_assert_eq!(bs.len(), 8);
    let mut res = vec![(0u8, 0u8); bs[0].len() * 16];
    for (i, bit) in bs.iter().enumerate().take(8) {
        for (j, bit_j) in bit.iter().enumerate() {
            for k in 0..16 {
                let mut si = res[16 * j + k].0;
                let mut sii = res[16 * j + k].1;
                si |= (((bit_j.si.as_u16() >> k) & 0x1) << i) as u8;
                sii |= (((bit_j.sii.as_u16() >> k) & 0x1) << i) as u8;
                res[16 * j + k].0 = si;
                res[16 * j + k].1 = sii;
            }
        }
    }
    res.into_iter()
        .map(|(si, sii)| RssShare::from(GF8(si), GF8(sii)))
        .collect()
}

#[cfg(test)]
mod test {
    use itertools::{izip, repeat_n, Itertools};
    use rand::{thread_rng, CryptoRng, Rng};
    use crate::rep3_core::{test::TestSetup, share::{HasZero, RssShare, RssShareVec}};

    use crate::{
        chida::{online::test::ChidaSetup, ChidaParty},
        lut256::{
            offline::{generate_ohv256_output, generate_ohv256_ss_output, generate_rndohv256, generate_rndohv256_mt, generate_rndohv256_ss, generate_rndohv256_ss_mt},
            RndOhv,
        },
        share::{
            bs_bool16::BsBool16,
            gf8::GF8,
            test::{assert_eq, consistent, secret_share_vector},
            Field,
        }, util::mul_triple_vec::{MulTripleVector, NoMulTripleRecording},
    };

    use super::{generate_ohv, un_bitslice8};

    fn secret_share_vecvec<R: Rng + CryptoRng, F: Field>(
        rng: &mut R,
        v: &Vec<Vec<F>>,
    ) -> (
        Vec<RssShareVec<F>>,
        Vec<RssShareVec<F>>,
        Vec<RssShareVec<F>>,
    ) {
        let mut s1 = Vec::with_capacity(v.len());
        let mut s2 = Vec::with_capacity(v.len());
        let mut s3 = Vec::with_capacity(v.len());
        for i in 0..v.len() {
            let (rss1, rss2, rss3) = secret_share_vector(rng, &v[i]);
            s1.push(rss1);
            s2.push(rss2);
            s3.push(rss3);
        }
        (s1, s2, s3)
    }

    // ohv bits are in lsb-first order
    fn check_ohv_correct(
        ohv_bits1: &[RssShare<BsBool16>],
        ohv_bits2: &[RssShare<BsBool16>],
        ohv_bits3: &[RssShare<BsBool16>],
        expected: usize,
    ) {
        assert_eq!(ohv_bits1.len(), ohv_bits2.len());
        assert_eq!(ohv_bits1.len(), ohv_bits3.len());
        let reconstructed = izip!(ohv_bits1, ohv_bits2, ohv_bits3)
            .map(|(b1, b2, b3)| {
                consistent(b1, b2, b3);
                let bs = b1.si + b2.si + b3.si;
                // this check only works of bs = 0xffff or 0x0000
                assert!(bs == BsBool16::ZERO || bs == BsBool16::ONE);
                bs
            })
            .collect_vec();

        assert_eq!(reconstructed[expected], BsBool16::ONE);
        for i in 0..reconstructed.len() {
            if i != expected {
                assert_eq!(reconstructed[i], BsBool16::ZERO);
            }
        }
    }

    fn transpose<F: Field>(v: Vec<RssShareVec<F>>) -> Vec<RssShareVec<F>> {
        let simd = v[0].len();
        assert!(v.iter().all(|vx| vx.len() == simd));
        let mut outer = Vec::with_capacity(simd);
        for i in 0..simd {
            outer.push(v.iter().map(|vx| vx[i]).collect_vec());
        }
        outer
    }

    #[test]
    fn test_unbitslice8() {
        let input = vec![
            vec![
                BsBool16::new(0b1010_1010_1010_1010),
                BsBool16::new(0b1010_1010_1010_1010),
            ],
            vec![
                BsBool16::new(0b1100_1100_1100_1100),
                BsBool16::new(0b1100_1100_1100_1100),
            ],
            vec![
                BsBool16::new(0b1111_0000_1111_0000),
                BsBool16::new(0b1111_0000_1111_0000),
            ],
            vec![
                BsBool16::new(0b1111_1111_0000_0000),
                BsBool16::new(0b1111_1111_0000_0000),
            ],
            vec![
                BsBool16::new(0b0000_0000_0000_0000),
                BsBool16::new(0b1111_1111_1111_1111),
            ],
            vec![
                BsBool16::new(0b0000_0000_0000_0000),
                BsBool16::new(0b0000_0000_0000_0000),
            ],
            vec![
                BsBool16::new(0b0000_0000_0000_0000),
                BsBool16::new(0b0000_0000_0000_0000),
            ],
            vec![
                BsBool16::new(0b0000_0000_0000_0000),
                BsBool16::new(0b0000_0000_0000_0000),
            ],
        ];
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let output1 = un_bitslice8(&shares.0);
        let output2 = un_bitslice8(&shares.1);
        let output3 = un_bitslice8(&shares.2);
        assert_eq!(output1.len(), 32);
        assert_eq!(output2.len(), 32);
        assert_eq!(output3.len(), 32);
        izip!(output1, output2, output3)
            .enumerate()
            .for_each(|(i, (o1, o2, o3))| {
                consistent(&o1, &o2, &o3);
                assert_eq(o1, o2, o3, GF8(i as u8));
            });
    }

    #[test]
    fn generate_ohv2() {
        let input = vec![vec![BsBool16::ZERO, BsBool16::ONE]];
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let program = |share: Vec<Vec<RssShare<BsBool16>>>| {
            move |p: &mut ChidaParty| generate_ohv(p.as_party_mut(), &mut NoMulTripleRecording, share, 2).unwrap()
        };
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(shares.0), program(shares.1), program(shares.2));
        assert_eq!(ohv1.len(), 2);
        assert_eq!(ohv2.len(), 2);
        assert_eq!(ohv3.len(), 2);
        let simd = input[0].len();
        assert!(ohv1.iter().all(|vec| vec.len() == simd));
        assert!(ohv2.iter().all(|vec| vec.len() == simd));
        assert!(ohv3.iter().all(|vec| vec.len() == simd));

        let shares1 = transpose(ohv1);
        let shares2 = transpose(ohv2);
        let shares3 = transpose(ohv3);
        let expected = [0, 1];
        izip!(shares1, shares2, shares3, expected).for_each(|(s1, s2, s3, expected)| {
            check_ohv_correct(&s1, &s2, &s3, expected);
        });
    }

    #[test]
    fn generate_ohv4() {
        let input = vec![
            vec![BsBool16::ZERO, BsBool16::ONE, BsBool16::ZERO, BsBool16::ONE],
            vec![BsBool16::ZERO, BsBool16::ZERO, BsBool16::ONE, BsBool16::ONE],
        ];
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let program = |share: Vec<Vec<RssShare<BsBool16>>>| {
            move |p: &mut ChidaParty| generate_ohv(p.as_party_mut(), &mut NoMulTripleRecording, share, 4).unwrap()
        };
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(shares.0), program(shares.1), program(shares.2));
        assert_eq!(ohv1.len(), 4);
        assert_eq!(ohv2.len(), 4);
        assert_eq!(ohv3.len(), 4);
        let simd = input[0].len();
        assert!(ohv1.iter().all(|vec| vec.len() == simd));
        assert!(ohv2.iter().all(|vec| vec.len() == simd));
        assert!(ohv3.iter().all(|vec| vec.len() == simd));

        let shares1 = transpose(ohv1);
        let shares2 = transpose(ohv2);
        let shares3 = transpose(ohv3);
        let expected = [0, 1, 2, 3];
        izip!(shares1, shares2, shares3, expected).for_each(|(s1, s2, s3, expected)| {
            check_ohv_correct(&s1, &s2, &s3, expected);
        });
    }

    #[test]
    fn generate_ohv8() {
        let input = vec![
            vec![
                BsBool16::ZERO,
                BsBool16::ONE,
                BsBool16::ZERO,
                BsBool16::ONE,
                BsBool16::ZERO,
                BsBool16::ONE,
                BsBool16::ZERO,
                BsBool16::ONE,
            ],
            vec![
                BsBool16::ZERO,
                BsBool16::ZERO,
                BsBool16::ONE,
                BsBool16::ONE,
                BsBool16::ZERO,
                BsBool16::ZERO,
                BsBool16::ONE,
                BsBool16::ONE,
            ],
            vec![
                BsBool16::ZERO,
                BsBool16::ZERO,
                BsBool16::ZERO,
                BsBool16::ZERO,
                BsBool16::ONE,
                BsBool16::ONE,
                BsBool16::ONE,
                BsBool16::ONE,
            ],
        ];
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let program = |share: Vec<Vec<RssShare<BsBool16>>>| {
            move |p: &mut ChidaParty| generate_ohv(p.as_party_mut(), &mut NoMulTripleRecording, share, 8).unwrap()
        };
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(shares.0), program(shares.1), program(shares.2));
        assert_eq!(ohv1.len(), 8);
        assert_eq!(ohv2.len(), 8);
        assert_eq!(ohv3.len(), 8);
        let simd = input[0].len();
        assert!(ohv1.iter().all(|vec| vec.len() == simd));
        assert!(ohv2.iter().all(|vec| vec.len() == simd));
        assert!(ohv3.iter().all(|vec| vec.len() == simd));

        let shares1 = transpose(ohv1);
        let shares2 = transpose(ohv2);
        let shares3 = transpose(ohv3);
        let expected = [0, 1, 2, 3, 4, 5, 6, 7];
        izip!(shares1, shares2, shares3, expected).for_each(|(s1, s2, s3, expected)| {
            check_ohv_correct(&s1, &s2, &s3, expected);
        });
    }

    fn generate_ohv_input(k: usize, n: usize) -> Vec<Vec<BsBool16>> {
        assert_eq!(1 << k, n);
        let mut bits = Vec::with_capacity(k);
        for _ in 0..k {
            bits.push(Vec::with_capacity(n));
        }
        for i in 0..n {
            for j in 0..k {
                let el = if ((i >> j) & 0x1) == 0x1 {
                    BsBool16::ONE
                } else {
                    BsBool16::ZERO
                };
                bits[j].push(el);
            }
        }
        bits
    }

    #[test]
    fn generate_ohv16() {
        let input = generate_ohv_input(4, 16);
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let program = |share: Vec<Vec<RssShare<BsBool16>>>| {
            move |p: &mut ChidaParty| generate_ohv(p.as_party_mut(), &mut NoMulTripleRecording, share, 16).unwrap()
        };
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(shares.0), program(shares.1), program(shares.2));
        assert_eq!(ohv1.len(), 16);
        assert_eq!(ohv2.len(), 16);
        assert_eq!(ohv3.len(), 16);
        let simd = input[0].len();
        assert!(ohv1.iter().all(|vec| vec.len() == simd));
        assert!(ohv2.iter().all(|vec| vec.len() == simd));
        assert!(ohv3.iter().all(|vec| vec.len() == simd));

        let shares1 = transpose(ohv1);
        let shares2 = transpose(ohv2);
        let shares3 = transpose(ohv3);
        let expected = 0..16;
        izip!(shares1, shares2, shares3, expected).for_each(|(s1, s2, s3, expected)| {
            check_ohv_correct(&s1, &s2, &s3, expected);
        });
    }

    #[test]
    fn generate_ohv32() {
        let input = generate_ohv_input(5, 32);
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let program = |share: Vec<Vec<RssShare<BsBool16>>>| {
            move |p: &mut ChidaParty| generate_ohv(p.as_party_mut(), &mut NoMulTripleRecording, share, 32).unwrap()
        };
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(shares.0), program(shares.1), program(shares.2));
        assert_eq!(ohv1.len(), 32);
        assert_eq!(ohv2.len(), 32);
        assert_eq!(ohv3.len(), 32);
        let simd = input[0].len();
        assert!(ohv1.iter().all(|vec| vec.len() == simd));
        assert!(ohv2.iter().all(|vec| vec.len() == simd));
        assert!(ohv3.iter().all(|vec| vec.len() == simd));

        let shares1 = transpose(ohv1);
        let shares2 = transpose(ohv2);
        let shares3 = transpose(ohv3);
        let expected = 0..32;
        izip!(shares1, shares2, shares3, expected).for_each(|(s1, s2, s3, expected)| {
            check_ohv_correct(&s1, &s2, &s3, expected);
        });
    }

    #[test]
    fn generate_ohv64() {
        let input = generate_ohv_input(6, 64);
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let program = |share: Vec<Vec<RssShare<BsBool16>>>| {
            move |p: &mut ChidaParty| generate_ohv(p.as_party_mut(), &mut NoMulTripleRecording, share, 64).unwrap()
        };
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(shares.0), program(shares.1), program(shares.2));
        assert_eq!(ohv1.len(), 64);
        assert_eq!(ohv2.len(), 64);
        assert_eq!(ohv3.len(), 64);
        let simd = input[0].len();
        assert!(ohv1.iter().all(|vec| vec.len() == simd));
        assert!(ohv2.iter().all(|vec| vec.len() == simd));
        assert!(ohv3.iter().all(|vec| vec.len() == simd));

        let shares1 = transpose(ohv1);
        let shares2 = transpose(ohv2);
        let shares3 = transpose(ohv3);
        let expected = 0..64;
        izip!(shares1, shares2, shares3, expected).for_each(|(s1, s2, s3, expected)| {
            check_ohv_correct(&s1, &s2, &s3, expected);
        });
    }

    #[test]
    fn generate_ohv128() {
        let input = generate_ohv_input(7, 128);
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let program = |share: Vec<Vec<RssShare<BsBool16>>>| {
            move |p: &mut ChidaParty| generate_ohv(p.as_party_mut(), &mut NoMulTripleRecording, share, 128).unwrap()
        };
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(shares.0), program(shares.1), program(shares.2));
        assert_eq!(ohv1.len(), 128);
        assert_eq!(ohv2.len(), 128);
        assert_eq!(ohv3.len(), 128);
        let simd = input[0].len();
        assert!(ohv1.iter().all(|vec| vec.len() == simd));
        assert!(ohv2.iter().all(|vec| vec.len() == simd));
        assert!(ohv3.iter().all(|vec| vec.len() == simd));

        let shares1 = transpose(ohv1);
        let shares2 = transpose(ohv2);
        let shares3 = transpose(ohv3);
        let expected = 0..128;
        izip!(shares1, shares2, shares3, expected).for_each(|(s1, s2, s3, expected)| {
            check_ohv_correct(&s1, &s2, &s3, expected);
        });
    }

    #[test]
    fn generate_ohv256() {
        let input = generate_ohv_input(8, 256);
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let program = |share: Vec<Vec<RssShare<BsBool16>>>| {
            move |p: &mut ChidaParty| generate_ohv(p.as_party_mut(), &mut NoMulTripleRecording, share, 256).unwrap()
        };
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(shares.0), program(shares.1), program(shares.2));
        assert_eq!(ohv1.len(), 256);
        assert_eq!(ohv2.len(), 256);
        assert_eq!(ohv3.len(), 256);
        let simd = input[0].len();
        assert!(ohv1.iter().all(|vec| vec.len() == simd));
        assert!(ohv2.iter().all(|vec| vec.len() == simd));
        assert!(ohv3.iter().all(|vec| vec.len() == simd));

        let shares1 = transpose(ohv1);
        let shares2 = transpose(ohv2);
        let shares3 = transpose(ohv3);
        let expected = 0..256;
        izip!(shares1, shares2, shares3, expected).for_each(|(s1, s2, s3, expected)| {
            check_ohv_correct(&s1, &s2, &s3, expected);
        });
    }

    fn reconstruct_and_check_rndohv(
        mut ohv1: RndOhv,
        ohv2: RndOhv,
        ohv3: RndOhv,
        expected_bit: u8,
    ) {
        for i in 0..4 {
            ohv1.0[i] ^= ohv2.0[i] ^ ohv3.0[i];
        }
        let ohv = ohv1.0;
        if expected_bit < 64 {
            assert_eq!([1 << expected_bit, 0, 0, 0], ohv);
        } else if expected_bit < 128 {
            assert_eq!([0, 1 << (expected_bit - 64), 0, 0], ohv);
        } else if expected_bit < 192 {
            assert_eq!([0, 0, 1 << (expected_bit - 128), 0], ohv);
        } else {
            assert_eq!([0, 0, 0, 1 << (expected_bit - 192)], ohv);
        }
    }

    #[test]
    fn generate_ohv_output256() {
        let input = generate_ohv_input(8, 256);
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let program = |share: Vec<Vec<RssShare<BsBool16>>>| {
            move |p: &mut ChidaParty| generate_ohv256_output(p.as_party_mut(), &mut NoMulTripleRecording, share).unwrap()
        };
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(shares.0), program(shares.1), program(shares.2));
        assert_eq!(ohv1.len(), 256 * 16);
        assert_eq!(ohv2.len(), 256 * 16);
        assert_eq!(ohv3.len(), 256 * 16);
        let expected = (0..256).flat_map(|i| repeat_n(i, 16));
        izip!(ohv1, ohv2, ohv3, expected).for_each(|(s1, s2, s3, expected)| {
            consistent(
                &RssShare::from(s1.random_si, s1.random_sii),
                &RssShare::from(s2.random_si, s2.random_sii),
                &RssShare::from(s3.random_si, s3.random_sii),
            );
            // check consistency of bitvec
            assert_eq!(s1.sii.0, s2.si.0);
            assert_eq!(s2.sii.0, s3.si.0);
            assert_eq!(s3.sii.0, s1.si.0);
            // random GF8 reconstructs to expected
            assert_eq!(
                s1.random_si + s2.random_si + s3.random_si,
                GF8(expected as u8)
            );
            // reconstructed bitvec has correct bit set
            reconstruct_and_check_rndohv(s1.si, s2.si, s3.si, expected as u8);
        });
    }

    #[test]
    fn rnd_ohv256() {
        const N: usize = 145;
        let program = || |p: &mut ChidaParty| generate_rndohv256(p.as_party_mut(), &mut NoMulTripleRecording, N).unwrap();
        let ((ohv1, _), (ohv2, _), (ohv3, _)) = ChidaSetup::localhost_setup(program(), program(), program());
        assert_eq!(ohv1.len(), N);
        assert_eq!(ohv2.len(), N);
        assert_eq!(ohv3.len(), N);
        izip!(ohv1, ohv2, ohv3).for_each(|(s1, s2, s3)| {
            consistent(
                &RssShare::from(s1.random_si, s1.random_sii),
                &RssShare::from(s2.random_si, s2.random_sii),
                &RssShare::from(s3.random_si, s3.random_sii),
            );
            // check consistency of bitvec
            assert_eq!(s1.sii.0, s2.si.0);
            assert_eq!(s2.sii.0, s3.si.0);
            assert_eq!(s3.sii.0, s1.si.0);
            // reconstruct random GF8
            let index = s1.random_si + s2.random_si + s3.random_si;
            // reconstructed bitvec has correct bit set
            reconstruct_and_check_rndohv(s1.si, s2.si, s3.si, index.0);
        });
    }

    #[test]
    fn test_generate_ohv_input() {
        assert_eq!(
            generate_ohv_input(1, 2),
            vec![vec![BsBool16::ZERO, BsBool16::ONE],]
        );
        assert_eq!(
            generate_ohv_input(3, 8),
            vec![
                vec![
                    BsBool16::ZERO,
                    BsBool16::ONE,
                    BsBool16::ZERO,
                    BsBool16::ONE,
                    BsBool16::ZERO,
                    BsBool16::ONE,
                    BsBool16::ZERO,
                    BsBool16::ONE
                ],
                vec![
                    BsBool16::ZERO,
                    BsBool16::ZERO,
                    BsBool16::ONE,
                    BsBool16::ONE,
                    BsBool16::ZERO,
                    BsBool16::ZERO,
                    BsBool16::ONE,
                    BsBool16::ONE
                ],
                vec![
                    BsBool16::ZERO,
                    BsBool16::ZERO,
                    BsBool16::ZERO,
                    BsBool16::ZERO,
                    BsBool16::ONE,
                    BsBool16::ONE,
                    BsBool16::ONE,
                    BsBool16::ONE
                ],
            ]
        );
    }

    #[test]
    fn rnd_ohv256_mt() {
        const N: usize = 2367;
        const N_THREADS: usize = 3;
        let program = || |p: &mut ChidaParty| generate_rndohv256_mt::<_, BsBool16>(p.as_party_mut(), &mut NoMulTripleRecording, N).unwrap();
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup_multithreads(N_THREADS, program(), program(), program());
        assert_eq!(ohv1.len(), N);
        assert_eq!(ohv2.len(), N);
        assert_eq!(ohv3.len(), N);
        izip!(ohv1, ohv2, ohv3).for_each(|(s1, s2, s3)| {
            consistent(
                &RssShare::from(s1.random_si, s1.random_sii),
                &RssShare::from(s2.random_si, s2.random_sii),
                &RssShare::from(s3.random_si, s3.random_sii),
            );
            // check consistency of bitvec
            assert_eq!(s1.sii.0, s2.si.0);
            assert_eq!(s2.sii.0, s3.si.0);
            assert_eq!(s3.sii.0, s1.si.0);
            // reconstruct random GF8
            let index = s1.random_si + s2.random_si + s3.random_si;
            // reconstructed bitvec has correct bit set
            reconstruct_and_check_rndohv(s1.si, s2.si, s3.si, index.0);
        });
    }

    fn assert_len<F: Field>(rec: &MulTripleVector<F>, len: usize) {
        assert_eq!(rec.ai().len(), len);
        assert_eq!(rec.aii().len(), len);
        assert_eq!(rec.bi().len(), len);
        assert_eq!(rec.bii().len(), len);
        assert_eq!(rec.ci().len(), len);
        assert_eq!(rec.cii().len(), len);
    }

    #[test]
    fn test_rndohv256_registers_correct_triples() {
        const N: usize = 145;
        let program = || {
            |p: &mut ChidaParty| {
                let mut rec = MulTripleVector::new();
                generate_rndohv256(p.as_party_mut(), &mut rec, N).unwrap();
                rec
            }
        };
        let ((mut rec1, _), (mut rec2, _), (mut rec3, _)) = ChidaSetup::localhost_setup(program(), program(), program());
        // ohv256 should register 8 GF(2^64) triples per instance (bitsliced in blocks of 16)
        assert_len(&rec1, N.div_ceil(16)*16*8); // N * 8
        assert_len(&rec2, N.div_ceil(16)*16*8);
        assert_len(&rec3, N.div_ceil(16)*16*8);

        izip!(rec1.drain_into_rss_iter(), rec2.drain_into_rss_iter(), rec3.drain_into_rss_iter()).for_each(|(trip1, trip2, trip3)| {
            consistent(&trip1.0, &trip2.0, &trip3.0);
            consistent(&trip1.1, &trip2.1, &trip3.1);
            consistent(&trip1.2, &trip2.2, &trip3.2);
            let a = trip1.0.si + trip2.0.si + trip3.0.si;
            let b = trip1.1.si + trip2.1.si + trip3.1.si;
            assert_eq(trip1.2, trip2.2, trip3.2, a*b);
        });
    }

    fn into_8_array<T>(vec: Vec<T>) -> [T; 8] {
        assert_eq!(vec.len(), 8);
        let mut it = vec.into_iter();
        [it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap(), it.next().unwrap(),]
    }

    #[test]
    fn ohv256_ss_output() {
        let input = generate_ohv_input(8, 256);
        let mut rng = thread_rng();
        let shares = secret_share_vecvec(&mut rng, &input);
        let program = |share: [Vec<RssShare<BsBool16>>; 8]| {
            move |p: &mut ChidaParty| generate_ohv256_ss_output(p.as_party_mut(), &mut NoMulTripleRecording, 256*16, share).unwrap()
        };

        let share1 = into_8_array(shares.0);
        let share2 = into_8_array(shares.1);
        let share3 = into_8_array(shares.2);

        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(share1), program(share2), program(share3));
        assert_eq!(ohv1.len(), 256*16);
        assert_eq!(ohv2.len(), 256*16);
        assert_eq!(ohv3.len(), 256*16);
        let expected = (0..256).flat_map(|i| repeat_n(i, 16));
        izip!(ohv1, ohv2, ohv3, expected).for_each(|(s1, s2, s3, expected)| {
            consistent(
                &RssShare::from(s1.random_si, s1.random_sii),
                &RssShare::from(s2.random_si, s2.random_sii),
                &RssShare::from(s3.random_si, s3.random_sii),
            );
            // random GF8 reconstructs to expected
            assert_eq!(
                s1.random_si + s2.random_si + s3.random_si,
                GF8(expected as u8)
            );
            // reconstructed bitvec has correct bit set
            reconstruct_and_check_rndohv(s1.ohv, s2.ohv, s3.ohv, expected as u8);
        });
    }

    #[test]
    fn rnd_ohv256_ss() {
        const N: usize = 147;
        let program = || {
            move |p: &mut ChidaParty| generate_rndohv256_ss(p.as_party_mut(), &mut NoMulTripleRecording, N).unwrap()
        };

        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup(program(), program(), program());
        assert_eq!(ohv1.len(), N);
        assert_eq!(ohv2.len(), N);
        assert_eq!(ohv3.len(), N);
        izip!(ohv1, ohv2, ohv3).for_each(|(s1, s2, s3)| {
            consistent(
                &RssShare::from(s1.random_si, s1.random_sii),
                &RssShare::from(s2.random_si, s2.random_sii),
                &RssShare::from(s3.random_si, s3.random_sii),
            );
            // reconstruct random GF8
            let index = s1.random_si + s2.random_si + s3.random_si;
            // reconstructed bitvec has correct bit set
            reconstruct_and_check_rndohv(s1.ohv, s2.ohv, s3.ohv, index.0);
        });
    }

    #[test]
    fn rnd_ohv256_ss_mt() {
        const N: usize = 2367;
        const N_THREADS: usize = 3;
        let program = || |p: &mut ChidaParty| generate_rndohv256_ss_mt(p.as_party_mut(), &mut NoMulTripleRecording, N).unwrap();
        let ((ohv1, _), (ohv2, _), (ohv3, _)) =
            ChidaSetup::localhost_setup_multithreads(N_THREADS, program(), program(), program());
        assert_eq!(ohv1.len(), N);
        assert_eq!(ohv2.len(), N);
        assert_eq!(ohv3.len(), N);
        izip!(ohv1, ohv2, ohv3).for_each(|(s1, s2, s3)| {
            consistent(
                &RssShare::from(s1.random_si, s1.random_sii),
                &RssShare::from(s2.random_si, s2.random_sii),
                &RssShare::from(s3.random_si, s3.random_sii),
            );
            // reconstruct random GF8
            let index = s1.random_si + s2.random_si + s3.random_si;
            // reconstructed bitvec has correct bit set
            reconstruct_and_check_rndohv(s1.ohv, s2.ohv, s3.ohv, index.0);
        });
    }
}
