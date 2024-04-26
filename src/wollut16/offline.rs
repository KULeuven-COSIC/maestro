//! This module contains the offline phase components.
//!
//! This is primarily the preprocessing protocol for the one-hot vector encoding.
use itertools::izip;
use rayon::prelude::*;

use crate::{
    chida,
    party::{error::MpcResult, MainParty, MulTripleRecorder, Party},
    share::{bs_bool16::BsBool16, gf4::GF4, Field, RssShare},
    wollut16::{RndOhv16, RndOhvOutput},
};
#[cfg(feature = "verbose-timing")]
use {crate::party::PARTY_TIMER, std::time::Instant};

fn map_si(rss: &RssShare<BsBool16>) -> &BsBool16 {
    &rss.si
}

fn map_sii(rss: &RssShare<BsBool16>) -> &BsBool16 {
    &rss.sii
}

fn fill<'a>(slice: &mut [BsBool16], it: impl Iterator<Item = &'a BsBool16>) {
    slice.iter_mut().zip(it).for_each(|(dst, el)| *dst = *el);
}

fn inner_product(
    elements: &[&[RssShare<BsBool16>]],
    n: usize,
    start: RssShare<BsBool16>,
    selector: &[bool],
) -> Vec<RssShare<BsBool16>> {
    debug_assert_eq!(elements.len(), selector.len());
    let mut res = vec![start; n];
    for (i, elem_i) in elements.iter().enumerate() {
        if selector[i] {
            for (j, res_j) in res.iter_mut().enumerate() {
                *res_j += elem_i[j];
            }
        }
    }
    res
}

const SELECTOR_IDX_0: [bool; 15] = [
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
];
const SELECTOR_IDX_1: [bool; 15] = [
    true, false, true, false, true, false, true, false, true, false, true, false, true, false, true,
];
const SELECTOR_IDX_2: [bool; 15] = [
    false, true, true, false, false, true, true, false, false, true, true, false, false, true, true,
];
const SELECTOR_IDX_3: [bool; 15] = [
    false, false, true, false, false, false, true, false, false, false, true, false, false, false,
    true,
];
const SELECTOR_IDX_4: [bool; 15] = [
    false, false, false, true, true, true, true, false, false, false, false, true, true, true, true,
];
const SELECTOR_IDX_5: [bool; 15] = [
    false, false, false, false, true, false, true, false, false, false, false, false, true, false,
    true,
];
const SELECTOR_IDX_6: [bool; 15] = [
    false, false, false, false, false, true, true, false, false, false, false, false, false, true,
    true,
];
const SELECTOR_IDX_7: [bool; 15] = [
    false, false, false, false, false, false, true, false, false, false, false, false, false,
    false, true,
];
const SELECTOR_IDX_8: [bool; 15] = [
    false, false, false, false, false, false, false, true, true, true, true, true, true, true, true,
];
const SELECTOR_IDX_9: [bool; 15] = [
    false, false, false, false, false, false, false, false, true, false, true, false, true, false,
    true,
];
const SELECTOR_IDX_10: [bool; 15] = [
    false, false, false, false, false, false, false, false, false, true, true, false, false, true,
    true,
];
const SELECTOR_IDX_11: [bool; 15] = [
    false, false, false, false, false, false, false, false, false, false, true, false, false,
    false, true,
];
const SELECTOR_IDX_12: [bool; 15] = [
    false, false, false, false, false, false, false, false, false, false, false, true, true, true,
    true,
];
const SELECTOR_IDX_13: [bool; 15] = [
    false, false, false, false, false, false, false, false, false, false, false, false, true,
    false, true,
];
const SELECTOR_IDX_14: [bool; 15] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false,
    true, true,
];
const SELECTOR_IDX_15: [bool; 15] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, true,
];

/// This function implements the random one-hot vector generation as in `Protocol 6`.
pub fn generate_random_ohv16<P: Party, Rec: MulTripleRecorder<BsBool16>>(party: &mut P, triple_rec: &mut Rec, n: usize) -> MpcResult<Vec<RndOhvOutput>> {
    let n16 = if n % 16 == 0 { n / 16 } else { n / 16 + 1 };
    // generate 4 random bits
    let r0 = party.generate_random(n16);
    let r1 = party.generate_random(n16);
    let r2 = party.generate_random(n16);
    let r3 = party.generate_random(n16);
    generate_ohv16(party, triple_rec, n, r0, r1, r2, r3)
}

/// This function is a multi-threaded version of the random one-hot vector generation as in `Protocol 6`.
pub fn generate_random_ohv16_mt<'a, Rec: MulTripleRecorder<BsBool16>>(party: &'a mut MainParty, triple_rec: &mut Rec, n: usize) -> MpcResult<Vec<RndOhvOutput>> {
    let n16 = if n % 16 == 0 { n / 16 } else { n / 16 + 1};
    let ranges = party.split_range_equally(n16);
    let threads = party.create_thread_parties_with_additional_data(ranges, |start, end| Some(triple_rec.create_thread_mul_triple_recorder(start, end)));

    let mut rnd_ohv = Vec::with_capacity(threads.len());

    party.run_in_threadpool(|| {
        threads.into_par_iter().map(|mut thread_party| {
            // generate 4 random bits
            let task_n = thread_party.task_size();
            let r0 = thread_party.generate_random(task_n);
            let r1 = thread_party.generate_random(task_n);
            let r2 = thread_party.generate_random(task_n);
            let r3 = thread_party.generate_random(task_n);
            let mut rec = thread_party.additional_data.take().unwrap();
            let rnd_ohv = generate_ohv16(&mut thread_party, &mut rec, task_n*16, r0, r1, r2, r3).unwrap();
            (rnd_ohv, rec)
        }).collect_into_vec(&mut rnd_ohv);
        Ok(())
    })?;

    let (rnd_ohv, recs): (Vec<_>, Vec<_>) = rnd_ohv.into_iter().unzip();

    // record observed triples
    triple_rec.join_thread_mul_triple_recorders(recs);

    // make sure that only n rndohv are returned
    let rnd_ohv = rnd_ohv.into_iter().flatten().take(n).collect();
    party.wait_for_completion();
    Ok(rnd_ohv)
}

// implements Protocol 7 with fixed inputs
fn generate_ohv16<P: Party, Rec: MulTripleRecorder<BsBool16>>(party: &mut P, triple_rec: &mut Rec, n: usize, r0: Vec<RssShare<BsBool16>>, r1: Vec<RssShare<BsBool16>>, r2: Vec<RssShare<BsBool16>>, r3: Vec<RssShare<BsBool16>>) -> MpcResult<Vec<RndOhvOutput>> {
   let n16 = r0.len();
   debug_assert_eq!(n16, r1.len());
   debug_assert_eq!(n16, r2.len());
   debug_assert_eq!(n16, r3.len());

    #[cfg(feature = "verbose-timing")]
    let mul_phase = Instant::now();
    #[cfg(feature = "verbose-timing")]
    let total = mul_phase.clone();

    // Round 1: compute r_i * r_j for i=0,1,2,3 and j > i
    // fill a with r0|r0|r0|r1|r1|r2
    // fill b with r1|r2|r3|r2|r3|r3

    let mut ai = vec![BsBool16::default(); 6 * n16];
    fill(&mut ai[..n16], r0.iter().map(map_si));
    ai.copy_within(0..n16, n16);
    ai.copy_within(0..n16, 2 * n16);
    fill(&mut ai[3 * n16..4 * n16], r1.iter().map(map_si));
    ai.copy_within(3 * n16..4 * n16, 4 * n16);
    fill(&mut ai[5 * n16..], r2.iter().map(map_si));

    let mut aii = vec![BsBool16::default(); 6 * n16];
    fill(&mut aii[..n16], r0.iter().map(map_sii));
    aii.copy_within(0..n16, n16);
    aii.copy_within(0..n16, 2 * n16);
    fill(&mut aii[3 * n16..4 * n16], r1.iter().map(map_sii));
    aii.copy_within(3 * n16..4 * n16, 4 * n16);
    fill(&mut aii[5 * n16..], r2.iter().map(map_sii));

    let mut bi = vec![BsBool16::default(); 6 * n16];
    fill(&mut bi[..n16], r1.iter().map(map_si));
    fill(&mut bi[n16..2 * n16], r2.iter().map(map_si));
    fill(&mut bi[2 * n16..3 * n16], r3.iter().map(map_si));
    bi.copy_within(n16..2 * n16, 3 * n16);
    bi.copy_within(2 * n16..3 * n16, 4 * n16);
    bi.copy_within(2 * n16..3 * n16, 5 * n16);

    let mut bii = vec![BsBool16::default(); 6 * n16];
    fill(&mut bii[..n16], r1.iter().map(map_sii));
    fill(&mut bii[n16..2 * n16], r2.iter().map(map_sii));
    fill(&mut bii[2 * n16..3 * n16], r3.iter().map(map_sii));
    bii.copy_within(n16..2 * n16, 3 * n16);
    bii.copy_within(2 * n16..3 * n16, 4 * n16);
    bii.copy_within(2 * n16..3 * n16, 5 * n16);

    let mut ci = vec![BsBool16::default(); 6 * n16];
    let mut cii = vec![BsBool16::default(); 6 * n16];
    chida::online::mul_no_sync(party, &mut ci, &mut cii, &ai, &aii, &bi, &bii)?;
    triple_rec.record_mul_triple(&ai, &aii, &bi, &bii, &ci, &cii);

    // Round 2: compute (r_i * r_j) * r_k for k > j and r0r1 * r2r3
    // fill a2 with r01|r01|r02|r12|r01
    // fill b2 with  r2| r3| r3| r3|r23

    let mut a2i = vec![BsBool16::default(); 5 * n16];
    a2i[..n16].copy_from_slice(&ci[..n16]);
    a2i.copy_within(..n16, n16);
    a2i[2 * n16..3 * n16].copy_from_slice(&ci[n16..2 * n16]);
    a2i[3 * n16..4 * n16].copy_from_slice(&ci[3 * n16..4 * n16]);
    a2i.copy_within(..n16, 4 * n16);

    let mut a2ii = vec![BsBool16::default(); 5 * n16];
    a2ii[..n16].copy_from_slice(&cii[..n16]);
    a2ii.copy_within(..n16, n16);
    a2ii[2 * n16..3 * n16].copy_from_slice(&cii[n16..2 * n16]);
    a2ii[3 * n16..4 * n16].copy_from_slice(&cii[3 * n16..4 * n16]);
    a2ii.copy_within(..n16, 4 * n16);

    let mut b2i = vec![BsBool16::default(); 5 * n16];
    b2i[..n16].copy_from_slice(&ai[5 * n16..]);
    b2i[n16..2 * n16].copy_from_slice(&bi[2 * n16..3 * n16]);
    b2i.copy_within(n16..2 * n16, 2 * n16);
    b2i.copy_within(n16..2 * n16, 3 * n16);
    b2i[4 * n16..].copy_from_slice(&ci[5 * n16..]);

    let mut b2ii = vec![BsBool16::default(); 5 * n16];
    b2ii[..n16].copy_from_slice(&aii[5 * n16..]);
    b2ii[n16..2 * n16].copy_from_slice(&bii[2 * n16..3 * n16]);
    b2ii.copy_within(n16..2 * n16, 2 * n16);
    b2ii.copy_within(n16..2 * n16, 3 * n16);
    b2ii[4 * n16..].copy_from_slice(&cii[5 * n16..]);

    let mut c2i = vec![BsBool16::default(); 5 * n16];
    let mut c2ii = vec![BsBool16::default(); 5 * n16];
    chida::online::mul_no_sync(party, &mut c2i, &mut c2ii, &a2i, &a2ii, &b2i, &b2ii)?;
    triple_rec.record_mul_triple(&a2i, &a2ii, &b2i, &b2ii, &c2i, &c2ii);

    let pairs: Vec<_> = ci
        .into_iter()
        .zip(cii)
        .map(|(si, sii)| RssShare::from(si, sii))
        .collect();
    let r01 = &pairs[..n16];
    let r02 = &pairs[n16..2 * n16];
    let r03 = &pairs[2 * n16..3 * n16];
    let r12 = &pairs[3 * n16..4 * n16];
    let r13 = &pairs[4 * n16..5 * n16];
    let r23 = &pairs[5 * n16..];

    let triples: Vec<_> = c2i
        .into_iter()
        .zip(c2ii)
        .map(|(si, sii)| RssShare::from(si, sii))
        .collect();
    let r012 = &triples[..n16];
    let r013 = &triples[n16..2 * n16];
    let r023 = &triples[2 * n16..3 * n16];
    let r123 = &triples[3 * n16..4 * n16];
    let r0123 = &triples[4 * n16..];

    let elements = [
        &r0, &r1, r01, &r2, r02, r12, r012, &r3, r03, r13, r013, r23, r023, r123, r0123,
    ];

    let zero = party.constant(BsBool16::ZERO);
    let one = party.constant(BsBool16::ONE);
    let ohv_0 = inner_product(&elements, n16, one, &SELECTOR_IDX_0);
    let ohv_1 = inner_product(&elements, n16, zero, &SELECTOR_IDX_1);
    let ohv_2 = inner_product(&elements, n16, zero, &SELECTOR_IDX_2);
    let ohv_3 = inner_product(&elements, n16, zero, &SELECTOR_IDX_3);
    let ohv_4 = inner_product(&elements, n16, zero, &SELECTOR_IDX_4);
    let ohv_5 = inner_product(&elements, n16, zero, &SELECTOR_IDX_5);
    let ohv_6 = inner_product(&elements, n16, zero, &SELECTOR_IDX_6);
    let ohv_7 = inner_product(&elements, n16, zero, &SELECTOR_IDX_7);
    let ohv_8 = inner_product(&elements, n16, zero, &SELECTOR_IDX_8);
    let ohv_9 = inner_product(&elements, n16, zero, &SELECTOR_IDX_9);
    let ohv_10 = inner_product(&elements, n16, zero, &SELECTOR_IDX_10);
    let ohv_11 = inner_product(&elements, n16, zero, &SELECTOR_IDX_11);
    let ohv_12 = inner_product(&elements, n16, zero, &SELECTOR_IDX_12);
    let ohv_13 = inner_product(&elements, n16, zero, &SELECTOR_IDX_13);
    let ohv_14 = inner_product(&elements, n16, zero, &SELECTOR_IDX_14);
    let ohv_15 = inner_product(&elements, n16, zero, &SELECTOR_IDX_15);

    #[cfg(feature = "verbose-timing")]
    {
        let mul_phase = mul_phase.elapsed();
        PARTY_TIMER
            .lock()
            .unwrap()
            .report_time("prep_mul", mul_phase);
    }
    #[cfg(feature = "verbose-timing")]
    let transpose_ohv = Instant::now();

    let ohv_transposed = un_bitslice([
        ohv_0, ohv_1, ohv_2, ohv_3, ohv_4, ohv_5, ohv_6, ohv_7, ohv_8, ohv_9, ohv_10, ohv_11,
        ohv_12, ohv_13, ohv_14, ohv_15,
    ]);
    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER
        .lock()
        .unwrap()
        .report_time("prep_transpose_ohv", transpose_ohv.elapsed());
    #[cfg(feature = "verbose-timing")]
    let transpose_rand = Instant::now();

    let rand_transposed = un_bitslice4([r0, r1, r2, r3]);

    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER
        .lock()
        .unwrap()
        .report_time("prep_transpose_rand", transpose_rand.elapsed());

    let res = izip!(
        ohv_transposed.into_iter().take(n),
        rand_transposed.into_iter().take(n)
    )
    .map(|((ohv_si, ohv_sii), rand)| RndOhvOutput {
        si: ohv_si,
        sii: ohv_sii,
        random: rand.si,
    })
    .collect();

    #[cfg(feature = "verbose-timing")]
    PARTY_TIMER
        .lock()
        .unwrap()
        .report_time("prep_total", total.elapsed());

    Ok(res)
}

fn un_bitslice(bs: [Vec<RssShare<BsBool16>>; 16]) -> Vec<(RndOhv16, RndOhv16)> {
    let mut res = vec![(RndOhv16::new(0u16), RndOhv16::new(0u16)); 16 * bs[0].len()];
    for (i, bit) in bs.iter().enumerate() {
        for (j, bit_j) in bit.iter().enumerate() {
            let si = bit_j.si.as_u16();
            let sii = bit_j.sii.as_u16();
            for k in 0..16 {
                res[16 * j + k].0 .0 |= ((si >> k) & 0x1) << i;
                res[16 * j + k].1 .0 |= ((sii >> k) & 0x1) << i;
            }
        }
    }
    res
}

pub fn un_bitslice4(bs: [Vec<RssShare<BsBool16>>; 4]) -> Vec<RssShare<GF4>> {
    let mut res = vec![0u8; bs[0].len() * 16];
    for (i, bit) in bs.iter().enumerate() {
        for j in 0..bit.len() {
            for k in 0..16 {
                let mut si = res[16 * j + k] & 0x0f;
                let mut sii = res[16 * j + k] & 0xf0;
                si |= (((bit[j].si.as_u16() >> k) & 0x1) << i) as u8;
                sii |= (((bit[j].sii.as_u16() >> k) & 0x1) << (4 + i)) as u8;
                res[16 * j + k] = si | sii;
            }
        }
    }
    res.into_iter()
        .map(|x| RssShare::from(GF4::new(x & 0xf), GF4::new(x >> 4)))
        .collect()
}

#[cfg(test)]
pub mod test {
    use itertools::izip;
    use rand::thread_rng;

    use crate::{
        chida::{online::test::ChidaSetup, ChidaParty},
        party::{test::TestSetup, NoMulTripleRecording},
        share::{
            bs_bool16::BsBool16,
            gf4::GF4,
            test::{assert_eq, consistent, secret_share_vector},
            RssShare,
        },
        wollut16::{
            offline::{generate_random_ohv16, generate_random_ohv16_mt},
            RndOhvOutput,
        },
    };

    use super::{generate_ohv16, un_bitslice4};

    #[test]
    fn unbitslice4_correct() {
        let inputs = [
            vec![
                BsBool16::new(0b0101010101010101_u16.reverse_bits()),
                BsBool16::new(0b0101010101010101),
            ],
            vec![
                BsBool16::new(0b0011001100110011_u16.reverse_bits()),
                BsBool16::new(0b0011001100110011),
            ],
            vec![
                BsBool16::new(0b0000111100001111_u16.reverse_bits()),
                BsBool16::new(0b0000111100001111),
            ],
            vec![
                BsBool16::new(0b0000000011111111_u16.reverse_bits()),
                BsBool16::new(0b0000000011111111),
            ],
        ];
        let mut rng = thread_rng();
        let bit0 = secret_share_vector::<BsBool16, _>(&mut rng, &inputs[0]);
        let bit1 = secret_share_vector::<BsBool16, _>(&mut rng, &inputs[1]);
        let bit2 = secret_share_vector::<BsBool16, _>(&mut rng, &inputs[2]);
        let bit3 = secret_share_vector::<BsBool16, _>(&mut rng, &inputs[3]);
        let t1 = un_bitslice4([bit0.0, bit1.0, bit2.0, bit3.0]);
        let t2 = un_bitslice4([bit0.1, bit1.1, bit2.1, bit3.1]);
        let t3 = un_bitslice4([bit0.2, bit1.2, bit2.2, bit3.2]);
        assert_eq!(t1.len(), 32);
        assert_eq!(t2.len(), 32);
        assert_eq!(t3.len(), 32);
        for (i, (t1, t2, t3)) in izip!(t1, t2, t3).enumerate() {
            consistent(&t1, &t2, &t3);
            if i < 16 {
                assert_eq(t1, t2, t3, GF4::new(i as u8));
            } else {
                assert_eq(t1, t2, t3, GF4::new(31 - i as u8));
            }
        }
    }

    #[test]
    fn ohv16() {
        let inputs = [
            vec![BsBool16::new(0b0101010101010101)],
            vec![BsBool16::new(0b0011001100110011)],
            vec![BsBool16::new(0b0000111100001111)],
            vec![BsBool16::new(0b0000000011111111)],
        ];
        let mut rng = thread_rng();
        let bit0 = secret_share_vector::<BsBool16, _>(&mut rng, &inputs[0]);
        let bit1 = secret_share_vector::<BsBool16, _>(&mut rng, &inputs[1]);
        let bit2 = secret_share_vector::<BsBool16, _>(&mut rng, &inputs[2]);
        let bit3 = secret_share_vector::<BsBool16, _>(&mut rng, &inputs[3]);

        let program = |b0: Vec<RssShare<BsBool16>>,
                       b1: Vec<RssShare<BsBool16>>,
                       b2: Vec<RssShare<BsBool16>>,
                       b3: Vec<RssShare<BsBool16>>| {
            move |p: &mut ChidaParty| generate_ohv16(p.as_party_mut(), &mut NoMulTripleRecording, 16, b0, b1, b2, b3).unwrap()
        };
        let (h1, h2, h3) = ChidaSetup::localhost_setup(
            program(bit0.0, bit1.0, bit2.0, bit3.0),
            program(bit0.1, bit1.1, bit2.1, bit3.1),
            program(bit0.2, bit1.2, bit2.2, bit3.2),
        );
        let (o1, _) = h1.join().unwrap();
        let (o2, _) = h2.join().unwrap();
        let (o3, _) = h3.join().unwrap();

        assert_eq!(o1.len(), 16);
        assert_eq!(o2.len(), 16);
        assert_eq!(o3.len(), 16);
        for (i, (o1, o2, o3)) in izip!(o1, o2, o3).enumerate() {
            let rand = o1.random + o2.random + o3.random;
            // rand should be 15-i (per construction of inputs)
            assert_eq!(rand.as_u8(), (15 - i) as u8);

            // check consistent
            assert_eq!(o1.sii, o2.si);
            assert_eq!(o2.sii, o3.si);
            assert_eq!(o3.sii, o1.si);
            // check correct
            let ohv = o1.si.0 ^ o2.si.0 ^ o3.si.0;
            let index = rand.as_u8() as usize;
            assert!(index < 16);
            assert_eq!(1 << index, ohv);
        }
    }

    pub fn check_correct_rnd_ohv16(
        o1: Vec<RndOhvOutput>,
        o2: Vec<RndOhvOutput>,
        o3: Vec<RndOhvOutput>,
    ) {
        for (o1, o2, o3) in izip!(o1, o2, o3) {
            let rand = o1.random + o2.random + o3.random;
            // check consistent
            assert_eq!(o1.sii, o2.si);
            assert_eq!(o2.sii, o3.si);
            assert_eq!(o3.sii, o1.si);
            // check correct
            let ohv = o1.si.0 ^ o2.si.0 ^ o3.si.0;
            let index = rand.as_u8() as usize;
            assert!(index < 16);
            assert_eq!(1 << index, ohv);
        }
    }

    #[test]
    fn random_ohv16() {
        const N: usize = 10000;
        let program = || {
            |p: &mut ChidaParty| {
                generate_random_ohv16(p.as_party_mut(), &mut NoMulTripleRecording, N).unwrap()
            }
        };

        let (h1, h2, h3) = ChidaSetup::localhost_setup(program(), program(), program());
        let (o1, _) = h1.join().unwrap();
        let (o2, _) = h2.join().unwrap();
        let (o3, _) = h3.join().unwrap();
        assert_eq!(o1.len(), N);
        assert_eq!(o2.len(), N);
        assert_eq!(o3.len(), N);
        check_correct_rnd_ohv16(o1, o2, o3);
    }

    #[test]
    fn random_ohv16_mt() {
        const THREADS: usize = 3;
        const N: usize = 10001;
        let program = || {
            |p: &mut ChidaParty| {
                generate_random_ohv16_mt(p.as_party_mut(), &mut NoMulTripleRecording, N).unwrap()
            }
        };

        let (h1, h2, h3) =
            ChidaSetup::localhost_setup_multithreads(THREADS, program(), program(), program());
        let (o1, _) = h1.join().unwrap();
        let (o2, _) = h2.join().unwrap();
        let (o3, _) = h3.join().unwrap();
        assert_eq!(o1.len(), N);
        assert_eq!(o2.len(), N);
        assert_eq!(o3.len(), N);
        check_correct_rnd_ohv16(o1, o2, o3);
    }
}
