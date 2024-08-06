#![allow(dead_code)]
use dist_dec::chida::online::test::ChidaSetup;
use dist_dec::party::test::TestSetup;
use dist_dec::party::{error::MpcResult, ArithmeticBlackBox};
use dist_dec::share::{bs_bool16::BsBool16, gf4::GF4, Field, RssShare};
use dist_dec::{chida::ChidaParty, wollut16};
use itertools::{izip, Itertools};
use std::time::{Duration, Instant};

struct LUTBenchResult {
    prep_time: Vec<Duration>,
    online_time: Vec<Duration>,
}

impl LUTBenchResult {
    pub fn new() -> Self {
        Self {
            prep_time: Vec::new(),
            online_time: Vec::new(),
        }
    }

    fn join(results: &mut [Self]) -> Self {
        let mut j = Self::new();
        for res in results {
            j.prep_time.append(&mut res.prep_time);
            j.online_time.append(&mut res.online_time);
        }
        j
    }

    fn min_avg_max(v: Vec<f64>) -> (f64, f64, f64) {
        let min = v
            .iter()
            .copied()
            .reduce(f64::min)
            .or(Some(f64::NAN))
            .unwrap();
        let avg = v.iter().copied().sum::<f64>() / v.len() as f64;
        let max = v
            .iter()
            .copied()
            .reduce(f64::max)
            .or(Some(f64::NAN))
            .unwrap();
        (min, avg, max)
    }

    fn print(&self, name: &str) {
        let prep_time = self.prep_time.iter().map(|d| d.as_secs_f64()).collect_vec();
        let online_time = self
            .online_time
            .iter()
            .map(|d| d.as_secs_f64())
            .collect_vec();

        let (prep_min, prep_avg, prep_max) = Self::min_avg_max(prep_time);
        let (online_min, online_avg, online_max) = Self::min_avg_max(online_time);
        println!(
            "{}\n\tPre-Processing:\t{}s (min) {}s (avg) {}s (max)",
            name, prep_min, prep_avg, prep_max
        );
        println!(
            "\tOnline\t\t{}s (min) {}s (avg) {}s (max)",
            online_min, online_avg, online_max
        );
    }
}

fn lut16_ohv_as_bytes_benchmark(n_rep: usize, batch: usize) -> LUTBenchResult {
    let program = || {
        move |p: &mut ChidaParty| {
            let mut prep_times = Vec::new();
            let mut online_times = Vec::new();
            for _ in 0..n_rep {
                let inputs1 = p.generate_alpha(batch);
                let inputs2 = p.generate_alpha(batch);
                let inputs3 = p.generate_alpha(batch);
                let prep_now = Instant::now();
                let rnd_ohv = generate_random_ohv16_bytes(p, batch).unwrap();
                prep_times.push(prep_now.elapsed());
                let online_now = Instant::now();
                let res = lut_with_rnd_ohv_bytes(&rnd_ohv, inputs1, inputs2, inputs3);
                online_times.push(online_now.elapsed());
                criterion::black_box(res); // to prevent optimization that removes the computation
            }
            LUTBenchResult {
                prep_time: prep_times,
                online_time: online_times,
            }
        }
    };

    let (h1, h2, h3) = ChidaSetup::localhost_setup(program(), program(), program());
    let (res1, _) = h1.join().unwrap();
    let (res2, _) = h2.join().unwrap();
    let (res3, _) = h3.join().unwrap();
    LUTBenchResult::join(&mut [res1, res2, res3])
}

fn lut16_bitsliced_sbox_benchmark(n_rep: usize, batch: usize) -> LUTBenchResult {
    let program = || {
        move |p: &mut ChidaParty| {
            let mut prep_times = Vec::new();
            let mut online_times = Vec::new();
            for _ in 0..n_rep {
                let inputs1 = p.generate_alpha(batch);
                let inputs2 = p.generate_alpha(batch);
                let inputs3 = p.generate_alpha(batch);
                let prep_now = Instant::now();
                let rnd_ohv =
                    wollut16::offline::generate_random_ohv16(p.as_party_mut(), batch).unwrap();
                prep_times.push(prep_now.elapsed());
                let online_now = Instant::now();
                let res = wollut16::online::lut_with_rnd_ohv_bitsliced(
                    &rnd_ohv, inputs1, inputs2, inputs3,
                );
                online_times.push(online_now.elapsed());
                criterion::black_box(res); // to prevent optimization that removes the computation
            }
            LUTBenchResult {
                prep_time: prep_times,
                online_time: online_times,
            }
        }
    };

    let (h1, h2, h3) = ChidaSetup::localhost_setup(program(), program(), program());
    let (res1, _) = h1.join().unwrap();
    let (res2, _) = h2.join().unwrap();
    let (res3, _) = h3.join().unwrap();
    LUTBenchResult::join(&mut [res1, res2, res3])
}

fn main() {
    const N_ITERS: usize = 100;
    const BATCH: usize = 50000 * 16;

    println!("Running lut16_ohv_as_bytes_benchmark");
    let lut16_bytes = lut16_ohv_as_bytes_benchmark(N_ITERS, BATCH);
    println!("Running lut16_bitsliced_sbox_benchmark");
    let lut16_bitsliced = lut16_bitsliced_sbox_benchmark(N_ITERS, BATCH);

    lut16_bytes.print("LUT-16 bytes");
    lut16_bitsliced.print("LUT-16 bitsliced");
}

/// Output of the random one-hot vector pre-processing.
/// Contains a (2,3)-sharing of a size 16 one-hot vector `RndOhv16` and a (3,3)-sharing of the corresponding `GF4` element that indicates
/// the position of 1 in the vector.
pub struct RndOhvOutputBytes {
    /// share i of one-hot vector
    pub si: RndOhv16Bytes,
    /// share i+1 of one-hot vector
    pub sii: RndOhv16Bytes,
    /// (3,3) sharing of the position of the 1 in the vector
    pub random: GF4,
}

// a random one-hot vector of size 16
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct RndOhv16Bytes([u8; 16]);

impl RndOhv16Bytes {
    pub fn new(table: [u8; 16]) -> Self {
        Self(table)
    }

    pub fn lut(&self, offset: usize, table: &[u8; 16]) -> GF4 {
        let mut res = 0u8;
        for i in 0..16_usize {
            res ^= self.0[i] & table[i ^ offset];
        }
        GF4::new_unchecked(res)
    }
}

fn un_bitslice_bytes(bs: [Vec<RssShare<BsBool16>>; 16]) -> Vec<(RndOhv16Bytes, RndOhv16Bytes)> {
    // let now = Instant::now();
    let mut res = vec![(0u16, 0u16); 16 * bs[0].len()];
    for i in 0..16 {
        let bit = &bs[i];
        for j in 0..bit.len() {
            let si = bit[j].si.as_u16();
            let sii = bit[j].sii.as_u16();
            for k in 0..16 {
                res[16 * j + k].0 |= ((si >> k) & 0x1) << i;
                res[16 * j + k].1 |= ((sii >> k) & 0x1) << i;
            }
        }
    }
    let res = res
        .into_iter()
        .map(|(ohv_i, ohv_ii)| {
            let mut si = [0u8; 16];
            let mut sii = [0u8; 16];
            for i in 0..16 {
                si[i] = 0xff * ((ohv_i >> i) & 0x1) as u8;
                sii[i] = 0xff * ((ohv_ii >> i) & 0x1) as u8;
            }
            (RndOhv16Bytes::new(si), RndOhv16Bytes::new(sii))
        })
        .collect();
    // println!("un_bitslice: {}s", now.elapsed().as_secs_f64());
    res
}

// implements Protocol 7
pub fn generate_random_ohv16_bytes<P: ArithmeticBlackBox<BsBool16> + ArithmeticBlackBox<GF4>>(
    party: &mut P,
    n: usize,
) -> MpcResult<Vec<RndOhvOutputBytes>> {
    let n16 = if n % 16 == 0 { n / 16 } else { n / 16 + 1 };
    // generate 4 random bits
    let r0 = party.generate_random(n16);
    let r1 = party.generate_random(n16);
    let r2 = party.generate_random(n16);
    let r3 = party.generate_random(n16);
    generate_ohv16_bytes(party, n, r0, r1, r2, r3)
}

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
    for i in 0..elements.len() {
        if selector[i] {
            for j in 0..res.len() {
                res[j] += elements[i][j];
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

// implements Protocol 7 with fixed inputs
fn generate_ohv16_bytes<P: ArithmeticBlackBox<BsBool16> + ArithmeticBlackBox<GF4>>(
    party: &mut P,
    n: usize,
    r0: Vec<RssShare<BsBool16>>,
    r1: Vec<RssShare<BsBool16>>,
    r2: Vec<RssShare<BsBool16>>,
    r3: Vec<RssShare<BsBool16>>,
) -> MpcResult<Vec<RndOhvOutputBytes>> {
    let n16 = r0.len();
    debug_assert_eq!(n16, r1.len());
    debug_assert_eq!(n16, r2.len());
    debug_assert_eq!(n16, r3.len());

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
    party.mul(&mut ci, &mut cii, &ai, &aii, &bi, &bii)?;

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
    party.mul(&mut c2i, &mut c2ii, &a2i, &a2ii, &b2i, &b2ii)?;

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

    let ohv_transposed = un_bitslice_bytes([
        ohv_0, ohv_1, ohv_2, ohv_3, ohv_4, ohv_5, ohv_6, ohv_7, ohv_8, ohv_9, ohv_10, ohv_11,
        ohv_12, ohv_13, ohv_14, ohv_15,
    ]);
    let rand_transposed = wollut16::offline::un_bitslice4([r0, r1, r2, r3]);

    let res = izip!(
        ohv_transposed.into_iter().take(n),
        rand_transposed.into_iter().take(n),
        party.generate_alpha(n)
    )
    .map(|((ohv_si, ohv_sii), rand, alpha)| RndOhvOutputBytes {
        si: ohv_si,
        sii: ohv_sii,
        random: rand.si + alpha,
    })
    .collect();

    Ok(res)
}

const GF4_INV: [u8; 16] = [
    0x00, 0x01, 0x09, 0x0e, 0x0d, 0x0b, 0x07, 0x06, 0x0f, 0x02, 0x0c, 0x05, 0x0a, 0x04, 0x03, 0x08,
];

#[inline]
pub fn lut_with_rnd_ohv_bytes(
    rnd_ohv: &[RndOhvOutputBytes],
    ci: Vec<GF4>,
    cii: Vec<GF4>,
    ciii: Vec<GF4>,
) -> (Vec<GF4>, Vec<GF4>) {
    izip!(ci, cii, ciii, rnd_ohv)
        .map(|(ci, cii, ciii, ohv)| {
            let c = (ci + cii + ciii).as_u8() as usize;
            (ohv.si.lut(c, &GF4_INV), ohv.sii.lut(c, &GF4_INV))
        })
        .unzip()
}

#[cfg(test)]
mod test {
    use crate::{generate_ohv16_bytes, generate_random_ohv16_bytes};

    fn reconstruct_ohv16(mut ohv1: RndOhv16, ohv2: RndOhv16, ohv3: RndOhv16) -> [u8; 16] {
        for i in 0..16 {
            ohv1.0[i] ^= ohv2.0[i] ^ ohv3.0[i];
        }
        ohv1.0
    }

    #[test]
    fn ohv16_bytes() {
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
            move |p: &mut ChidaParty| generate_ohv16_bytes(p, 16, b0, b1, b2, b3).unwrap()
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
            let ohv = reconstruct_ohv16(o1.si, o2.si, o3.si);
            let index = rand.as_u8() as usize;
            assert!(index < 16);
            for i in 0..16 {
                if i == index {
                    assert_eq!(ohv[i], 0xff);
                } else {
                    assert_eq!(ohv[i], 0x00);
                }
            }
        }
    }

    #[test]
    fn random_ohv16_bytes() {
        const N: usize = 10000;
        let program = || |p: &mut ChidaParty| generate_random_ohv16_bytes(p, N).unwrap();

        let (h1, h2, h3) = ChidaSetup::localhost_setup(program(), program(), program());
        let (o1, _) = h1.join().unwrap();
        let (o2, _) = h2.join().unwrap();
        let (o3, _) = h3.join().unwrap();
        assert_eq!(o1.len(), N);
        assert_eq!(o2.len(), N);
        assert_eq!(o3.len(), N);
        for (o1, o2, o3) in izip!(o1, o2, o3) {
            let rand = o1.random + o2.random + o3.random;
            // check consistent
            assert_eq!(o1.sii, o2.si);
            assert_eq!(o2.sii, o3.si);
            assert_eq!(o3.sii, o1.si);
            // check correct
            let ohv = reconstruct_ohv16(o1.si, o2.si, o3.si);
            let index = rand.as_u8() as usize;
            assert!(index < 16);
            for i in 0..16 {
                if i == index {
                    assert_eq!(ohv[i], 0xff);
                } else {
                    assert_eq!(ohv[i], 0x00);
                }
            }
        }
    }
}
