use crate::rep3_core::share::RssShare;

use crate::{lut256::RndOhv, share::bs_bool16::BsBool16};

const UN_BITSLICE_SS_SPLIT: usize = 500;
const UN_BITSLICE_RSS_SPLIT: usize = 1000;

/// Transposes the bitsliced one-hot vector bs of length 256 into a vector of [RndOhv]
pub fn un_bitslice_ss(bs: &[Vec<BsBool16>]) -> Vec<RndOhv> {
    debug_assert_eq!(bs.len(), 256);

    fn un_bitslice_ss_inner(bs: &[Vec<BsBool16>], from: usize, to: usize, res: &mut Vec<[u64; 4]>) {
        let size = to-from;
        let rnd_ohv_res = &mut res[16*from..16*to];
        for k in 0..16 {
            let mut res = vec![0u16; 16 * size];
            for i in 0..16 {
                let bit = &bs[16 * k + i];
                for j in 0..size {
                    let si = bit[from+j].as_u16();
                    for k in 0..16 {
                        res[16 * j + k] |= ((si >> k) & 0x1) << i;
                    }
                }
            }
            rnd_ohv_res
                .iter_mut()
                .zip(res.into_iter())
                .for_each(|(dst, ohv)| {
                    if k < 4 {
                        dst[0] |= (ohv as u64) << (16 * k);
                    } else if k < 8 {
                        dst[1] |= (ohv as u64) << (16 * (k - 4));
                    } else if k < 12 {
                        dst[2] |= (ohv as u64) << (16 * (k - 8));
                    } else {
                        dst[3] |= (ohv as u64) << (16 * (k - 12));
                    }
                });
        }
    }

    let mut res = vec![[0u64; 4]; 16 * bs[0].len()];
    let mut from = 0;
    let mut to = usize::min(UN_BITSLICE_SS_SPLIT, bs[0].len());
    while from < to {
        un_bitslice_ss_inner(bs, from, to, &mut res);
        from = to;
        to = usize::min(to+UN_BITSLICE_SS_SPLIT, bs[0].len());
    }
    res
        .into_iter()
        .map(|ohv| RndOhv::new(ohv))
        .collect()
    
}

/// Transposes the bitsliced, rss one-hot vector bs of length 256 into a vector of pairs of [RndOhv]
pub fn un_bitslice(bs: &[Vec<RssShare<BsBool16>>]) -> Vec<(RndOhv, RndOhv)> {
    debug_assert_eq!(bs.len(), 256);
    fn un_bitslice_inner(bs: &[Vec<RssShare<BsBool16>>], from: usize, to: usize, res: &mut Vec<([u64; 4], [u64; 4])>) {
        let size = to-from;
        let rnd_ohv_res = &mut res[16*from..16*to];
        for k in 0..16 {
            let mut res = vec![(0u16, 0u16); 16 * size];
            for i in 0..16 {
                let bit = &bs[16 * k + i];
                for j in 0..size {
                    let si = bit[from+j].si.as_u16();
                    let sii = bit[from+j].sii.as_u16();
                    for k in 0..16 {
                        res[16 * j + k].0 |= ((si >> k) & 0x1) << i;
                        res[16 * j + k].1 |= ((sii >> k) & 0x1) << i;
                    }
                }
            }
            rnd_ohv_res
                .iter_mut()
                .zip(res.into_iter())
                .for_each(|(dst, (ohv_i, ohv_ii))| {
                    if k < 4 {
                        dst.0[0] |= (ohv_i as u64) << (16 * k);
                        dst.1[0] |= (ohv_ii as u64) << (16 * k);
                    } else if k < 8 {
                        dst.0[1] |= (ohv_i as u64) << (16 * (k - 4));
                        dst.1[1] |= (ohv_ii as u64) << (16 * (k - 4));
                    } else if k < 12 {
                        dst.0[2] |= (ohv_i as u64) << (16 * (k - 8));
                        dst.1[2] |= (ohv_ii as u64) << (16 * (k - 8));
                    } else {
                        dst.0[3] |= (ohv_i as u64) << (16 * (k - 12));
                        dst.1[3] |= (ohv_ii as u64) << (16 * (k - 12));
                    }
                });
        }
    }

    let mut res = vec![([0u64; 4], [0u64; 4]); 16 * bs[0].len()];
    let mut from = 0;
    let mut to = usize::min(UN_BITSLICE_RSS_SPLIT, bs[0].len());
    while from < to {
        un_bitslice_inner(bs, from, to, &mut res);
        from = to;
        to = usize::min(to+UN_BITSLICE_RSS_SPLIT, bs[0].len());
    }
    res
        .into_iter()
        .map(|(ohv_si, ohv_sii)| (RndOhv::new(ohv_si), RndOhv::new(ohv_sii)))
        .collect()
}