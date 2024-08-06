use criterion::{criterion_group, criterion_main, Criterion};
use itertools::Itertools;
use rand::thread_rng;
use rep3_aes::{lut256::RndOhv, share::{bs_bool16::BsBool16, FieldRngExt, RssShare}};

const SIMD_SIZE: usize = 10000;

fn un_bitslice_ss_v1(bs: &[Vec<BsBool16>]) -> Vec<RndOhv> {
    debug_assert_eq!(bs.len(), 256);
    let mut rnd_ohv_res = vec![[0u64; 4]; 16 * bs[0].len()];
    for k in 0..16 {
        let mut res = vec![0u16; 16 * bs[0].len()];
        for i in 0..16 {
            let bit = &bs[16 * k + i];
            for j in 0..bit.len() {
                let si = bit[j].as_u16();
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
    rnd_ohv_res
        .into_iter()
        .map(|ohv| RndOhv::new(ohv))
        .collect()
}

fn un_bitslice_ss_v2(bs: &[Vec<BsBool16>]) -> Vec<RndOhv> {
    debug_assert_eq!(bs.len(), 256);
    let mut rnd_ohv_res = vec![0u128; 32 * bs[0].len()];

    for bit_i in 0..128 {
        let bitvec = &bs[bit_i];
        for j in 0..bitvec.len() {
            let bs = bitvec[j].as_u16();
            for k in 0..16 {
                rnd_ohv_res[32*j+2*k] |= (((bs >> k) & 0x1) as u128) << bit_i;
            }
        }
    }

    for bit_i in 0..128 {
        let bitvec = &bs[128+bit_i];
        for j in 0..bitvec.len() {
            let bs = bitvec[j].as_u16();
            for k in 0..16 {
                rnd_ohv_res[32*j+2*k+1] |= (((bs >> k) & 0x1) as u128) << bit_i;
            }
        }
    }

    rnd_ohv_res
        .into_iter()
        .chunks(2)
        .into_iter()
        .map(|mut ohv| {
            let mut table = [0u64, 0u64, 0u64, 0u64];
            let t1 = ohv.next().unwrap();
            table[0] = t1 as u64;
            table[1] = (t1 >> 64) as u64;
            let t2 = ohv.next().unwrap();
            table[2] = t2 as u64;
            table[3] = (t2 >> 64) as u64;
            RndOhv::new(table)
        })
        .collect()
}

fn un_bitslice_ss_v3(bs: &[Vec<BsBool16>]) -> Vec<RndOhv> {
    debug_assert_eq!(bs.len(), 256);
    let mut rnd_ohv_res = vec![0u64; 64 * bs[0].len()];

    for i in 0..4 {
        for bit_i in 0..64 {
            let bitvec = &bs[64*i+bit_i];
            for j in 0..bitvec.len() {
                let bs = bitvec[j].as_u16();
                for k in 0..16 {
                    rnd_ohv_res[64*j+4*k+i] |= (((bs >> k) & 0x1) as u64) << bit_i;
                }
            }
        }
    }

    rnd_ohv_res
        .into_iter()
        .chunks(4)
        .into_iter()
        .map(|mut ohv| {
            let table = [ohv.next().unwrap(), ohv.next().unwrap(), ohv.next().unwrap(), ohv.next().unwrap()];
            RndOhv::new(table)
        })
        .collect()
}

fn un_bitslice_ss_v4(bs: &[Vec<u8>]) -> Vec<RndOhv> {
    debug_assert_eq!(bs.len(), 256);
    let mut rnd_ohv_res = vec![[0u64; 4]; 8 * bs[0].len()];
    for k in 0..32 {
        let mut res = vec![0u8; 8 * bs[0].len()];
        for i in 0..8 {
            let bit = &bs[8 * k + i];
            for j in 0..bit.len() {
                let si = bit[j];
                for k in 0..8 {
                    res[8 * j + k] |= ((si >> k) & 0x1) << i;
                }
            }
        }
        rnd_ohv_res
            .iter_mut()
            .zip(res.into_iter())
            .for_each(|(dst, ohv)| {
                if k < 8 {
                    dst[0] |= (ohv as u64) << (8 * k);
                } else if k < 16 {
                    dst[1] |= (ohv as u64) << (8 * (k - 8));
                } else if k < 24 {
                    dst[2] |= (ohv as u64) << (8 * (k - 16));
                } else {
                    dst[3] |= (ohv as u64) << (8 * (k - 24));
                }
            });
    }
    rnd_ohv_res
        .into_iter()
        .map(|ohv| RndOhv::new(ohv))
        .collect()
}

fn un_bitslice_ss_v5(bs: &[Vec<BsBool16>]) -> Vec<RndOhv> {

    let mut res = vec![RndOhv::new([0u64; 4]); 16 * bs[0].len()];

    fn un_bitslice_ss_v5_inner(bs: &[Vec<BsBool16>], from: usize, to: usize, res: &mut Vec<RndOhv>) {
        debug_assert_eq!(bs.len(), 256);
        let size = to-from;
        let mut rnd_ohv_res = vec![[0u64; 4]; 16 * size];
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
        res.iter_mut().skip(16*from).zip(rnd_ohv_res)
            .for_each(|(dst, ohv)| *dst = RndOhv::new(ohv));
    }

    const SPLIT: usize = 500;
    let mut from = 0;
    let mut to = usize::min(SPLIT, bs[0].len());
    while from < to {
        un_bitslice_ss_v5_inner(bs, from, to, &mut res);
        from = to;
        to = usize::min(to+SPLIT, bs[0].len());
    }
    res
    
}

fn un_bitslice_ss_v6(bs: &[Vec<BsBool16>]) -> Vec<RndOhv> {

    let mut res = vec![[0u64; 4]; 16 * bs[0].len()];

    fn un_bitslice_ss_v6_inner(bs: &[Vec<BsBool16>], from: usize, to: usize, res: &mut Vec<[u64; 4]>) {
        debug_assert_eq!(bs.len(), 256);
        let size = to-from;
        let rnd_ohv_res = &mut res[16*from..16*to];//vec![[0u64; 4]; 16 * size];
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

    const SPLIT: usize = 500;
    let mut from = 0;
    let mut to = usize::min(SPLIT, bs[0].len());
    while from < to {
        un_bitslice_ss_v6_inner(bs, from, to, &mut res);
        from = to;
        to = usize::min(to+SPLIT, bs[0].len());
    }
    res
        .into_iter()
        .map(|ohv| RndOhv::new(ohv))
        .collect()
    
}

fn benchmark_un_bitslice_ss(c: &mut Criterion) {
    // run tests
    un_bitslice_ss_v2_correct();
    un_bitslice_ss_v3_correct();
    un_bitslice_ss_v4_correct();
    un_bitslice_ss_v5_correct();
    un_bitslice_ss_v6_correct();

    // prepare a random instance
    let mut rng = thread_rng();
    let bitslice: Vec<Vec<BsBool16>> = (0..256).map(|_| rng.generate(SIMD_SIZE)).collect_vec();
    let bitslice_v4 = bitslice.iter().map(|v| {
        v.iter().flat_map(|bs16| [bs16.as_u16() as u8, (bs16.as_u16() >> 8) as u8]).collect_vec()
    }).collect_vec();

    c.bench_function("un_bitslice_ss_v1", |b| {
        b.iter(|| criterion::black_box(un_bitslice_ss_v1(&bitslice)))
    });

    c.bench_function("un_bitslice_ss_v2", |b| {
        b.iter(|| criterion::black_box(un_bitslice_ss_v2(&bitslice)))
    });

    c.bench_function("un_bitslice_ss_v3", |b| {
        b.iter(|| criterion::black_box(un_bitslice_ss_v3(&bitslice)))
    });

    c.bench_function("un_bitslice_ss_v4", |b| {
        b.iter(|| criterion::black_box(un_bitslice_ss_v4(&bitslice_v4)))
    });

    c.bench_function("un_bitslice_ss_v5", |b| {
        b.iter(|| criterion::black_box(un_bitslice_ss_v5(&bitslice)))
    });

    c.bench_function("un_bitslice_ss_v6", |b| {
        b.iter(|| criterion::black_box(un_bitslice_ss_v6(&bitslice)))
    });
}

fn un_bitslice_v1(bs: &[Vec<RssShare<BsBool16>>]) -> Vec<(RndOhv, RndOhv)> {
    debug_assert_eq!(bs.len(), 256);
    let mut rnd_ohv_res = vec![([0u64; 4], [0u64; 4]); 16 * bs[0].len()];
    for k in 0..16 {
        let mut res = vec![(0u16, 0u16); 16 * bs[0].len()];
        for i in 0..16 {
            let bit = &bs[16 * k + i];
            for j in 0..bit.len() {
                let si = bit[j].si.as_u16();
                let sii = bit[j].sii.as_u16();
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
    rnd_ohv_res
        .into_iter()
        .map(|(ohv_si, ohv_sii)| (RndOhv::new(ohv_si), RndOhv::new(ohv_sii)))
        .collect()
}

fn un_bitslice_v2(bs: &[Vec<RssShare<BsBool16>>]) -> Vec<(RndOhv, RndOhv)> {
    debug_assert_eq!(bs.len(), 256);

    let (bs_si, bs_sii): (Vec<_>, Vec<_>) = bs.iter().map(|bitvec| {
        let (si, sii): (Vec<_>, Vec<_>) = bitvec.iter().map(|rss| (rss.si, rss.sii)).unzip();
        (si, sii)
    }).unzip();

    let ohv_si = un_bitslice_ss_v6(&bs_si);
    let ohv_sii = un_bitslice_ss_v6(&bs_sii);
    ohv_si.into_iter().zip(ohv_sii).collect_vec()
}

fn un_bitslice_v3(bs: &[Vec<RssShare<BsBool16>>]) -> Vec<(RndOhv, RndOhv)> {
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
    
    const SPLIT: usize = 1000;
    let mut from = 0;
    let mut to = usize::min(SPLIT, bs[0].len());
    while from < to {
        un_bitslice_inner(bs, from, to, &mut res);
        from = to;
        to = usize::min(to+SPLIT, bs[0].len());
    }
    res
        .into_iter()
        .map(|(ohv_si, ohv_sii)| (RndOhv::new(ohv_si), RndOhv::new(ohv_sii)))
        .collect()
}

fn benchmark_un_bitslice_rss(c: &mut Criterion) {
    // run tests
    un_bitslice_v2_correct();
    un_bitslice_v3_correct();

    // prepare a random instance
    let mut rng = thread_rng();
    let bitslice: Vec<Vec<RssShare<BsBool16>>> = (0..256).map(|_| {
        let si = rng.generate(SIMD_SIZE);
        let sii = rng.generate(SIMD_SIZE);
        si.into_iter().zip(sii).map(|(si, sii)| RssShare::from(si, sii)).collect_vec()
    }).collect_vec();

    c.bench_function("un_bitslice_v1", |b| {
        b.iter(|| criterion::black_box(un_bitslice_v1(&bitslice)))
    });

    c.bench_function("un_bitslice_v2", |b| {
        b.iter(|| criterion::black_box(un_bitslice_v2(&bitslice)))
    });

    c.bench_function("un_bitslice_v3", |b| {
        b.iter(|| criterion::black_box(un_bitslice_v3(&bitslice)))
    });

}

criterion_group!(unpack_bitslice, benchmark_un_bitslice_ss, benchmark_un_bitslice_rss);
criterion_main!(unpack_bitslice);

// #[test]
fn un_bitslice_ss_v2_correct() {
    // prepare a random instance
    let mut rng = thread_rng();
    let bitslice: Vec<Vec<BsBool16>> = (0..256).map(|_| rng.generate(SIMD_SIZE)).collect_vec();

    let res1 = un_bitslice_ss_v1(&bitslice);
    let res2 = un_bitslice_ss_v2(&bitslice);
    assert_eq!(res1.len(), res2.len());
    assert_eq!(res1, res2);
}

// #[test]
fn un_bitslice_ss_v3_correct() {
    // prepare a random instance
    let mut rng = thread_rng();
    let bitslice: Vec<Vec<BsBool16>> = (0..256).map(|_| rng.generate(SIMD_SIZE)).collect_vec();

    let res1 = un_bitslice_ss_v1(&bitslice);
    let res2 = un_bitslice_ss_v3(&bitslice);
    assert_eq!(res1.len(), res2.len());
    assert_eq!(res1, res2);
}

// #[test]
fn un_bitslice_ss_v4_correct() {
    // prepare a random instance
    let mut rng = thread_rng();
    let bitslice: Vec<Vec<BsBool16>> = (0..256).map(|_| rng.generate(SIMD_SIZE)).collect_vec();
    let bitslice_v4 = bitslice.iter().map(|v| {
        v.iter().flat_map(|bs16| [bs16.as_u16() as u8, (bs16.as_u16() >> 8) as u8]).collect_vec()
    }).collect_vec();
    assert_eq!(bitslice_v4.len(), 256);
    assert_eq!(bitslice_v4[0].len(), 2*SIMD_SIZE);


    let res1 = un_bitslice_ss_v1(&bitslice);
    let res2 = un_bitslice_ss_v4(&bitslice_v4);
    assert_eq!(res1.len(), res2.len());
    assert_eq!(res1, res2);
}

// #[test]
fn un_bitslice_ss_v5_correct() {
    // prepare a random instance
    let mut rng = thread_rng();
    let bitslice: Vec<Vec<BsBool16>> = (0..256).map(|_| rng.generate(SIMD_SIZE)).collect_vec();

    let res1 = un_bitslice_ss_v1(&bitslice);
    let res2 = un_bitslice_ss_v5(&bitslice);
    assert_eq!(res1.len(), res2.len());
    assert_eq!(res1, res2);
}

// #[test]
fn un_bitslice_ss_v6_correct() {
    // prepare a random instance
    let mut rng = thread_rng();
    let bitslice: Vec<Vec<BsBool16>> = (0..256).map(|_| rng.generate(SIMD_SIZE)).collect_vec();

    let res1 = un_bitslice_ss_v1(&bitslice);
    let res2 = un_bitslice_ss_v6(&bitslice);
    assert_eq!(res1.len(), res2.len());
    assert_eq!(res1, res2);
}

// #[test]
fn un_bitslice_v2_correct() {
    // prepare a random instance
    let mut rng = thread_rng();
    let bitslice: Vec<Vec<RssShare<BsBool16>>> = (0..256).map(|_| {
        let si = rng.generate(SIMD_SIZE);
        let sii = rng.generate(SIMD_SIZE);
        si.into_iter().zip(sii).map(|(si, sii)| RssShare::from(si, sii)).collect_vec()
    }).collect_vec();

    let res1 = un_bitslice_v1(&bitslice);
    let res2 = un_bitslice_v2(&bitslice);
    assert_eq!(res1.len(), res2.len());
    assert_eq!(res1, res2);
}

// #[test]
fn un_bitslice_v3_correct() {
    // prepare a random instance
    let mut rng = thread_rng();
    let bitslice: Vec<Vec<RssShare<BsBool16>>> = (0..256).map(|_| {
        let si = rng.generate(SIMD_SIZE);
        let sii = rng.generate(SIMD_SIZE);
        si.into_iter().zip(sii).map(|(si, sii)| RssShare::from(si, sii)).collect_vec()
    }).collect_vec();

    let res1 = un_bitslice_v1(&bitslice);
    let res2 = un_bitslice_v3(&bitslice);
    assert_eq!(res1.len(), res2.len());
    assert_eq!(res1, res2);
}