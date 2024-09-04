use criterion::*;
use maestro::share::gf2p64::GF2p64;
use rand::thread_rng;
use maestro::rep3_core::party::RngExt;

fn clmul_bench_variants(c: &mut Criterion) {
    let mut rng = thread_rng();
    let n: usize = 2*32768;
    let x: Vec<GF2p64> = GF2p64::generate(&mut rng, n);
    let y: Vec<GF2p64> = GF2p64::generate(&mut rng, n);
    let x1 = x.clone();
    let y1 = y.clone();
    // let x2 = x.clone();
    // let y2 = y.clone();

    /* 
    #[allow(deprecated)]
    c.bench_function("Basic", move |b| {
        b.iter(|| GF2p64::fallback_inner_product(&x, &y))
    });
    */

    c.bench_function("Delayed", move |b| {
        b.iter(|| GF2p64::clmul_inner_product(&x, &y))
    });

    c.bench_function("Delayed u128", move |b| {
        b.iter(|| GF2p64::fast_clmul_inner_product(&x1, &y1))
    });
   
}

criterion_group!(clmul_bench, clmul_bench_variants);
criterion_main!(clmul_bench);