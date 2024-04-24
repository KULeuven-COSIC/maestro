use criterion::*;
use dist_dec::share::{gf2p64::GF2p64, FieldRngExt};
use rand::*;

fn bench_multiplication(c: &mut Criterion) {
    let mut rng = thread_rng();
    let elements: Vec<GF2p64> = rng.generate(2);
    let x = elements[0];
    let y = elements[1];

    c.bench_function("Simple Multiplication", move |b| {
        b.iter(|| x.mul_using_add(&y))
    });

    #[cfg(any(
        all(
            feature = "clmul",
            target_arch = "x86_64",
            target_feature = "sse2",
            target_feature = "pclmulqdq"
        ),
        all(
            feature = "clmul",
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "aes"
        )
    ))]
    c.bench_function("CLMUL Multiplication", move |b| {
        b.iter(|| x.mul_clmul_u64(&y))
    });

}


fn bench_inner_product(c: &mut Criterion) {
    let mut rng = thread_rng();
    let x: Vec<GF2p64> = rng.generate(1024);
    let y: Vec<GF2p64> = rng.generate(1024);
    let x1 = x.clone();
    let y1 = y.clone();

    c.bench_function("Simple Inner Product", move |b| {
        b.iter(|| GF2p64::fall_back_inner_product(&x, &y))
    });

    #[cfg(any(
        all(
            feature = "clmul",
            target_arch = "x86_64",
            target_feature = "sse2",
            target_feature = "pclmulqdq"
        ),
        all(
            feature = "clmul",
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "aes"
        )
    ))]
    c.bench_function("CLMUL Inner Product with delayed propagation", move |b| {
        b.iter(|| GF2p64::clmul_inner_product(&x1, &y1))
    });
}

criterion_group!(gf2p64_mult_benchmark, bench_multiplication);
criterion_group!(gf2p64_ip_benchmark, bench_inner_product);
criterion_main!(gf2p64_mult_benchmark, gf2p64_ip_benchmark);