use criterion::*;
use rep3_aes::share::{gf2p64::GF2p64, FieldRngExt};
use rand::*;

fn bench_multiplication(c: &mut Criterion) {
    let mut rng = thread_rng();
    let elements: Vec<GF2p64> = rng.generate(2);
    let x = elements[0];
    let y = elements[1];

    #[allow(deprecated)]
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
    c.bench_function("CLMUL FastCarry Multiplication", move |b| {
        b.iter(|| x.mul_clmul_u64_fast(&y))
    });   
}

criterion_group!(gf2p64_mult_benchmark, bench_multiplication);
criterion_main!(gf2p64_mult_benchmark);
