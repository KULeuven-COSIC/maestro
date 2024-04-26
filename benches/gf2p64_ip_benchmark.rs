use criterion::*;
use rep3_aes::share::{gf2p64::GF2p64, FieldRngExt, RssShare};
use rand::{rngs::ThreadRng, thread_rng};

pub fn random_rss(n: usize) -> Vec<RssShare<GF2p64>>
where
    ThreadRng: FieldRngExt<GF2p64>,
{
    let mut rng = thread_rng();
    let x: Vec<GF2p64> = FieldRngExt::generate(&mut rng, n);
    let y: Vec<GF2p64> = FieldRngExt::generate(&mut rng, n);
    let res = x
        .iter()
        .zip(y.iter())
        .map(|(x, y)| RssShare::from(*x, *y))
        .collect();
    res
}

fn bench_inner_product(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("Inner Product Benchmark");

    for k in 0..5 {
        let n: usize = 2usize.pow(2u32.pow(k));
        let x: Vec<GF2p64> = rng.generate(n);
        let y: Vec<GF2p64> = rng.generate(n);
        let x1 = x.clone();
        let y1 = y.clone();

        #[allow(deprecated)]
        group.bench_function(BenchmarkId::new("Basic", n), move |b| {
            b.iter(|| GF2p64::fallback_inner_product(&x, &y))
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
        group.bench_function(BenchmarkId::new("Delayed Propagation", n), move |b| {
            b.iter(|| GF2p64::clmul_inner_product(&x1, &y1))
        });
    }
}

fn bench_weak_inner_product(c: &mut Criterion) {
    let mut group = c.benchmark_group("Weak Inner Product Benchmark");

    for k in 0..5 {
        let n: usize = 2usize.pow(2u32.pow(k));
        let x = random_rss(n);
        let y = random_rss(n);
        let x1 = x.clone();
        let y1 = y.clone();

        #[allow(deprecated)]
        group.bench_function(BenchmarkId::new("Basic", n), move |b| {
            b.iter(|| GF2p64::fallback_weak_ip(&x, &y))
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
        group.bench_function(BenchmarkId::new("Delayed Propagation", n), move |b| {
            b.iter(|| GF2p64::clmul_weak_inner_product(&x1, &y1))
        });
    }
}

/*

A special case of the bench_weak_inner_product

fn bench_small_inner_product(c: &mut Criterion) {
    let mut rng = thread_rng();
    let elements: Vec<GF2p64> = rng.generate(4);
    let x1 = elements[0];
    let x2 = elements[1];
    let y1 = elements[2];
    let y2 = elements[3];

    c.bench_function("Normal Multiplication", move |b| {
        b.iter(|| x1*y1 + y1*y2)
    });

    c.bench_function("IP Mult", move |b| {
        b.iter(|| GF2p64::clmul_inner_product(&[x1,x2],&[y1,y2]))
    });
}
*/

criterion_group!(
    gf2p64_ip_benchmark,
    bench_inner_product,
    bench_weak_inner_product
);
criterion_main!(gf2p64_ip_benchmark);
