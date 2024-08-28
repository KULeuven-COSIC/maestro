use std::slice;

use itertools::Itertools;
use rayon::{iter::{IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator}, slice::{ParallelSlice, ParallelSliceMut}};
use crate::rep3_core::{
    network::task::Direction,
    party::{broadcast::{Broadcast, BroadcastContext}, error::MpcResult, DigestExt, MainParty, Party}, share::{HasZero, RssShare, RssShareVec},
};
use crate::{share::{
        gf2p64::{GF2p64, GF2p64InnerProd}, Field, HasTwo, InnerProduct, Invertible
}, util::mul_triple_vec::MulTripleEncoder};

/// Protocol `8` to verify the multiplication triples at the end of the protocol.
pub fn verify_multiplication_triples(party: &mut MainParty, context: &mut BroadcastContext, triples: &mut [&mut (dyn MulTripleEncoder + Send + Sync)], dont_clear: bool) -> MpcResult<bool> {
    let lengths: usize = triples.iter().map(|enc| enc.len_triples_out()).sum();
    if lengths == 0 {
        return Ok(true);
    }
    let n = lengths.checked_next_power_of_two().expect("n too large");

    let r: GF2p64 = coin_flip(party, context)?;

    let mut x_vec = vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); n];
    let mut y_vec = vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); n];
    let mut zi = GF2p64InnerProd::new();
    let mut zii = GF2p64InnerProd::new();
    let mut weight = GF2p64::ONE;

    let mut i = 0;
    triples.iter_mut().for_each(|enc| {
        let len = enc.len_triples_out();
        // encode
        (*enc).add_triples(&mut x_vec[i..(i+len)], &mut y_vec[i..(i+len)], &mut zi, &mut zii, &mut weight, r);
        if !dont_clear {
            enc.clear();
        }
        i += len;
    });
    let z = RssShare::from(zi.sum(), zii.sum());
    // println!("add_triples_time={}s", add_triples_time.elapsed().as_secs_f64());
    verify_dot_product_opt(party, context, x_vec, y_vec, z)
}

#[rustfmt::skip]
pub fn verify_multiplication_triples_mt(party: &mut MainParty, context: &mut BroadcastContext, triples: &mut [&mut (dyn MulTripleEncoder + Send + Sync)], dont_clear: bool) -> MpcResult<bool>
{
    let length: usize = triples.iter().map(|enc| enc.len_triples_out()).sum();
    let n = length.checked_next_power_of_two().expect("n too large");
    if n < (1 << 14) {
        // don't use multi-threading for such small task
        return verify_multiplication_triples(party, context, triples, dont_clear);
    }

    let n_threads = party.num_worker_threads();
    let chunk_sizes = triples.iter().map(|enc| {
        let len = enc.len_triples_in();
        if len < 4096 {
            None
        }else{
            Some(party.chunk_size_for_task(len))
        }
    }).collect_vec();
    
    let r: Vec<GF2p64> = coin_flip_n(party, context, triples.len()*n_threads)?;

    let mut x_vec = vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); n];
    let mut y_vec = vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); n];

    let indices = triples.iter().map(|enc| enc.len_triples_out());
    let x_vec_chunks = split_at_indices_mut(&mut x_vec[..length], indices.clone());
    let y_vec_chunks = split_at_indices_mut(&mut y_vec[..length], indices);
    
    let z_vec = party.run_in_threadpool(|| {
        let vec: Vec<_> = triples.par_iter_mut()
            .zip_eq(x_vec_chunks.into_par_iter())
            .zip_eq(y_vec_chunks.into_par_iter())
            .zip_eq(chunk_sizes.into_par_iter())
            .zip_eq(r.par_chunks_exact(n_threads))
            .map(|((((enc, x_vec), y_vec), chunk_size), rand)| {
                match chunk_size {
                    None => {
                        // do all in a single thread
                        let mut zi = GF2p64InnerProd::new();
                        let mut zii = GF2p64InnerProd::new();
                        let mut weight = GF2p64::ONE;
                        enc.add_triples(x_vec, y_vec, &mut zi, &mut zii, &mut weight, rand[0]);
                        if !dont_clear { enc.clear() }
                        RssShare::from(zi.sum(), zii.sum())
                    },
                    Some(chunk_size) => {
                        // chunk with multiple threads
                        let mut z = RssShare::from(GF2p64::ZERO, GF2p64::ZERO);
                        enc.add_triples_par(x_vec, y_vec, &mut z, GF2p64::ONE, rand, chunk_size);
                        if !dont_clear { enc.clear() }
                        z
                    }
                }
            }).collect();
        Ok(vec)
    })?;
    // sum all z values
    let z = z_vec.into_iter().fold(RssShare::from(GF2p64::ZERO, GF2p64::ZERO), |acc, x| acc + x);

    // println!("Add triples: {}", add_triples_time.elapsed().as_secs_f64());
    verify_dot_product_opt(party, context, x_vec, y_vec, z)
}

fn split_at_indices_mut<T, I>(mut slice: &mut[T], indices: I) -> Vec<&mut[T]>
where I: IntoIterator<Item=usize>
{
    let it = indices.into_iter();
    let mut chunks = Vec::with_capacity(it.size_hint().0);
    for index in it {
        let (chunk, rest) = slice.split_at_mut(index);
        slice = rest;
        chunks.push(chunk);
    }
    chunks
}

/// Protocol to verify the component-wise multiplication triples
///
/// This protocol assumes that the input vectors are of length 2^n for some n.
fn verify_dot_product<F: Field + DigestExt + HasTwo + Invertible>(
    party: &mut MainParty,
    context: &mut BroadcastContext,
    x_vec: Vec<RssShare<F>>,
    y_vec: Vec<RssShare<F>>,
    z: RssShare<F>,
) -> MpcResult<bool>
where
    F: InnerProduct,
{
    let n = x_vec.len();
    debug_assert_eq!(n, y_vec.len());
    debug_assert!(n & (n - 1) == 0 && n != 0);
    if n == 1 {
        return check_triple(party, context, x_vec[0], y_vec[0], z);
    }
    // let inner_prod_time = Instant::now();
    // Compute dot products
    let f1: RssShareVec<F> = x_vec.iter().skip(1).step_by(2).copied().collect();
    let g1: RssShareVec<F> = y_vec.iter().skip(1).step_by(2).copied().collect();
    let f2: Vec<_> = x_vec
        .chunks(2)
        .map(|c| c[0] + (c[0] + c[1]) * F::TWO)
        .collect();
    let g2: Vec<_> = y_vec
        .chunks(2)
        .map(|c| c[0] + (c[0] + c[1]) * F::TWO)
        .collect();
    // let inner_prod_time = inner_prod_time.elapsed();
    // let weak_inner_prod_time = Instant::now();
    let mut hs = [F::ZERO; 2];
    hs[0] = F::weak_inner_product(&f1, &g1);
    hs[1] = F::weak_inner_product(&f2, &g2);
    // let weak_inner_prod_time = weak_inner_prod_time.elapsed();
    // let ss_rss_time = Instant::now();
    let h = ss_to_rss_shares(party, &hs)?;
    // let ss_rss_time = ss_rss_time.elapsed();
    let h1 = &h[0];
    let h2 = &h[1];
    let h0 = z - *h1;
    // let coin_flip_time = Instant::now();
    // Coin flip
    let r = coin_flip(party, context)?;
    // For large F this is very unlikely
    debug_assert!(r != F::ZERO && r != F::ONE);
    // let coin_flip_time = coin_flip_time.elapsed();

    // let poly_time = Instant::now();
    // Compute polynomials
    let fr: Vec<_> = x_vec.chunks(2).map(|c| c[0] + (c[0] + c[1]) * r).collect();
    let gr: Vec<_> = y_vec.chunks(2).map(|c| c[0] + (c[0] + c[1]) * r).collect();
    // let poly_time = poly_time.elapsed();
    let hr = lagrange_deg2(&h0, h1, h2, r);
    // println!("[vfy-dp] n={}, inner_prod_time={}s, weak_inner_prod_time={}s, ss_rss_time={}s, coin_flip_time={}s, poly_time={}s", n, inner_prod_time.as_secs_f32(), weak_inner_prod_time.as_secs_f32(), ss_rss_time.as_secs_f32(), coin_flip_time.as_secs_f32(), poly_time.as_secs_f32());
    verify_dot_product(party, context, fr, gr, hr)
}

#[inline]
fn compute_poly<F: Field>(x: &mut [RssShare<F>], r: F) {
    let mut i = 0;
    for k in 0..x.len()/2 {
        x[k] = x[i] + (x[i] + x[i+1])*r;
        i += 2;
    }
}

#[inline]
fn compute_poly_dst<F: Field>(dst: &mut [RssShare<F>], x: &[RssShare<F>], r: F) {
    debug_assert_eq!(2*dst.len(), x.len());
    let mut i = 0;
    for k in 0..dst.len() {
        dst[k] = x[i] + (x[i] + x[i+1])*r;
        i += 2;
    }
}

fn verify_dot_product_opt<F: Field + DigestExt + HasTwo + Invertible + Send + Sync>(
    party: &mut MainParty,
    context: &mut BroadcastContext,
    mut x_vec: Vec<RssShare<F>>,
    mut y_vec: Vec<RssShare<F>>,
    z: RssShare<F>,
) -> MpcResult<bool>
where
    F: InnerProduct,
{
    let n = x_vec.len();
    // println!("n = {}", n);
    debug_assert_eq!(n, y_vec.len());
    debug_assert!(n & (n - 1) == 0 && n != 0);
    if n == 1 {
        return check_triple(party, context, x_vec[0], y_vec[0], z);
    }
    let multi_threading = party.has_multi_threading() && n >= (1 << 13);
    let mut chunk_size = if x_vec.len() % party.num_worker_threads() == 0 {
        x_vec.len() / party.num_worker_threads()
    }else{
        x_vec.len() / party.num_worker_threads() +1
    };
    // make sure chunk size is even
    if chunk_size % 2 != 0 { chunk_size += 1 }

    // let inner_prod_time = Instant::now();
    let mut hs = [F::ZERO; 2];
    if !multi_threading {
        hs[0] = F::weak_inner_product2(&x_vec[1..], &y_vec[1..]);
        hs[1] = F::weak_inner_product3(&x_vec, &y_vec);
    }else{
        let mut h0 = F::ZERO;
        let mut h1 = F::ZERO;
        party.run_in_threadpool_scoped(|scope| {
            scope.spawn(|_| { 
                h0 = x_vec[1..]
                    .par_chunks(chunk_size)
                    .zip_eq(y_vec[1..].par_chunks(chunk_size))
                    .map(|(x,y)| F::weak_inner_product2(x, y))
                    .reduce(|| F::ZERO, |sum, v| sum + v);
            });
            scope.spawn(|_| {
                h1 = x_vec.par_chunks(chunk_size)
                    .zip_eq(y_vec.par_chunks(chunk_size))
                    .map(|(x,y)| F::weak_inner_product3(x, y))
                    .reduce(|| F::ZERO, |sum, v| sum + v);
            });
        });
        hs[0] = h0;
        hs[1] = h1;
    }
    
    // let inner_prod_time = inner_prod_time.elapsed();
    // let ss_rss_time = Instant::now();
    let h = ss_to_rss_shares(party, &hs)?;
    // let ss_rss_time = ss_rss_time.elapsed();
    let h1 = &h[0];
    let h2 = &h[1];
    let h0 = z - *h1;
    // let coin_flip_time = Instant::now();
    // Coin flip
    let r = coin_flip(party, context)?;
    // For large F this is very unlikely
    debug_assert!(r != F::ZERO && r != F::ONE);
    // let coin_flip_time = coin_flip_time.elapsed();

    // let poly_time = Instant::now();
    // Compute polynomials
    let (fr, gr) = if !multi_threading {
        compute_poly(&mut x_vec, r);
        x_vec.truncate(x_vec.len()/2);
        let fr = x_vec;
        compute_poly(&mut y_vec, r);
        y_vec.truncate(y_vec.len()/2);
        let gr = y_vec;
        (fr, gr)
    }else{
        let mut fr = vec![RssShare::from(F::ZERO, F::ZERO); x_vec.len()/2];
        let mut gr = vec![RssShare::from(F::ZERO, F::ZERO); x_vec.len()/2];
        party.run_in_threadpool_scoped(|scope| {
            scope.spawn(|_| {
                fr.par_chunks_mut(chunk_size/2)
                .zip_eq(x_vec.par_chunks(chunk_size))
                .for_each(|(dst, x)| {
                    compute_poly_dst(dst, x, r);
                });
            });

            scope.spawn(|_| {
                gr.par_chunks_mut(chunk_size/2)
                .zip_eq(y_vec.par_chunks(chunk_size))
                .for_each(|(dst, y)| {
                    compute_poly_dst(dst, y, r);
                });
            });
        });
        (fr, gr)
    };
    
    // let poly_time = poly_time.elapsed();
    let hr = lagrange_deg2(&h0, h1, h2, r);
    // println!("[vfy-dp-opt] n={}, inner_prod_time={}s, ss_rss_time={}s, coin_flip_time={}s, poly_time={}s", n, inner_prod_time.as_secs_f32(), ss_rss_time.as_secs_f32(), coin_flip_time.as_secs_f32(), poly_time.as_secs_f32());
    verify_dot_product_opt(party, context, fr, gr, hr)
}

/// Protocol 1 CheckTriple
fn check_triple<F: Field + DigestExt>(
    party: &mut MainParty,
    context: &mut BroadcastContext,
    x: RssShare<F>,
    y: RssShare<F>,
    z: RssShare<F>,
) -> MpcResult<bool>
where
    F: InnerProduct,
{
    // Generate RSS sharing of random value
    let x_prime = party.generate_random(1)[0];
    let z_prime = weak_mult(party, &x_prime, &y)?;
    let t = coin_flip(party, context)?;
    let rho = reconstruct(party, context, x + x_prime * t)?;
    reconstruct(party, context, z + z_prime * t - y * rho).map(|x| x.is_zero())
}

/// Shared lagrange evaluation of the polynomial h at position x for given (shared) points h(0), h(1), h(2)
#[inline]
fn lagrange_deg2<F: Field + HasTwo + Invertible>(
    h0: &RssShare<F>,
    h1: &RssShare<F>,
    h2: &RssShare<F>,
    x: F,
) -> RssShare<F> {
    // Lagrange weights
    // w0^-1 = (1-0)*(2-0) = 1*2 = 2
    let w0 = F::TWO.inverse();
    // w1^-1 = (0-1)*(2-1) = 1*(2-1) = (2-1) = 2+1
    let w1 = (F::TWO + F::ONE).inverse();
    // w2^-1 = (0-2)*(1-2) = 2*(1+2) = 2 * (2+1)
    let w2 = w0 * w1;
    let l0 = w0 * (x - F::ONE) * (x - F::TWO);
    let l1 = w1 * x * (x - F::TWO);
    let l2 = w2 * x * (x - F::ONE);
    // Lagrange interpolation
    (*h0) * l0 + (*h1) * l1 + (*h2) * l2
}

fn reconstruct<F: Field + DigestExt>(party: &mut MainParty, context: &mut BroadcastContext, rho: RssShare<F>) -> MpcResult<F> {
    party
        .open_rss(
            context,
            slice::from_ref(&rho.si),
            slice::from_ref(&rho.sii),
        )
        .map(|v| v[0])
}

/// Coin flip protocol returns a random value in F
///
/// Generates a sharing of a random value that is then reconstructed globally.
fn coin_flip<F: Field + DigestExt>(party: &mut MainParty, context: &mut BroadcastContext) -> MpcResult<F> {
    let r: RssShare<F> = party.generate_random(1)[0];
    reconstruct(party, context, r)
}

/// Coin flip protocol returns a n random values in F
///
/// Generates a sharing of a n random values that is then reconstructed globally.
fn coin_flip_n<F: Field + DigestExt>(party: &mut MainParty, context: &mut BroadcastContext, n: usize) -> MpcResult<Vec<F>> {
    let (r_i, r_ii): (Vec<_>, Vec<_>) = party.generate_random::<F>(n).into_iter().map(|rss| (rss.si, rss.sii)).unzip();
    party.open_rss(context, &r_i, &r_ii)
}

/// Computes the components wise multiplication of replicated shared x and y.
fn weak_mult<F: Field + Copy + Sized>(
    party: &mut MainParty,
    x: &RssShare<F>,
    y: &RssShare<F>,
) -> MpcResult<RssShare<F>>
where
    F: InnerProduct,
{
    // Compute a sum sharing of x*y
    let zs = F::weak_inner_product(&[*x], &[*y]);
    single_ss_to_rss_shares(party, zs)
}

/// Converts a vector of sum sharings into a replicated sharing
#[inline]
fn ss_to_rss_shares<F: Field + Copy + Sized>(
    party: &mut MainParty,
    sum_shares: &[F],
) -> MpcResult<RssShareVec<F>> {
    let n = sum_shares.len();
    let alphas = party.generate_alpha(n);
    let s_i: Vec<F> = sum_shares.iter().zip(alphas).map(|(s, a)| *s + a).collect();
    let mut s_ii = vec![F::ZERO; n];
    party.send_field_slice(Direction::Previous, &s_i);
    party.receive_field_slice(Direction::Next, &mut s_ii)
        .rcv()?;
    party.wait_for_completion();
    let res: RssShareVec<F> = s_ii
        .iter()
        .zip(s_i)
        .map(|(sii, si)| RssShare::from(si, *sii))
        .collect();
    Ok(res)
}

/// Converts a sum sharing into a replicated sharing
#[inline]
fn single_ss_to_rss_shares<F: Field + Copy + Sized>(
    party: &mut MainParty,
    sum_share: F,
) -> MpcResult<RssShare<F>> {
    // Convert zs to RSS sharing
    let s_i = [sum_share + party.generate_alpha(1).next().unwrap()];
    let mut s_ii = [F::ZERO; 1];
    party.send_field_slice(Direction::Previous, &s_i);
    party.receive_field_slice(Direction::Next, &mut s_ii)
        .rcv()?;
    party.io().wait_for_completion();
    Ok(RssShare::from(s_i[0], s_ii[0]))
}

#[cfg(test)]
mod test {

    use itertools::izip;
    use rand::{thread_rng, CryptoRng, Rng};
    use crate::rep3_core::{party::{broadcast::{Broadcast, BroadcastContext}, MainParty}, share::{HasZero, RssShare}};
    use crate::rep3_core::test::{PartySetup, TestSetup};
    use crate::{
        share::{
            bs_bool16::BsBool16, gf2p64::GF2p64, gf4::BsGF4, gf8::GF8, test::{assert_eq, consistent, secret_share, secret_share_vector}, Field, InnerProduct
        }, util::mul_triple_vec::{BsBool16Encoder, BsGF4Encoder, GF2p64Encoder, GF2p64SubfieldEncoder, MulTripleRecorder, MulTripleVector}, wollut16_malsec::{
            mult_verification::{verify_dot_product_opt, verify_multiplication_triples, verify_multiplication_triples_mt}, test::{localhost_setup_wl16as, WL16DefaultParams},
            WL16ASParty,
        }
    };

    use super::{lagrange_deg2, ss_to_rss_shares, verify_dot_product, weak_mult};

    fn gen_rand_vec<R: Rng + CryptoRng, F: Field>(rng: &mut R, n: usize) -> Vec<F> {
        F::generate(rng, n)
    }

    #[test]
    fn test_weak_mult() {
        let mut rng = thread_rng();
        let a = gen_rand_vec::<_, GF2p64>(&mut rng, 1)[0];
        let b = gen_rand_vec::<_, GF2p64>(&mut rng, 1)[0];
        let c = a * b;

        let (a1, a2, a3) = secret_share(&mut rng, &a);
        let (b1, b2, b3) = secret_share(&mut rng, &b);
        let program = |a: RssShare<GF2p64>, b: RssShare<GF2p64>| {
            move |p: &mut MainParty| {
                let c = weak_mult(p, &a, &b).unwrap();
                c
            }
        };
        let ((c1, _), (c2, _), (c3, _)) =
            PartySetup::localhost_setup(program(a1, b1), program(a2, b2), program(a3, b3));
        consistent(&c1, &c2, &c3);
        assert_eq(c1, c2, c3, c)
    }

    #[test]
    fn test_weak_dot() {
        let mut rng = thread_rng();
        let a_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, 32);
        let b_vec: Vec<GF2p64> = gen_rand_vec(&mut rng, 32);
        let c: GF2p64 = a_vec
            .iter()
            .zip(&b_vec)
            .fold(GF2p64::ZERO, |s, (&a, b)| s + a * *b);

        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let program = |a: Vec<RssShare<GF2p64>>, b: Vec<RssShare<GF2p64>>| {
            move |p: &mut MainParty| {
                let c = GF2p64::weak_inner_product(&a, &b);
                ss_to_rss_shares(p, &[c]).unwrap()[0]
            }
        };
        let ((c1, _), (c2, _), (c3, _)) =
            PartySetup::localhost_setup(program(a1, b1), program(a2, b2), program(a3, b3));
        consistent(&c1, &c2, &c3);
        assert_eq(c1, c2, c3, c)
    }

    #[test]
    fn test_lagrange() {
        // Random test case computed with sage
        let h0 = GF2p64::new(0xae4c7d19aef1dbda_u64);
        let h1 = GF2p64::new(0x6b86224afd87c726_u64);
        let h2 = GF2p64::new(0x5dfdd6bed2aa767c_u64);
        let x = GF2p64::new(0x0f1ee7a8005230eb_u64);
        let y = GF2p64::new(0x6a6446037f403245_u64);
        let mut rng = thread_rng();
        let (h01, h02, h03) = secret_share(&mut rng, &h0);
        let (h11, h12, h13) = secret_share(&mut rng, &h1);
        let (h21, h22, h23) = secret_share(&mut rng, &h2);
        let program =
            |h0: RssShare<GF2p64>, h1: RssShare<GF2p64>, h2: RssShare<GF2p64>, x: GF2p64| {
                move |_p: &mut WL16ASParty| lagrange_deg2(&h0, &h1, &h2, x)
            };
        let ((r1, _), (r2, _), (r3, _)) = localhost_setup_wl16as::<WL16DefaultParams, _, _, _, _, _, _>(
            program(h01, h11, h21, x),
            program(h02, h12, h22, x),
            program(h03, h13, h23, x),
            None,
        );
        consistent(&r1, &r2, &r3);
        assert_eq(r1, r2, r3, y)
    }

    #[test]
    fn test_inner_prod_correctness() {
        let mut rng = thread_rng();
        let a_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, 32);
        let b_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, 32);
        let c: GF2p64 = a_vec
            .iter()
            .zip(&b_vec)
            .fold(GF2p64::ZERO, |s, (&a, b)| s + a * *b);
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share(&mut rng, &c);
        let program = |a: Vec<RssShare<GF2p64>>, b: Vec<RssShare<GF2p64>>, c: RssShare<GF2p64>| {
            move |p: &mut MainParty| {
                let mut context = BroadcastContext::new();
                let res = verify_dot_product(p, &mut context, a, b, c).unwrap();
                p.compare_view(context).unwrap();
                res
            }
        };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_inner_prod_correctness_mt() {
        const N: usize = 1 << 15;
        const N_THREADS: usize = 3;
        let mut rng = thread_rng();
        let a_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, N);
        let b_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, N);
        let c: GF2p64 = a_vec
            .iter()
            .zip(&b_vec)
            .fold(GF2p64::ZERO, |s, (&a, b)| s + a * *b);
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share(&mut rng, &c);
        let program = |a: Vec<RssShare<GF2p64>>, b: Vec<RssShare<GF2p64>>, c: RssShare<GF2p64>| {
            move |p: &mut MainParty| {
                let mut context = BroadcastContext::new();
                let res = verify_dot_product_opt(p, &mut context, a, b, c).unwrap();
                p.compare_view(context).unwrap();
                res
            }
        };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup_multithreads(
            N_THREADS,
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_inner_prod_soundness() {
        let mut rng = thread_rng();
        let a_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, 32);
        let b_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, 32);
        let c: GF2p64 = a_vec
            .iter()
            .zip(&b_vec)
            .fold(GF2p64::ZERO, |s, (&a, b)| s + a * *b);
        // Offset product by random amount
        let mut r = gen_rand_vec::<_, GF2p64>(&mut rng, 1)[0];
        if r.is_zero() {
            r = GF2p64::ONE
        }
        let c = c + r;
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share(&mut rng, &c);
        let program = |a: Vec<RssShare<GF2p64>>, b: Vec<RssShare<GF2p64>>, c: RssShare<GF2p64>| {
            move |p: &mut MainParty| verify_dot_product(p, &mut BroadcastContext::new(), a, b, c).unwrap()
        };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, false);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf4_mul_verify_correctness() {
        let n = 31;
        let mut rng = thread_rng();
        let a_vec: Vec<BsGF4> = gen_rand_vec::<_, BsGF4>(&mut rng, n);
        let b_vec: Vec<BsGF4> = gen_rand_vec::<_, BsGF4>(&mut rng, n);
        let c_vec: Vec<BsGF4> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);
        let program =
            |a: Vec<RssShare<BsGF4>>, b: Vec<RssShare<BsGF4>>, c: Vec<RssShare<BsGF4>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    let res = verify_multiplication_triples(p, &mut context, &mut [&mut BsGF4Encoder(&mut triples)], false).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vector is cleared
                    assert_eq!(triples.len(), 0);
                    res
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf2_mul_verify_correctness() {
        let n = 32;
        let mut rng = thread_rng();
        let a_vec: Vec<BsBool16> = gen_rand_vec::<_, BsBool16>(&mut rng, n);
        let b_vec: Vec<BsBool16> = gen_rand_vec::<_, BsBool16>(&mut rng, n);
        let c_vec: Vec<BsBool16> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);
        let program =
            |a: Vec<RssShare<BsBool16>>, b: Vec<RssShare<BsBool16>>, c: Vec<RssShare<BsBool16>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    let res = verify_multiplication_triples(p, &mut context, &mut [&mut BsBool16Encoder(&mut triples)], false).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vector is cleared
                    assert_eq!(triples.len(), 0);
                    res
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf64_mul_verify_correctness() {
        let n = 32;
        let mut rng = thread_rng();
        let a_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, n);
        let b_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, n);
        let c_vec: Vec<GF2p64> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);
        let program =
            |a: Vec<RssShare<GF2p64>>, b: Vec<RssShare<GF2p64>>, c: Vec<RssShare<GF2p64>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    let res = verify_multiplication_triples(p, &mut context, &mut [&mut GF2p64Encoder(&mut triples)], false).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vector is cleared
                    assert_eq!(triples.len(), 0);
                    res
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf4_mul_verify_soundness() {
        let n = 32;
        let mut rng = thread_rng();
        let a_vec: Vec<BsGF4> = gen_rand_vec::<_, BsGF4>(&mut rng, n);
        let b_vec: Vec<BsGF4> = gen_rand_vec::<_, BsGF4>(&mut rng, n);
        let mut c_vec: Vec<BsGF4> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let mut r = gen_rand_vec::<_, BsGF4>(&mut rng, 1)[0];
        if r.is_zero() {
            r = BsGF4::ONE
        }
        c_vec[rng.gen_range(0..n)] += r;
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);
        let program =
            |a: Vec<RssShare<BsGF4>>, b: Vec<RssShare<BsGF4>>, c: Vec<RssShare<BsGF4>>| {
                move |p: &mut MainParty| {
                    let mut triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    verify_multiplication_triples(p, &mut BroadcastContext::new(), &mut [&mut BsGF4Encoder(&mut triples)], false).unwrap()
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, false);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf2_mul_verify_soundness() {
        let n = 32;
        let mut rng = thread_rng();
        let a_vec: Vec<BsBool16> = gen_rand_vec::<_, BsBool16>(&mut rng, n);
        let b_vec: Vec<BsBool16> = gen_rand_vec::<_, BsBool16>(&mut rng, n);
        let mut c_vec: Vec<BsBool16> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let mut r = gen_rand_vec::<_, BsBool16>(&mut rng, 1)[0];
        if r.is_zero() {
            r = BsBool16::ONE
        }
        c_vec[rng.gen_range(0..n)] += r;
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);
        let program =
            |a: Vec<RssShare<BsBool16>>, b: Vec<RssShare<BsBool16>>, c: Vec<RssShare<BsBool16>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    verify_multiplication_triples(p, &mut context, &mut [&mut BsBool16Encoder(&mut triples)], false).unwrap()
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, false);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf64_mul_verify_soundness() {
        let n = 32;
        let mut rng = thread_rng();
        let a_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, n);
        let b_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, n);
        let mut c_vec: Vec<GF2p64> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let mut r = gen_rand_vec::<_, GF2p64>(&mut rng, 1)[0];
        if r.is_zero() {
            r = GF2p64::ONE
        }
        c_vec[rng.gen_range(0..n)] += r;
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);
        let program =
            |a: Vec<RssShare<GF2p64>>, b: Vec<RssShare<GF2p64>>, c: Vec<RssShare<GF2p64>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    verify_multiplication_triples(p, &mut context, &mut [&mut GF2p64Encoder(&mut triples)], false).unwrap()
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, false);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf2_and_gf4_and_gf64_mul_verify_correctness() {
        let n = 31;
        let mut rng = thread_rng();
        let a_vec: Vec<BsGF4> = gen_rand_vec::<_, BsGF4>(&mut rng, n);
        let b_vec: Vec<BsGF4> = gen_rand_vec::<_, BsGF4>(&mut rng, n);
        let c_vec: Vec<BsGF4> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);

        let x_vec: Vec<BsBool16> = gen_rand_vec(&mut rng, n);
        let y_vec: Vec<BsBool16> = gen_rand_vec(&mut rng, n);
        let z_vec: Vec<BsBool16> = x_vec.iter().zip(y_vec.iter()).map(|(x,y)| *x * *y).collect();
        let (x1, x2, x3) = secret_share_vector(&mut rng, x_vec);
        let (y1, y2, y3) = secret_share_vector(&mut rng, y_vec);
        let (z1, z2, z3) = secret_share_vector(&mut rng, z_vec);

        let u_vec: Vec<GF2p64> = gen_rand_vec(&mut rng, n);
        let v_vec: Vec<GF2p64> = gen_rand_vec(&mut rng, n);
        let w_vec: Vec<GF2p64> = u_vec.iter().zip(v_vec.iter()).map(|(x,y)| *x * *y).collect();
        let (u1, u2, u3) = secret_share_vector(&mut rng, u_vec);
        let (v1, v2, v3) = secret_share_vector(&mut rng, v_vec);
        let (w1, w2, w3) = secret_share_vector(&mut rng, w_vec);

        let program =
            |a: Vec<RssShare<BsGF4>>, b: Vec<RssShare<BsGF4>>, c: Vec<RssShare<BsGF4>>, 
            x: Vec<RssShare<BsBool16>>, y: Vec<RssShare<BsBool16>>, z: Vec<RssShare<BsBool16>>,
            u: Vec<RssShare<GF2p64>>, v: Vec<RssShare<GF2p64>>, w: Vec<RssShare<GF2p64>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut gf4_triples = MulTripleVector::new();
                    let mut gf2_triples = MulTripleVector::new();
                    let mut gf64_triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        gf4_triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    izip!(x, y, z).for_each(|(x,y,z)| {
                        gf2_triples.record_mul_triple(&[x.si], &[x.sii], &[y.si], &[y.sii], &[z.si], &[z.sii]);
                    });
                    izip!(u, v, w).for_each(|(u,v,w)| {
                        gf64_triples.record_mul_triple(&[u.si], &[u.sii], &[v.si], &[v.sii], &[w.si], &[w.sii])
                    });
                    let res = verify_multiplication_triples(p, &mut context, &mut [&mut BsGF4Encoder(&mut gf4_triples), &mut BsBool16Encoder(&mut gf2_triples), &mut GF2p64Encoder(&mut gf64_triples)], false).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vectors are cleared
                    assert_eq!(gf4_triples.len(), 0);
                    assert_eq!(gf2_triples.len(), 0);
                    assert_eq!(gf64_triples.len(), 0);
                    res
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1, x1, y1, z1, u1, v1, w1),
            program(a2, b2, c2, x2, y2, z2, u2, v2, w2),
            program(a3, b3, c3, x3, y3, z3, u3, v3, w3),
        );
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf2_and_gf4_and_gf64_mul_verify_correctness_mt() {
        let n = 1 << 12;
        const N_THREADS: usize = 3;
        let mut rng = thread_rng();
        let a_vec: Vec<BsGF4> = gen_rand_vec::<_, BsGF4>(&mut rng, n);
        let b_vec: Vec<BsGF4> = gen_rand_vec::<_, BsGF4>(&mut rng, n);
        let c_vec: Vec<BsGF4> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);

        let x_vec: Vec<BsBool16> = gen_rand_vec(&mut rng, n);
        let y_vec: Vec<BsBool16> = gen_rand_vec(&mut rng, n);
        let z_vec: Vec<BsBool16> = x_vec.iter().zip(y_vec.iter()).map(|(x,y)| *x * *y).collect();
        let (x1, x2, x3) = secret_share_vector(&mut rng, x_vec);
        let (y1, y2, y3) = secret_share_vector(&mut rng, y_vec);
        let (z1, z2, z3) = secret_share_vector(&mut rng, z_vec);

        let u_vec: Vec<GF2p64> = gen_rand_vec(&mut rng, n);
        let v_vec: Vec<GF2p64> = gen_rand_vec(&mut rng, n);
        let w_vec: Vec<GF2p64> = u_vec.iter().zip(v_vec.iter()).map(|(x,y)| *x * *y).collect();
        let (u1, u2, u3) = secret_share_vector(&mut rng, u_vec);
        let (v1, v2, v3) = secret_share_vector(&mut rng, v_vec);
        let (w1, w2, w3) = secret_share_vector(&mut rng, w_vec);


        let program =
            |a: Vec<RssShare<BsGF4>>, b: Vec<RssShare<BsGF4>>, c: Vec<RssShare<BsGF4>>, 
            x: Vec<RssShare<BsBool16>>, y: Vec<RssShare<BsBool16>>, z: Vec<RssShare<BsBool16>>,
            u: Vec<RssShare<GF2p64>>, v: Vec<RssShare<GF2p64>>, w: Vec<RssShare<GF2p64>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut gf4_triples = MulTripleVector::new();
                    let mut gf2_triples = MulTripleVector::new();
                    let mut gf64_triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        gf4_triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    izip!(x, y, z).for_each(|(x,y,z)| {
                        gf2_triples.record_mul_triple(&[x.si], &[x.sii], &[y.si], &[y.sii], &[z.si], &[z.sii]);
                    });
                    izip!(u, v, w).for_each(|(u,v,w)| {
                        gf64_triples.record_mul_triple(&[u.si], &[u.sii], &[v.si], &[v.sii], &[w.si], &[w.sii])
                    });
                    let res = verify_multiplication_triples_mt(p, &mut context, &mut [&mut BsGF4Encoder(&mut gf4_triples), &mut BsBool16Encoder(&mut gf2_triples), &mut GF2p64Encoder(&mut gf64_triples)], false).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vectors are cleared
                    assert_eq!(gf4_triples.len(), 0);
                    assert_eq!(gf2_triples.len(), 0);
                    assert_eq!(gf64_triples.len(), 0);
                    res
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup_multithreads(
            N_THREADS,
            program(a1, b1, c1, x1, y1, z1, u1, v1, w1),
            program(a2, b2, c2, x2, y2, z2, u2, v2, w2),
            program(a3, b3, c3, x3, y3, z3, u3, v3, w3),
        );
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf8_mul_verify_correctness() {
        let n = 32;
        let mut rng = thread_rng();
        let a_vec: Vec<GF8> = gen_rand_vec::<_, GF8>(&mut rng, n);
        let b_vec: Vec<GF8> = gen_rand_vec::<_, GF8>(&mut rng, n);
        let c_vec: Vec<GF8> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);
        let program =
            |a: Vec<RssShare<GF8>>, b: Vec<RssShare<GF8>>, c: Vec<RssShare<GF8>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    let res = verify_multiplication_triples(p, &mut context, &mut [&mut GF2p64SubfieldEncoder(&mut triples)], false).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vector is cleared
                    assert_eq!(triples.len(), 0);
                    res
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf8_mul_verify_soundness() {
        let n = 32;
        let mut rng = thread_rng();
        let a_vec: Vec<GF8> = gen_rand_vec::<_, GF8>(&mut rng, n);
        let b_vec: Vec<GF8> = gen_rand_vec::<_, GF8>(&mut rng, n);
        let mut c_vec: Vec<GF8> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let mut r = gen_rand_vec::<_, GF8>(&mut rng, 1)[0];
        if r.is_zero() {
            r = GF8::ONE
        }
        c_vec[rng.gen_range(0..n)] += r;
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);
        let program =
            |a: Vec<RssShare<GF8>>, b: Vec<RssShare<GF8>>, c: Vec<RssShare<GF8>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    verify_multiplication_triples(p, &mut context, &mut [&mut GF2p64SubfieldEncoder(&mut triples)], false).unwrap()
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, false);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf8_mul_verify_correctness_mt() {
        let n = 1 << 12;
        const N_THREADS: usize = 3;
        let mut rng = thread_rng();
        let a_vec: Vec<GF8> = gen_rand_vec::<_, GF8>(&mut rng, n);
        let b_vec: Vec<GF8> = gen_rand_vec::<_, GF8>(&mut rng, n);
        let c_vec: Vec<GF8> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);
        let program =
            |a: Vec<RssShare<GF8>>, b: Vec<RssShare<GF8>>, c: Vec<RssShare<GF8>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    let res = verify_multiplication_triples_mt(p, &mut context, &mut [&mut GF2p64SubfieldEncoder(&mut triples)], false).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vector is cleared
                    assert_eq!(triples.len(), 0);
                    res
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup_multithreads(
            N_THREADS,
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf8_mul_verify_soundness_mt() {
        let n = 1 << 12;
        const N_THREADS: usize = 3;
        let mut rng = thread_rng();
        let a_vec: Vec<GF8> = gen_rand_vec::<_, GF8>(&mut rng, n);
        let b_vec: Vec<GF8> = gen_rand_vec::<_, GF8>(&mut rng, n);
        let mut c_vec: Vec<GF8> = a_vec.iter().zip(&b_vec).map(|(&a, &b)| a * b).collect();
        let mut r = gen_rand_vec::<_, GF8>(&mut rng, 1)[0];
        if r.is_zero() {
            r = GF8::ONE
        }
        c_vec[rng.gen_range(0..n)] += r;
        let (a1, a2, a3) = secret_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = secret_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = secret_share_vector(&mut rng, c_vec);
        let program =
            |a: Vec<RssShare<GF8>>, b: Vec<RssShare<GF8>>, c: Vec<RssShare<GF8>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    verify_multiplication_triples_mt(p, &mut context, &mut [&mut GF2p64SubfieldEncoder(&mut triples)], false).unwrap()
                }
            };
        let ((r1, _), (r2, _), (r3, _)) = PartySetup::localhost_setup_multithreads(
            N_THREADS,
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(r1, false);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }
}
