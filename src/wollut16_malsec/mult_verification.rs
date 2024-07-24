use std::slice;

use itertools::izip;
use rand_chacha::ChaCha20Rng;
use rayon::{iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator}, slice::{ParallelSlice, ParallelSliceMut}};
use sha2::Sha256;

use crate::{
    network::task::Direction,
    party::{broadcast::{Broadcast, BroadcastContext}, error::MpcResult, MainParty, MulTripleVector, Party},
    share::{
        bs_bool16::BsBool16, gf2p64::{GF2p64, GF2p64InnerProd, GF2p64Subfield}, gf4::BsGF4, Field, FieldDigestExt, FieldRngExt, HasTwo, InnerProduct, Invertible, RssShare, RssShareVec
    },
};

/// Protocol `8` to verify the multiplication triples at the end of the protocol.
pub fn verify_multiplication_triples(party: &mut MainParty, context: &mut BroadcastContext, gf4_triples: &mut MulTripleVector<BsGF4>, gf2_triples: &mut MulTripleVector<BsBool16>) -> MpcResult<bool> {
    let r: GF2p64 = coin_flip(party, context)?;
    let k1 = gf4_triples.len() * 2; //each BsGF4 contains two values
    let k2 = gf2_triples.len() * 16; //each BsBool16 contains 16 values
    let n = (k1+k2).checked_next_power_of_two().expect("n too large");

    // let add_triples_time = Instant::now();

    let mut x_vec = vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); n];
    let mut y_vec = vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); n];
    let mut z = RssShare::from(GF2p64::ZERO, GF2p64::ZERO);
    let mut weight = GF2p64::ONE;

    if k1 > 0 {
        let (ai, aii, bi, bii, ci, cii) = (gf4_triples.ai(), gf4_triples.aii(), gf4_triples.bi(), gf4_triples.bii(), gf4_triples.ci(), gf4_triples.cii());
        (z, weight) = add_gf4_triples(&mut x_vec[..k1], &mut y_vec[..k1], ai, aii, bi, bii, ci, cii, z, r);
        gf4_triples.clear();
    }

    if k2 > 0 {
        // Add GF2 triples 
        // The embedding of GF2 is trivial, i.e. 0 -> 0 and 1 -> 1.
        let (ai, aii, bi, bii, ci, cii) = (gf2_triples.ai(), gf2_triples.aii(), gf2_triples.bi(), gf2_triples.bii(), gf2_triples.ci(), gf2_triples.cii());
        z = add_gf2_triples(&mut x_vec[k1..(k1+k2)], &mut y_vec[k1..(k1+k2)], ai, aii, bi, bii, ci, cii, z, weight, r);
        gf2_triples.clear();
    }
    // println!("add_triples_time={}s", add_triples_time.elapsed().as_secs_f64());
    verify_dot_product_opt(party, context, x_vec, y_vec, z)
}

#[rustfmt::skip]
pub fn verify_multiplication_triples_mt(party: &mut MainParty, context: &mut BroadcastContext, gf4_triples: &mut MulTripleVector<BsGF4>, gf2_triples: &mut MulTripleVector<BsBool16>) -> MpcResult<bool> {
    let k1 = gf4_triples.len() * 2; //each BsGF4 contains two values
    let k2 = gf2_triples.len() * 16; //each BsBool16 contains 16 values
    let n = (k1+k2).checked_next_power_of_two().expect("n too large");
    if (k1+k2) < (1 << 14) {
        // don't use multi-threading for such small task
        return verify_multiplication_triples(party, context, gf4_triples, gf2_triples);
    }
    // let add_triples_time = Instant::now();

    let n_threads = party.num_worker_threads();
    let chunk_size_gf4 = party.chunk_size_for_task(gf4_triples.len());
    let chunk_size_gf2 = party.chunk_size_for_task(gf2_triples.len());
    let r: Vec<GF2p64> = coin_flip_n(party, context, 2*n_threads)?;

    let mut x_vec = vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); n];
    let mut y_vec = vec![RssShare::from(GF2p64::ZERO, GF2p64::ZERO); n];

    let mut z = RssShare::from(GF2p64::ZERO, GF2p64::ZERO);
    if k1 > 0 {
        let (ai, aii, bi, bii, ci, cii) = (gf4_triples.ai(), gf4_triples.aii(), gf4_triples.bi(), gf4_triples.bii(), gf4_triples.ci(), gf4_triples.cii());
        z = party.run_in_threadpool(|| {
            let z_gf4 = r[..n_threads].par_iter()
                .zip_eq(x_vec[..k1].par_chunks_mut(2*chunk_size_gf4))
                .zip_eq(y_vec[..k1].par_chunks_mut(2*chunk_size_gf4))
                .zip_eq(ai.par_chunks(chunk_size_gf4))
                .zip_eq(aii.par_chunks(chunk_size_gf4))
                .zip_eq(bi.par_chunks(chunk_size_gf4))
                .zip_eq(bii.par_chunks(chunk_size_gf4))
                .zip_eq(ci.par_chunks(chunk_size_gf4))
                .zip_eq(cii.par_chunks(chunk_size_gf4))
                .map(|((((((((r, x_vec), y_vec), ai), aii), bi), bii), ci), cii)| {
                    let (z, _) = add_gf4_triples(x_vec, y_vec, ai, aii, bi, bii, ci, cii, RssShare::from(GF2p64::ZERO, GF2p64::ZERO), *r);
                    z
                })
                .reduce(|| RssShare::from(GF2p64::ZERO, GF2p64::ZERO), |sum, rss| sum + rss);
            Ok(z_gf4)
        })?;
        gf4_triples.clear();
    }
    

    // Add GF2 triples 
    // The embedding of GF2 is trivial, i.e. 0 -> 0 and 1 -> 1.
    if k2 > 0 {
        let (ai, aii, bi, bii, ci, cii) = (gf2_triples.ai(), gf2_triples.aii(), gf2_triples.bi(), gf2_triples.bii(), gf2_triples.ci(), gf2_triples.cii());
        z += party.run_in_threadpool(|| {
            let z_gf2 = r[n_threads..].par_iter()
                .zip_eq(x_vec[k1..(k1+k2)].par_chunks_mut(16*chunk_size_gf2))
                .zip_eq(y_vec[k1..(k1+k2)].par_chunks_mut(16*chunk_size_gf2))
                .zip_eq(ai.par_chunks(chunk_size_gf2))
                .zip_eq(aii.par_chunks(chunk_size_gf2))
                .zip_eq(bi.par_chunks(chunk_size_gf2))
                .zip_eq(bii.par_chunks(chunk_size_gf2))
                .zip_eq(ci.par_chunks(chunk_size_gf2))
                .zip_eq(cii.par_chunks(chunk_size_gf2))
                .map(|((((((((r, x_vec), y_vec), ai), aii), bi), bii), ci), cii)| {
                    add_gf2_triples(x_vec, y_vec, ai, aii, bi, bii, ci, cii, RssShare::from(GF2p64::ZERO, GF2p64::ZERO), *r, *r)
                })
                .reduce(|| RssShare::from(GF2p64::ZERO, GF2p64::ZERO), |sum, rss| sum + rss);
            Ok(z_gf2)
        })?;
        gf2_triples.clear();
    }
    // println!("Add triples: {}", add_triples_time.elapsed().as_secs_f64());
    verify_dot_product_opt(party, context, x_vec, y_vec, z)
}

fn add_gf4_triples(x_vec: &mut [RssShare<GF2p64>], y_vec: &mut [RssShare<GF2p64>], ai: &[BsGF4], aii: &[BsGF4], bi: &[BsGF4], bii: &[BsGF4], ci: &[BsGF4], cii: &[BsGF4], z_init: RssShare<GF2p64>, rand: GF2p64) -> (RssShare<GF2p64>, GF2p64) {
    debug_assert_eq!(x_vec.len(), y_vec.len());
    debug_assert_eq!(x_vec.len(), 2*ai.len());
    let mut z = z_init;
    let mut z_i = GF2p64InnerProd::new();
    let mut z_ii = GF2p64InnerProd::new();
    let mut weight = rand;
    let mut i = 0;
    izip!(ai, aii, bi, bii, ci, cii).for_each(|(ai, aii, bi, bii, ci, cii)| {
        let (ai1, ai2) = ai.unpack();
        let (aii1, aii2) = aii.unpack();
        let (bi1, bi2) = bi.unpack();
        let (bii1, bii2) = bii.unpack();
        let (ci1, ci2) = ci.unpack();
        let (cii1, cii2) = cii.unpack();
        x_vec[i] = embed_sharing(ai1, aii1).mul_by_sc(weight);
        y_vec[i] = embed_sharing(bi1, bii1);
        z_i.add_prod(&ci1.embed(), &weight);
        z_ii.add_prod(&cii1.embed(), &weight);
        // z += embed_sharing(ci1, cii1).mul_by_sc(weight);
        weight *= rand;
        x_vec[i + 1] = embed_sharing(ai2, aii2).mul_by_sc(weight);
        y_vec[i + 1] = embed_sharing(bi2, bii2);
        z_i.add_prod(&ci2.embed(), &weight);
        z_ii.add_prod(&cii2.embed(), &weight);
        // z += embed_sharing(ci2, cii2).mul_by_sc(weight);
        weight *= rand;
        i += 2;
    });
    z.si += z_i.sum();
    z.sii += z_ii.sum();
    (z, weight)
}

fn add_gf2_triples(x_vec: &mut [RssShare<GF2p64>], y_vec: &mut [RssShare<GF2p64>], ai: &[BsBool16], aii: &[BsBool16], bi: &[BsBool16], bii: &[BsBool16], ci: &[BsBool16], cii: &[BsBool16], z_init: RssShare<GF2p64>, mut weight: GF2p64, rand: GF2p64) -> RssShare<GF2p64> {
    debug_assert_eq!(x_vec.len(), y_vec.len());
    debug_assert_eq!(x_vec.len(), 16*ai.len());
    let mut z = z_init;
    let mut z_i = GF2p64InnerProd::new();
    let mut z_ii = GF2p64InnerProd::new();
    let mut i = 0;
    izip!(ai, aii, bi, bii, ci, cii).for_each(|(ai, aii, bi, bii, ci, cii)| {
        let ai = gf2_embed(*ai);
        let aii = gf2_embed(*aii);
        let bi = gf2_embed(*bi);
        let bii = gf2_embed(*bii);
        let ci = gf2_embed(*ci);
        let cii = gf2_embed(*cii);
        for j in 0..16 {
            x_vec[i + j] = RssShare::from(ai[j],aii[j]).mul_by_sc(weight);
            y_vec[i + j] = RssShare::from(bi[j],bii[j]);
            z_i.add_prod(&ci[j], &weight);
            z_ii.add_prod(&cii[j], &weight);
            // z += RssShare::from(,cii[j]).mul_by_sc(weight);
            weight *= rand;
        }
        i += 16;
    });
    z.si += z_i.sum();
    z.sii += z_ii.sum();
    z
}

fn gf2_embed(s:BsBool16) -> [GF2p64;16] {
    let mut res = [GF2p64::ZERO;16];
    let s = s.as_u16();
    res.iter_mut().enumerate().for_each(|(i,r)| {
        if s & 1 << i != 0 {
            *r = GF2p64::ONE;
        }
    });
    res
}

/// Embed
fn embed_sharing<F>(si: F, sii: F) -> RssShare<GF2p64>
where
    F: Field + Copy + GF2p64Subfield,
{
    RssShare::from(si.embed(), sii.embed())
}

/// Protocol to verify the component-wise multiplication triples
///
/// This protocol assumes that the input vectors are of length 2^n for some n.
fn verify_dot_product<F: Field + Copy + HasTwo + Invertible>(
    party: &mut MainParty,
    context: &mut BroadcastContext,
    x_vec: Vec<RssShare<F>>,
    y_vec: Vec<RssShare<F>>,
    z: RssShare<F>,
) -> MpcResult<bool>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
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

fn verify_dot_product_opt<F: Field + Copy + HasTwo + Invertible + Send + Sync>(
    party: &mut MainParty,
    context: &mut BroadcastContext,
    mut x_vec: Vec<RssShare<F>>,
    mut y_vec: Vec<RssShare<F>>,
    z: RssShare<F>,
) -> MpcResult<bool>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
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

/// Protocol [TODO Add Number at the end] CheckTriple
fn check_triple<F: Field + Copy>(
    party: &mut MainParty,
    context: &mut BroadcastContext,
    x: RssShare<F>,
    y: RssShare<F>,
    z: RssShare<F>,
) -> MpcResult<bool>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
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
fn lagrange_deg2<F: Field + Copy + HasTwo + Invertible>(
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
    h0.mul_by_sc(l0) + h1.mul_by_sc(l1) + h2.mul_by_sc(l2)
}

fn reconstruct<F: Field + Copy>(party: &mut MainParty, context: &mut BroadcastContext, rho: RssShare<F>) -> MpcResult<F>
where
    Sha256: FieldDigestExt<F>,
{
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
fn coin_flip<F: Field + Copy>(party: &mut MainParty, context: &mut BroadcastContext) -> MpcResult<F>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    let r: RssShare<F> = party.generate_random(1)[0];
    reconstruct(party, context, r)
}

/// Coin flip protocol returns a n random values in F
///
/// Generates a sharing of a n random values that is then reconstructed globally.
fn coin_flip_n<F: Field + Copy>(party: &mut MainParty, context: &mut BroadcastContext, n: usize) -> MpcResult<Vec<F>>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    let (r_i, r_ii): (Vec<_>, Vec<_>) = party.generate_random(n).into_iter().map(|rss| (rss.si, rss.sii)).unzip();
    party.open_rss(context, &r_i, &r_ii)
}

/// Computes the components wise multiplication of replicated shared x and y.
fn weak_mult<F: Field + Copy + Sized>(
    party: &mut MainParty,
    x: &RssShare<F>,
    y: &RssShare<F>,
) -> MpcResult<RssShare<F>>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
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
) -> MpcResult<RssShareVec<F>>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    let n = sum_shares.len();
    let alphas = party.generate_alpha(n);
    let s_i: Vec<F> = sum_shares.iter().zip(alphas).map(|(s, a)| *s + a).collect();
    let mut s_ii = vec![F::ZERO; n];
    party.send_field::<F>(Direction::Previous, &s_i, n);
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
) -> MpcResult<RssShare<F>>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    // Convert zs to RSS sharing
    let s_i = [sum_share + party.generate_alpha(1)[0]];
    let mut s_ii = [F::ZERO; 1];
    party.send_field::<F>(Direction::Previous, s_i, 1);
    party.receive_field_slice(Direction::Next, &mut s_ii)
        .rcv()?;
    party.io().wait_for_completion();
    Ok(RssShare::from(s_i[0], s_ii[0]))
}

#[cfg(test)]
mod test {

    use itertools::izip;
    use rand::{thread_rng, CryptoRng, Rng};

    use crate::{
        party::{broadcast::{Broadcast, BroadcastContext}, test::{PartySetup, TestSetup}, MainParty, MulTripleRecorder, MulTripleVector}, share::{
            bs_bool16::BsBool16, gf2p64::GF2p64, gf4::BsGF4, test::{assert_eq, consistent, secret_share, secret_share_vector}, Field, FieldRngExt, InnerProduct, RssShare
        }, wollut16_malsec::{
            mult_verification::{verify_dot_product_opt, verify_multiplication_triples, verify_multiplication_triples_mt}, test::localhost_setup_wl16as,
            WL16ASParty,
        }
    };

    use super::{lagrange_deg2, ss_to_rss_shares, verify_dot_product, weak_mult};

    fn gen_rand_vec<R: Rng + CryptoRng, F: Field>(rng: &mut R, n: usize) -> Vec<F>
    where
        R: FieldRngExt<F>,
    {
        rng.generate(n)
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
        let (h1, h2, h3) =
            PartySetup::localhost_setup(program(a1, b1), program(a2, b2), program(a3, b3));
        let (c1, _) = h1.join().unwrap();
        let (c2, _) = h2.join().unwrap();
        let (c3, _) = h3.join().unwrap();
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
        let (h1, h2, h3) =
            PartySetup::localhost_setup(program(a1, b1), program(a2, b2), program(a3, b3));
        let (c1, _) = h1.join().unwrap();
        let (c2, _) = h2.join().unwrap();
        let (c3, _) = h3.join().unwrap();
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
        let (h1, h2, h3) = localhost_setup_wl16as(
            program(h01, h11, h21, x),
            program(h02, h12, h22, x),
            program(h03, h13, h23, x),
            None,
        );
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();
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
        let (h1, h2, h3) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();
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
        let (h1, h2, h3) = PartySetup::localhost_setup_multithreads(
            N_THREADS,
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();
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
        let (h1, h2, h3) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();
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
                    let res = verify_multiplication_triples(p, &mut context, &mut triples, &mut MulTripleVector::new()).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vector is cleared
                    assert_eq!(triples.len(), 0);
                    res
                }
            };
        let (h1, h2, h3) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();
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
                    let res = verify_multiplication_triples(p, &mut context, &mut MulTripleVector::new(), &mut triples).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vector is cleared
                    assert_eq!(triples.len(), 0);
                    res
                }
            };
        let (h1, h2, h3) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();
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
                    verify_multiplication_triples(p, &mut BroadcastContext::new(), &mut triples, &mut MulTripleVector::new()).unwrap()
                }
            };
        let (h1, h2, h3) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();
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
                    verify_multiplication_triples(p, &mut context, &mut MulTripleVector::new(), &mut triples).unwrap()
                }
            };
        let (h1, h2, h3) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();
        assert_eq!(r1, false);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf2_and_gf4_mul_verify_correctness() {
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

        let program =
            |a: Vec<RssShare<BsGF4>>, b: Vec<RssShare<BsGF4>>, c: Vec<RssShare<BsGF4>>, x: Vec<RssShare<BsBool16>>, y: Vec<RssShare<BsBool16>>, z: Vec<RssShare<BsBool16>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut gf4_triples = MulTripleVector::new();
                    let mut gf2_triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        gf4_triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    izip!(x, y, z).for_each(|(x,y,z)| {
                        gf2_triples.record_mul_triple(&[x.si], &[x.sii], &[y.si], &[y.sii], &[z.si], &[z.sii]);
                    });
                    let res = verify_multiplication_triples(p, &mut context, &mut gf4_triples, &mut gf2_triples).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vectors are cleared
                    assert_eq!(gf4_triples.len(), 0);
                    assert_eq!(gf2_triples.len(), 0);
                    res
                }
            };
        let (h1, h2, h3) = PartySetup::localhost_setup(
            program(a1, b1, c1, x1, y1, z1),
            program(a2, b2, c2, x2, y2, z2),
            program(a3, b3, c3, x3, y3, z3),
        );
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn test_gf2_and_gf4_mul_verify_correctness_mt() {
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

        let program =
            |a: Vec<RssShare<BsGF4>>, b: Vec<RssShare<BsGF4>>, c: Vec<RssShare<BsGF4>>, x: Vec<RssShare<BsBool16>>, y: Vec<RssShare<BsBool16>>, z: Vec<RssShare<BsBool16>>| {
                move |p: &mut MainParty| {
                    let mut context = BroadcastContext::new();
                    let mut gf4_triples = MulTripleVector::new();
                    let mut gf2_triples = MulTripleVector::new();
                    izip!(a.iter(), b.iter(), c.iter()).for_each(|(a, b, c)| {
                        gf4_triples
                            .record_mul_triple(&[a.si], &[a.sii], &[b.si], &[b.sii], &[c.si], &[c.sii]);
                    });
                    izip!(x, y, z).for_each(|(x,y,z)| {
                        gf2_triples.record_mul_triple(&[x.si], &[x.sii], &[y.si], &[y.sii], &[z.si], &[z.sii]);
                    });
                    let res = verify_multiplication_triples_mt(p, &mut context, &mut gf4_triples, &mut gf2_triples).unwrap();
                    p.compare_view(context).unwrap();
                    // triple vectors are cleared
                    assert_eq!(gf4_triples.len(), 0);
                    assert_eq!(gf2_triples.len(), 0);
                    res
                }
            };
        let (h1, h2, h3) = PartySetup::localhost_setup_multithreads(
            N_THREADS,
            program(a1, b1, c1, x1, y1, z1),
            program(a2, b2, c2, x2, y2, z2),
            program(a3, b3, c3, x3, y3, z3),
        );
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();
        assert_eq!(r1, true);
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);
    }
}
