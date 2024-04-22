use std::{fmt::Debug, slice};

use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::{
    network::task::Direction,
    party::{broadcast::Broadcast, error::MpcResult},
    share::{Field, FieldDigestExt, FieldRngExt, HasTwo, Invertible, RssShare},
};

use super::WL16ASParty;

/// Protocol to verify the component-wise multiplication triples
///
/// This protocol assumes that the input vectors are of length 2^n for some n.
fn verify_dot_product<F: Field + Copy + HasTwo + Invertible>(
    party: &mut WL16ASParty,
    x_vec: &[RssShare<F>],
    y_vec: &[RssShare<F>],
    z: &RssShare<F>,
) -> MpcResult<bool>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    let n = x_vec.len();
    debug_assert_eq!(n, y_vec.len());
    debug_assert!(n & (n - 1) == 0 && n != 0);
    if n == 1 {
        return check_triple(party, &x_vec[0], &y_vec[0], z);
    }
    // Compute dot products
    let f1: Vec<_> = x_vec.iter().skip(1).step_by(2).collect();
    let g1: Vec<_> = y_vec.iter().skip(1).step_by(2).collect();
    let f2: Vec<_> = x_vec
        .chunks(2)
        .map(|c| c[0] + (c[0] + c[1]) * F::TWO)
        .collect();
    let g2: Vec<_> = y_vec
        .chunks(2)
        .map(|c| c[0] + (c[0] + c[1]) * F::TWO)
        .collect();
    let mut hs = [F::ZERO; 2];
    hs[0] = weak_dot_prod(party, f1, g1);
    hs[1] = weak_dot_prod(party, &f2, &g2);
    let h = ss_to_rss_shares(party, &hs)?;
    let h1 = &h[0];
    let h2 = &h[1];
    let h0 = *z - *h1;
    // Coin flip
    let r = coin_flip(party)?;
    // For large F this is very unlikely
    debug_assert!(r != F::ZERO && r != F::ONE);
    // Compute polynomials
    let fr: Vec<_> = x_vec.chunks(2).map(|c| c[0] + (c[0] + c[1]) * r).collect();
    let gr: Vec<_> = y_vec.chunks(2).map(|c| c[0] + (c[0] + c[1]) * r).collect();
    let hr = lagrange_deg2(&h0, h1, h2, r);
    verify_dot_product(party, &fr, &gr, &hr)
}

/// Protocol [TODO Add Number at the end] CheckTriple
fn check_triple<F: Field + Copy>(
    party: &mut WL16ASParty,
    x: &RssShare<F>,
    y: &RssShare<F>,
    z: &RssShare<F>,
) -> MpcResult<bool>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    // Generate RSS sharing of random value
    let x_prime = party.inner.generate_random(1)[0];
    let z_prime = weak_mult(party, &x_prime, y)?;
    let t = coin_flip(party)?;
    let rho = reconstruct(party, *x + x_prime * t)?;
    reconstruct(party, *z + z_prime * t - *y * rho).map(|x| x.is_zero())
}

/// Shared lagrange evaluation of the polynomial h at position x for given (shared) points h(0), h(1), h(2)
#[inline]
fn lagrange_deg2<F: Field + Copy + HasTwo + Invertible>(
    h0: &RssShare<F>,
    h1: &RssShare<F>,
    h2: &RssShare<F>,
    x: F,
) -> RssShare<F>
{
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

fn reconstruct<F: Field + Copy>(party: &mut WL16ASParty, rho: RssShare<F>) -> MpcResult<F>
where
    Sha256: FieldDigestExt<F>,
{
    party
        .inner
        .open_rss(
            &mut party.broadcast_context,
            slice::from_ref(&rho.si),
            slice::from_ref(&rho.sii),
        )
        .map(|v| v[0])
}

/// Coin flip protocol returns a random value in F
///
/// Generates a sharing of a random value that is then reconstructed globally.
fn coin_flip<F: Field + Copy>(party: &mut WL16ASParty) -> MpcResult<F>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    let r: RssShare<F> = party.inner.generate_random(1)[0];
    reconstruct(party, r)
}

/// Computes the components wise multiplication of replicated shared x and y.
fn weak_mult<F: Field + Copy + Sized>(
    party: &mut WL16ASParty,
    x: &RssShare<F>,
    y: &RssShare<F>,
) -> MpcResult<RssShare<F>>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    // Compute a sum sharing of x*y
    let zs = x.si * y.si + (x.si + x.sii) * (y.si + y.sii);
    single_ss_to_rss_shares(party, zs)
}

/// Computes the dot product of vectors x and y given as replicated shares.
/// The result is a sum sharing.
///
/// This function assumes that both vectors are of equal length.
fn weak_dot_prod<'a, I, F: Field + Copy + Sized + 'a>(
    party: &mut WL16ASParty,
    x_vec: I,
    y_vec: I,
) -> F
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
    I: IntoIterator<Item = &'a RssShare<F>>,
{
    // Compute a sum sharing of the dot product
    let prod: F = x_vec.into_iter().zip(y_vec).fold(F::ZERO, |sum, (x, y)| {
        sum + x.si * y.si + (x.si + x.sii) * (y.si + y.sii)
    });
    prod
}

/// Converts a vector of sum sharings into a replicated sharing
#[inline]
fn ss_to_rss_shares<F: Field + Copy + Sized>(
    party: &mut WL16ASParty,
    sum_shares: &[F],
) -> MpcResult<Vec<RssShare<F>>>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    let n = sum_shares.len();
    let alphas = party.inner.generate_alpha(n);
    let s_i: Vec<F> = sum_shares.iter().zip(alphas).map(|(s, a)| *s + a).collect();
    let mut s_ii = vec![F::ZERO; n];
    party
        .inner
        .io()
        .send_field::<F>(Direction::Previous, &s_i, n);
    party
        .inner
        .io()
        .receive_field_slice(Direction::Next, &mut s_ii)
        .rcv()?;
    party.inner.io().wait_for_completion();
    let res: Vec<RssShare<F>> = s_ii
        .iter()
        .zip(s_i)
        .map(|(sii, si)| RssShare::from(si, *sii))
        .collect();
    Ok(res)
}

/// Converts a sum sharing into a replicated sharing
#[inline]
fn single_ss_to_rss_shares<F: Field + Copy + Sized>(
    party: &mut WL16ASParty,
    sum_share: F,
) -> MpcResult<RssShare<F>>
where
    Sha256: FieldDigestExt<F>,
    ChaCha20Rng: FieldRngExt<F>,
{
    // Convert zs to RSS sharing
    let s_i = [sum_share + party.inner.generate_alpha(1)[0]];
    let mut s_ii = [F::ZERO; 1];
    party
        .inner
        .io()
        .send_field::<F>(Direction::Previous, s_i, 1);
    party
        .inner
        .io()
        .receive_field_slice(Direction::Next, &mut s_ii)
        .rcv()?;
    party.inner.io().wait_for_completion();
    Ok(RssShare::from(s_i[0], s_ii[0]))
}

#[cfg(test)]
mod test {
    use std::borrow::Borrow;

    use rand::{thread_rng, CryptoRng, Rng};
    use sha2::digest::typenum::Zero;

    use crate::{
        share::{
            gf2p64::GF2p64,
            test::{assert_eq, consistent, secret_share, secret_share_vector},
            Field, FieldRngExt, RssShare,
        },
        wollut16_malsec::{test::localhost_setup_wl16as, WL16ASParty},
    };

    use super::{lagrange_deg2, ss_to_rss_shares, verify_dot_product, weak_dot_prod, weak_mult};

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
            move |p: &mut WL16ASParty| {
                let c = weak_mult(p, &a, &b).unwrap();
                c
            }
        };
        let (h1, h2, h3) =
            localhost_setup_wl16as(program(a1, b1), program(a2, b2), program(a3, b3));
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
            move |p: &mut WL16ASParty| {
                let c = weak_dot_prod(p, &a, &b);
                ss_to_rss_shares(p, &[c]).unwrap()[0]
            }
        };
        let (h1, h2, h3) =
            localhost_setup_wl16as(program(a1, b1), program(a2, b2), program(a3, b3));
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
        let program = |h0: RssShare<GF2p64>, h1: RssShare<GF2p64>, h2: RssShare<GF2p64>, x: GF2p64| {
            move |_p: &mut WL16ASParty| {
                lagrange_deg2(&h0, &h1, &h2, x)
            }
        }; 
        let (h1, h2, h3) =
            localhost_setup_wl16as(program(h01, h11, h21, x), program(h02, h12, h22, x), program(h03, h13, h23, x));
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap(); 
        consistent(&r1, &r2, &r3);
        assert_eq(r1, r2, r3, y)        
    }

    fn bogus_secret_share<F: Field, R: Rng + CryptoRng>(
        _rng: &mut R,
        x: &F,
    ) -> (RssShare<F>, RssShare<F>, RssShare<F>) {
        let x1 = RssShare::from(x.clone(), F::ZERO);
        let x2 = RssShare::from(F::ZERO, F::ZERO);
        let x3 = RssShare::from(F::ZERO, x.clone());
        (x1, x2, x3)
    }

    fn bogus_share_vector<F: Field, R: Rng + CryptoRng>(
        rng: &mut R,
        elements: impl IntoIterator<Item = impl Borrow<F>>,
    ) -> (Vec<RssShare<F>>, Vec<RssShare<F>>, Vec<RssShare<F>>)
    where
        R: FieldRngExt<F>,
    {
        let (s1, (s2, s3)) = elements
            .into_iter()
            .map(|value| {
                let (s1, s2, s3) = bogus_secret_share(rng, value.borrow());
                (s1, (s2, s3))
            })
            .unzip();
        (s1, s2, s3)
    }

    #[test]
    fn test_inner_prod() {
        let mut rng = thread_rng();
        let a_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, 32);
        let b_vec: Vec<GF2p64> = gen_rand_vec::<_, GF2p64>(&mut rng, 32);
        let c: GF2p64 = a_vec
            .iter()
            .zip(&b_vec)
            .fold(GF2p64::ZERO, |s, (&a, b)| s + a * *b);        
        let (a1, a2, a3) = bogus_share_vector(&mut rng, a_vec);
        let (b1, b2, b3) = bogus_share_vector(&mut rng, b_vec);
        let (c1, c2, c3) = bogus_secret_share(&mut rng, &c);
        let program = |a: Vec<RssShare<GF2p64>>, b: Vec<RssShare<GF2p64>>, c: RssShare<GF2p64>| {
            move |p: &mut WL16ASParty| {
                verify_dot_product(p, &a, &b, &c).unwrap()
            }
        }; 
        let (h1, h2, h3) =
            localhost_setup_wl16as(program(a1, b1, c1), program(a2, b2, c2), program(a3, b3, c3));
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();  
        assert_eq!(r1, true);   
        assert_eq!(r1, r2);
        assert_eq!(r1, r3);         
    }

}
