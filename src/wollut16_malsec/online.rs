use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::{network::task::Direction, party::{error::MpcResult, ArithmeticBlackBox}, share::{Field, FieldDigestExt, FieldRngExt, RssShare}};

use super::WL16ASParty;

/// Protocol to verify the component-wise multiplication triples
/// 
/// This protocol assumes that the input vectors are of length 2^n for some n.
fn verify_dot_product<F: Field + Copy>(party: &mut WL16ASParty<F>, x_vec: &[RssShare<F>], y_vec: &[RssShare<F>], z_vec: &[RssShare<F>]) -> MpcResult<bool> 
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
{
    let n = x_vec.len();
    debug_assert_eq!(n, y_vec.len());
    debug_assert_eq!(n, z_vec.len());
    debug_assert!(n&(n-1) == 0 && n != 0);
    if n == 1 {
        return check_triple(party, &x_vec[0], &y_vec[0], &z_vec[0])
    }
    Ok(true)
}

/// Protocol [TODO Add Number at the end] CheckTriple 
fn check_triple<F: Field + Copy>(party: &mut WL16ASParty<F>, x: &RssShare<F>, y: &RssShare<F>, z: &RssShare<F>)  -> MpcResult<bool> 
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
{
    // Generate RSS sharing of random value
    let x_prime = party.inner.generate_random(1)[0];
    let z_prime = weak_mult(party, &[x_prime],&[*y]).unwrap()[0];
    let t = coin_flip(party);
    let rho = reconstruct(party, *x + x_prime*t);
    Ok(reconstruct(party, *z + z_prime*t - *y*rho).is_zero())
}

fn reconstruct<F: Field + Copy>(party: &mut WL16ASParty<F>, rho: RssShare<F>) -> F {
    todo!() // semi-honest + hashing
}

/// Coin flip protocol returns a random value in F
/// 
/// Generates a sharing of a random value that is then reconstructed globally.
fn coin_flip<F: Field + Copy>(party: &mut WL16ASParty<F>) -> F 
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
{
    let r: RssShare<F> = party.inner.generate_random(1)[0];
    reconstruct(party, r)
}

/// Computes the components wise multiplication of replicated shared vectors x and y.
fn weak_mult<F: Field + Copy + Sized>(party: &mut WL16ASParty<F>, x: &[RssShare<F>], y: &[RssShare<F>]) -> MpcResult<Vec<RssShare<F>>> 
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
{
    debug_assert_eq!(x.len(), y.len());
    let zs:Vec<F> = x.iter().zip(y).map(|(x,y)|{
        x.si * y.si + (x.si + x.sii) * (y.si + y.sii)
    }).collect();
    // Convert zs to RSS sharing
    let alphas:Vec<F> = party.inner.generate_alpha(zs.len());
    let mut z_i = vec![F::ZERO; zs.len()];
    let mut z_ii = vec![F::ZERO; zs.len()];
    z_i.iter_mut().enumerate().for_each(|(j, z_i)| {
        *z_i = zs[j] + alphas[j]
    });
    party.inner.io().send_field::<F>(Direction::Previous, z_i.iter());
    party.inner.io().receive_field_slice(Direction::Next, &mut z_ii).rcv()?;
    party.inner.io().wait_for_completion();
    let z_rss: Vec<RssShare<F>> = z_i.iter().zip(z_ii).map(|(&si, sii)|{RssShare::from(si, sii)}).collect();
    Ok(z_rss)
} 