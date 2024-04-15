use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::{party::ArithmeticBlackBox, share::{Field, FieldDigestExt, FieldRngExt, RssShare}};

use super::WL16ASParty;

/// Protocol [TODO Add Number at the end] CheckTriple 
fn check_triple<F: Field + Copy>(party: &mut WL16ASParty<F>, x: &RssShare<F>, y: &RssShare<F>, z: &RssShare<F>)  -> bool 
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
{
    // Generate RSS sharing of random value
    let x_prime = party.inner.generate_random(1)[0];
    let z_prime = weak_mult(party, &x_prime,y);
    let t = coin_flip();
    let rho = reconstruct(party, *x + x_prime*t);
    return reconstruct(party, *z + z_prime*t - *y*rho).is_zero()
}

fn reconstruct<F: Field + Copy>(party: &mut WL16ASParty<F>, rho: RssShare<F>) -> F {
    todo!() // semi-honest + hashing
}

fn coin_flip<F: Field + Copy>() -> F {
    todo!() // random + open
}

fn weak_mult<F: Field + Copy>(party: &mut WL16ASParty<F>, x_prime: &RssShare<F>, y: &RssShare<F>) -> RssShare<F> {
    todo!() // local-mult + share conversion
}  

