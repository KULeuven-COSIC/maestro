use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use crate::network::task::Direction;
use crate::party::broadcast::{Broadcast, BroadcastContext};
use crate::party::correlated_randomness::GlobalRng;
use crate::party::error::MpcError::SacrificeError;
use crate::party::error::MpcResult;
use crate::party::Party;
use crate::share::{Field, FieldRngExt, RssShare, FieldDigestExt};
use crate::share::field::GF8;

pub struct MulTriple<F: Field> {pub a: RssShare<F>, pub b: RssShare<F>, pub c: RssShare<F>}

pub struct RandomBit<F: Field>(RssShare<F>);

// creates a multiplication triple by creating ceil(soundness/|F|)+1 unchecked triples and then
// sacrificing ceil(soundness/|F|) triples to check one
// this is not efficient
pub fn create_correct_mul_triples<F: Field + Copy>(party: &mut Party, n: usize, soundness: usize) -> MpcResult<Vec<MulTriple<F>>>
    where ChaCha20Rng : FieldRngExt<F>,
    Sha256: FieldDigestExt<F>
{
    let (total_n, repetitions) = {
        let repetitions = soundness / (8*F::size());
        if soundness % (8*F::size()) != 0 {
            (n * (2+repetitions), 1+repetitions)
        }else { (n*(1+repetitions), repetitions) }
    };
    //println!("Total_n {}, repetitions {}", total_n, repetitions);

    let a_i: Vec<F> = party.random_prev.as_mut().generate(total_n);
    let a_ii = party.random_next.as_mut().generate(total_n);

    debug_assert_eq!(a_i.len(), total_n);
    debug_assert_eq!(a_ii.len(), total_n);

    let b_i = party.random_prev.as_mut().generate(total_n);
    let b_ii = party.random_next.as_mut().generate(total_n);

    debug_assert_eq!(b_i.len(), total_n);
    debug_assert_eq!(b_ii.len(), total_n);

    let alpha: Vec<F> = party.generate_alpha(total_n);

    debug_assert_eq!(alpha.len(), total_n);

    let mut c_i = vec![F::zero(); total_n];
    for i in 0..total_n {
        c_i[i] = (a_i[i] * b_i[i]) + (a_i[i] * b_ii[i]) + (a_ii[i] * b_i[i]) + alpha[i];
    }

    // send vi to P-1
    party.io().send_field::<F>(Direction::Previous, &c_i);
    // receive vii from P+1
    let c_ii = party.io().receive_field(Direction::Next, total_n).rcv()?;
    party.io().wait_for_completion();


    // get public random t's for sacrifice
    let mut rnd = GlobalRng::setup_global(party)?;
    let ts = rnd.as_mut().generate(repetitions);

    let mut rho_i = vec![F::zero(); repetitions * n];
    let mut rho_ii = vec![F::zero(); repetitions * n];
    let mut sigma_i = vec![F::zero(); repetitions * n];
    let mut sigma_ii = vec![F::zero(); repetitions * n];

    let mut rho_index = 0;
    let mut a_index = 0;
    for _i in 0..n {
        for rep in 0..repetitions {
            // rho = (t*a - f)
            rho_i[rho_index] = ts[rep] * a_i[a_index] - a_i[a_index+1+rep];
            rho_ii[rho_index] = ts[rep] * a_ii[a_index] - a_ii[a_index+1+rep];

            // sigma = b - g
            sigma_i[rho_index] = b_i[a_index] - b_i[a_index+1+rep];
            sigma_ii[rho_index] = b_ii[a_index] - b_ii[a_index+1+rep];

            rho_index += 1;
        }
        a_index += repetitions + 1;
    }

    let mut context = BroadcastContext::new();

    // open rho and sigma
    let rho = party.open_rss(&mut context, &rho_i, &rho_ii)?;
    let sigma = party.open_rss(&mut context, &sigma_i, &sigma_ii)?;

    // check correct open
    party.compare_view(context)?;

    let mut rho_index = 0;
    let mut a_index = 0;
    let mut zero_i = vec![F::zero(); repetitions * n];
    let mut zero_ii = vec![F::zero(); repetitions * n];
    for _i in 0..n {
        for rep in 0..repetitions {
            // t * c - h - sigma * f - rho * g - sigma * rho

            zero_i[rho_index] = (ts[rep] * c_i[a_index]) - c_i[a_index+1+rep] - (sigma[rho_index] * a_i[a_index+1+rep]) - (rho[rho_index] * b_i[a_index+1+rep]);
            zero_ii[rho_index] = (ts[rep] * c_ii[a_index]) - c_ii[a_index+1+rep] - (sigma[rho_index] * a_ii[a_index+1+rep]) - (rho[rho_index] * b_ii[a_index+1+rep]);

            if party.i == 0 {
                zero_i[rho_index] = zero_i[rho_index] - sigma[rho_index] * rho[rho_index];
            } else if party.i == 2 {
                zero_ii[rho_index] = zero_ii[rho_index] - sigma[rho_index] * rho[rho_index];
            }

            rho_index += 1;
        }
        a_index += repetitions + 1;
    }

    let mut context = BroadcastContext::new();

    // open zero
    let zero = party.open_rss(&mut context, &zero_i, &zero_ii)?;
    // check correct open
    party.compare_view(context)?;

    for z in zero {
        if !z.is_zero() {
            return Err(SacrificeError);
        }
    }

    let mut triples = Vec::with_capacity(n);
    for i in 0..n {
        let index = i * (repetitions+1);
        triples.push(MulTriple {
            a: RssShare::from(a_i[index], a_ii[index]),
            b: RssShare::from(b_i[index], b_ii[index]),
            c: RssShare::from(c_i[index], c_ii[index]),
        });
    }

    Ok(triples)
}

pub fn create_random_bits_gf8(party: &mut Party, global_rng: &mut GlobalRng, n: usize) -> Vec<RandomBit<GF8>> {
    let n_rand = if (n/8) % 8 == 0 { n / 8} else {n/8 + 1};

    let mut random_ri = vec![0; n_rand];
    let mut random_rii = vec![0; n_rand];
    party.random_prev.as_mut().fill_bytes(&mut random_ri);
    party.random_next.as_mut().fill_bytes(&mut random_rii);

    let mut vi = 0;
    let mut bit_i = 0;
    let mut res = Vec::with_capacity(n);
    for zero in party.generate_zero(global_rng, n) {
        let bi = RssShare::from(GF8((random_ri[vi] >> bit_i) & 0x1), GF8((random_rii[vi] >> bit_i) & 0x1));
        res.push(RandomBit(bi + zero));
        bit_i += 1;
        if bit_i >= 8 {
            bit_i = 0;
            vi += 1;
        }
    }
    res
}

#[cfg(test)]
mod test {
    use crate::party::correlated_randomness::GlobalRng;
    use crate::party::offline::{create_correct_mul_triples, create_random_bits_gf8};
    use crate::party::test::simple_localhost_setup;
    use crate::share::field::GF8;
    use crate::share::test::consistent;


    #[test]
    fn correct_gf8_triples() {
        const N: usize = 100;
        // generate N triples with soundness 2^-40
        let ((triples1, triples2, triples3), _) = simple_localhost_setup(|p| {
            create_correct_mul_triples::<GF8>(p, N, 40).unwrap()
        });

        assert_eq!(N, triples1.len());
        assert_eq!(N, triples2.len());
        assert_eq!(N, triples3.len());
        // check consistent
        for i in 0..N {
            consistent(&triples1[i].a, &triples2[i].a, &triples3[i].a);
            consistent(&triples1[i].b, &triples2[i].b, &triples3[i].b);
            consistent(&triples1[i].c, &triples2[i].c, &triples3[i].c);
        }

        // check correct
        for i in 0..N {
            let a = triples1[i].a.si + triples2[i].a.si + triples3[i].a.si;
            let b = triples1[i].b.si + triples2[i].b.si + triples3[i].b.si;
            let c = triples1[i].c.si + triples2[i].c.si + triples3[i].c.si;

            assert_eq!(a * b, c);
        }
    }

    #[test]
    fn correct_random_bits_gf8() {
        const N: usize = 100;
        let ((bits1, bits2, bits3), _) = simple_localhost_setup(|p| {
            let mut global_rng = GlobalRng::setup_global(p).unwrap();
            create_random_bits_gf8(p, &mut global_rng, N)
        });

        assert_eq!(bits1.len(), N);
        assert_eq!(bits2.len(), N);
        assert_eq!(bits3.len(), N);

        for (b1, (b2, b3)) in bits1.into_iter().zip(bits2.into_iter().zip(bits3)) {
            consistent(&b1.0, &b2.0, &b3.0);

            let b = b1.0.si + b2.0.si + b3.0.si;
            assert!(b == GF8(0) || b == GF8(1));
        }
    }
}