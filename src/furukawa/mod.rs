use itertools::{izip, Itertools};
use permutation::Permutation;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::{network::task::Direction, party::{broadcast::{Broadcast, BroadcastContext}, correlated_randomness::GlobalRng, error::{MpcError, MpcResult}, Party}, share::{field::GF8, Field, FieldDigestExt, FieldRngExt, RssShare}};

struct MulTripleVector<F> {
    // s.t. a*b = c
    ai: Vec<F>,
    aii: Vec<F>,
    bi: Vec<F>,
    bii: Vec<F>,
    ci: Vec<F>,
    cii: Vec<F>
}

pub struct FurukawaParty<F: Field> {
    inner: Party,
    triples_to_check: MulTripleVector<F>
}

pub fn input_round<F: Field>(party: &mut FurukawaParty<F>, my_input: impl IntoIterator<Item = F>) -> MpcResult<(Vec<RssShare<F>>, Vec<RssShare<F>>, Vec<RssShare<F>>)> {
    unimplemented!()
}

// struct Perm16(Permutation);

// impl Perm16 {
//     pub fn new<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> Self {
//         assert!(n < (1 << 16));
//         let 
//         let mut indices = Self(Permutation::oneline((0..n as u16).collect()));
//         // shuffle indices
//         indices.0.shuffle(rng);
//         indices
//     }

//     pub fn apply<T>(&self, slice: &mut [T]) {
//         assert_eq!(self.0.len(), slice.len());
//         for i in 0..self.0.len() {
//             slice.swa
//         }
//     }
// }

// required bucket size B for B=C for 2^10, 2^11, ..., 2^19; all batches > 2^19 use B=3; all batches < 2^10 use B=5
const BUCKET_SIZE: [usize; 10] = [5, 5, 5, 4, 4, 4, 4, 4, 4, 3];

fn bucket_cut_and_choose<F: Field + PartialEq + Copy>(party: &mut Party, n: usize) -> MpcResult<MulTripleVector<F>> 
where ChaCha20Rng: FieldRngExt<F>, Sha256: FieldDigestExt<F>
{
    // choose params
    let pow = n.checked_next_power_of_two().expect("n too large");
    println!("n={}, pow={}", n, pow);
    let (N, B) = 
        if pow <= (1 << 10) {
            (1<< 10, BUCKET_SIZE[0])
        }else if pow >= (1 << 20) {
            (pow, BUCKET_SIZE[9])
        }else{
            let mut i = 10;
            let mut tmp = n >> 10;
            while (tmp & 0x1) != 0x1 {
                tmp >>= 1;
                i += 1;
            }
            (pow, BUCKET_SIZE[i-10])
        };
    let C = B;
    let M = N*B+C;
    println!("N={}, B={}, M={}", N, B, M);
    // generate multiplication triples optimistically
    let mut a = party.generate_random(M);
    let mut b = party.generate_random(M);

    let alphas = party.generate_alpha(M);
    let mut ci = izip!(alphas, a.iter(), b.iter()).map(|(alpha_j, aj, bj)| {
        alpha_j + aj.si * bj.si + aj.si * bj.sii + aj.sii * bj.si
    }).collect_vec();
    // receive cii from P+1
    let rcv_cii = party.io().receive_field(Direction::Next, M);
    // send ci to P-1
    party.io().send_field::<F>(Direction::Previous, &ci);
    let mut cii = rcv_cii.rcv()?;
    party.io().wait_for_completion();

    // obtain fresh global randomness
    let mut rng = GlobalRng::setup_global(party)?;
    // shuffle
    let mut perm = {
        let mut perm = (0..M).collect_vec();
        perm.shuffle(rng.as_mut());
        Permutation::oneline(perm)
    };
    perm.apply_slice_in_place(&mut a);
    perm.apply_slice_in_place(&mut b);
    perm.apply_slice_in_place(&mut ci);
    perm.apply_slice_in_place(&mut cii);

    // open and check the first C triples
    let ok = open_and_check(party, &a[..C], &b[..C], &ci[..C], &cii[..C])?;
    if !ok {
        return Err(MpcError::SacrificeError);
    }
    
    sacrifice(party, N, B, &a[C..], &b[C..], &ci[C..], &cii[C..])?;
    let (ai, aii): (Vec<F>, Vec<F>) = a.into_iter().skip(C).take(n).map(|rss| (rss.si, rss.sii)).unzip();
    let (bi, bii): (Vec<F>, Vec<F>) = b.into_iter().skip(C).take(n).map(|rss| (rss.si, rss.sii)).unzip();
    Ok(MulTripleVector {
        ai,
        aii,
        bi,
        bii,
        ci: ci.into_iter().skip(C).take(n).collect(),
        cii: cii.into_iter().skip(C).take(n).collect()
    })
}

fn open_and_check<F: Field + PartialEq + Copy>(party: &mut Party, a: &[RssShare<F>], b: &[RssShare<F>], ci: &[F], cii: &[F]) -> MpcResult<bool> {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), ci.len());
    debug_assert_eq!(a.len(), cii.len());

    let rcv = party.io().receive_field(Direction::Next, 3*a.len());
    let aii_bii_cii = a.iter().map(|rss| &rss.sii)
        .chain(b.iter().map(|rss| &rss.sii))
        .chain(cii);
    party.io().send_field::<F>(Direction::Previous, aii_bii_cii);

    let aiii_biii_ciii = rcv.rcv()?;
    // check that all are correct
    for i in 0..a.len() {
        let ai = a[i].si + a[i].sii + aiii_biii_ciii[i];
        let bi = b[i].si + b[i].sii + aiii_biii_ciii[a.len()+i];
        let ci = ci[i] + cii[i] + aiii_biii_ciii[2*a.len()+i];
        if ai * bi != ci {
            party.io().wait_for_completion();
            return Ok(false)
        }
    }
    party.io().wait_for_completion();
    Ok(true)
}

fn sacrifice<F: Field + Copy>(party: &mut Party, n: usize, bucket_size: usize, a: &[RssShare<F>], b: &[RssShare<F>], ci: &[F], cii: &[F]) -> MpcResult<()>
where Sha256: FieldDigestExt<F>
{
    // the first n elements are to be checked
    // the other bucket_size-1 * n elements are sacrificed
    // for element j to be checked, we sacrifice elements j + n*i for i=1..bucket_size
    debug_assert_eq!(n*bucket_size, a.len());
    debug_assert_eq!(n*bucket_size, b.len());
    debug_assert_eq!(n*bucket_size, ci.len());
    debug_assert_eq!(n*bucket_size, cii.len());

    fn index(n: usize, bucket_size: usize) -> impl Iterator<Item=(usize,usize)> {
        (1..bucket_size).flat_map(move |bucket_i| {
            (0..n).map(move |element_i| (element_i, n*bucket_i + element_i))
        })
    }

    let mut rho_ii = index(n, bucket_size).map(|(element_i, idx)| {
            // x + a
            a[element_i].sii + a[idx].sii
    });
    let mut sigma_ii = index(n, bucket_size).map(|(element_i, idx)| {
        // y + b
        b[element_i].sii + b[idx].sii
    });
    let rcv_rho_iii_sigma_iii = party.io().receive_field(Direction::Next, 2*n*(bucket_size-1));
    party.io().send_field(Direction::Previous, rho_ii.by_ref().chain(sigma_ii.by_ref()));

    let rho_i = index(n, bucket_size).map(|(element_i, idx)| {
        // x + a
        a[element_i].si + a[idx].si
    });
    let sigma_i = index(n, bucket_size).map(|(element_i, idx)| {
        // y + b
        b[element_i].si + b[idx].si
    });
    let mut rho_iii_sigma_iii = rcv_rho_iii_sigma_iii.rcv()?;
    let sigma_iii = rho_iii_sigma_iii.split_off(n*(bucket_size-1));
    let rho_iii = rho_iii_sigma_iii;

    let rho = izip!(rho_i, rho_ii, rho_iii).map(|(si,sii,siii)| si + sii + siii);
    let sigma = izip!(sigma_i, sigma_ii, sigma_iii).map(|(si,sii,siii)| si + sii + siii);

    let mut context = BroadcastContext::new();
    izip!(index(n, bucket_size), rho, sigma).for_each(|((el_idx, sac_idx), rho, sigma)| {
        let rho_times_sigma = rho * sigma;
        let zero_i = ci[el_idx] + ci[sac_idx] + sigma * a[el_idx].si + rho * b[el_idx].si + rho_times_sigma;
        let zero_ii = cii[el_idx] + cii[sac_idx] + sigma * a[el_idx].sii + rho * b[el_idx].sii + rho_times_sigma;
        context.add_to_next_view(&zero_i);
        context.add_to_prev_view(&(-zero_i - zero_ii));
    });
    party.io().wait_for_completion();
    party.compare_view(context).map_err(|mpc_err| {
        match mpc_err {
            MpcError::BroadcastError => MpcError::SacrificeError, // turn broadcast error into sacrifice error
            _ => mpc_err
        }
    })
}

#[cfg(test)]
mod test {
    use itertools::{izip, Itertools};

    use crate::{furukawa::bucket_cut_and_choose, party::test::simple_localhost_setup, share::{field::GF8, test::consistent, Field, RssShare}};

    use super::MulTripleVector;

    fn check_len<F>(triples: &MulTripleVector<F>, len: usize) {
        assert_eq!(triples.ai.len(), len);
        assert_eq!(triples.aii.len(), len);
        assert_eq!(triples.bi.len(), len);
        assert_eq!(triples.bii.len(), len);
        assert_eq!(triples.ci.len(), len);
        assert_eq!(triples.cii.len(), len);
    }

    fn into_rss<'a: 'b, 'b: 'a, F: Field>(si: &'a[F], sii: &'b[F]) -> impl Iterator<Item=RssShare<F>> + 'a + 'b {
        si.iter().zip_eq(sii).map(|(si, sii)| RssShare::from(si.clone(), sii.clone()))
    }

    #[test]
    fn correct_gf8_triples() {
        const N: usize = (1 << 20); // create 2^20 triples
        // generate N triples with soundness 2^-40
        let ((triples1, triples2, triples3), _) = simple_localhost_setup(|p| {
            bucket_cut_and_choose::<GF8>(p, N).unwrap()
        });

        check_len(&triples1, N);
        check_len(&triples2, N);
        check_len(&triples3, N);
        // check consistent
        izip!(into_rss(&triples1.ai, &triples1.aii), into_rss(&triples2.ai, &triples2.aii), into_rss(&triples3.ai, &triples3.aii))
            .for_each(|(a1, a2, a3)| consistent(&a1, &a2, &a3));
        izip!(into_rss(&triples1.bi, &triples1.bii), into_rss(&triples2.bi, &triples2.bii), into_rss(&triples3.bi, &triples3.bii))
            .for_each(|(b1, b2, b3)| consistent(&b1, &b2, &b3));
        izip!(into_rss(&triples1.ci, &triples1.cii), into_rss(&triples2.ci, &triples2.cii), into_rss(&triples3.ci, &triples3.cii))
            .for_each(|(c1, c2, c3)| consistent(&c1, &c2, &c3));


        // check correct
        for i in 0..N {
            let a = triples1.ai[i] + triples2.ai[i] + triples3.ai[i];
            let b = triples1.bi[i] + triples2.bi[i] + triples3.bi[i];
            let c = triples1.ci[i] + triples2.ci[i] + triples3.ci[i];

            assert_eq!(a * b, c);
        }
    }
}