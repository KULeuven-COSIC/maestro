use std::ops::AddAssign;

use crate::rep3_core::{
    network::task::Direction,
    party::{
        broadcast::{Broadcast, BroadcastContext}, correlated_randomness::GlobalRng, error::{MpcError, MpcResult}, DigestExt, MainParty, Party
    }, share::{RssShare, RssShareVec},
};
use itertools::izip;
use rand::Rng;
use rand::{seq::SliceRandom, CryptoRng, RngCore};
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
    slice::{ParallelSlice, ParallelSliceMut},
};

use crate::{share::Field, util::mul_triple_vec::MulTripleVector};

// required bucket size B for B=C for 2^10, 2^11, ..., 2^19; all batches > 2^19 use B=3; all batches < 2^10 use B=5
const BUCKET_SIZE: [usize; 10] = [5, 5, 5, 4, 4, 4, 4, 4, 4, 3];

/// Returns `n` multiplication triples that are checked for correctness using bucket cut-and-choose.
/// This implementation has a fixed soundness of 40-bit.
///
/// Note that unless `n` is a power of 2 larger or equal to 2^10, this function will generate more triples but only return exactly `n`.
/// Depending on `next_power_of_two(n)`, different bucket sizes are chosen internally.
#[allow(non_snake_case)]
pub fn bucket_cut_and_choose<F: Field + DigestExt + Send + Sync>(
    party: &mut MainParty,
    n: usize,
) -> MpcResult<MulTripleVector<F>> {
    // choose params
    let pow = n.checked_next_power_of_two().expect("n too large");
    let (N, B) = if pow <= (1 << 10) {
        (1 << 10, BUCKET_SIZE[0])
    } else if pow >= (1 << 20) {
        (pow, BUCKET_SIZE[9])
    } else {
        let mut i = 10;
        let mut tmp = n >> 10;
        while (tmp & 0x1) != 0x1 {
            tmp >>= 1;
            i += 1;
        }
        (pow, BUCKET_SIZE[i - 10])
    };
    let C = B;
    let M = N * B + C;

    // generate multiplication triples optimistically
    // let mul_triples_time = Instant::now();
    let (mut a, mut b, mut ci, mut cii) =
        if party.has_multi_threading() && M >= 2 * party.num_worker_threads() {
            optimistic_mul_mt(party, M)?
        } else {
            optimistic_mul(party, M)?
        };
    party.io().wait_for_completion();
    // let mul_triples_time = mul_triples_time.elapsed();

    // obtain fresh global randomness
    let mut rng = GlobalRng::setup_global(party)?;

    // let shuffle_time = Instant::now();
    if party.has_multi_threading() && M >= 2 * party.num_worker_threads() {
        shuffle_mt(party, rng.as_mut(), &mut a, &mut b, &mut ci, &mut cii)
    } else {
        shuffle(rng.as_mut(), &mut a, &mut b, &mut ci, &mut cii);
    }
    // let shuffle_time = shuffle_time.elapsed();

    // let open_check_time = Instant::now();
    // open and check the first C triples
    let ok = open_and_check(party, &a[..C], &b[..C], &ci[..C], &cii[..C])?;
    // let open_check_time = open_check_time.elapsed();
    if !ok {
        println!("First C triples don't check out");
        return Err(MpcError::Sacrifice);
    }

    // let sacrifice_time = Instant::now();
    let (mut ai, mut aii): (Vec<F>, Vec<F>) =
        a.into_iter().skip(C).map(|rss| (rss.si, rss.sii)).unzip();
    let (mut bi, mut bii): (Vec<F>, Vec<F>) =
        b.into_iter().skip(C).map(|rss| (rss.si, rss.sii)).unzip();

    let (ai_check, ai_sac) = ai.split_at_mut(N);
    let (aii_check, aii_sac) = aii.split_at_mut(N);
    let (bi_check, bi_sac) = bi.split_at_mut(N);
    let (bii_check, bii_sac) = bii.split_at_mut(N);
    let (ci_check, ci_sac) = ci[C..].split_at_mut(N);
    let (cii_check, cii_sac) = cii[C..].split_at_mut(N);

    if party.has_multi_threading() && N >= 2 * party.num_worker_threads() {
        sacrifice_mt(
            party,
            N,
            B - 1,
            ai_check,
            aii_check,
            bi_check,
            bii_check,
            ci_check,
            cii_check,
            ai_sac,
            aii_sac,
            bi_sac,
            bii_sac,
            ci_sac,
            cii_sac,
        )?;
    } else {
        sacrifice(
            party,
            N,
            B - 1,
            ai_check,
            aii_check,
            bi_check,
            bii_check,
            ci_check,
            cii_check,
            ai_sac,
            aii_sac,
            bi_sac,
            bii_sac,
            ci_sac,
            cii_sac,
        )?;
    }
    
    let correct_triples = MulTripleVector::from_vecs(
        ai.into_iter().take(n).collect(),
        aii.into_iter().take(n).collect(),
        bi.into_iter().take(n).collect(),
        bii.into_iter().take(n).collect(),
        ci.into_iter().skip(C).take(n).collect(),
        cii.into_iter().skip(C).take(n).collect(),
    );
    // let sacrifice_time = sacrifice_time.elapsed();
    // println!("Bucket cut-and-choose: optimistic multiplication: {}s, shuffle: {}s, open: {}s, sacrifice: {}s", mul_triples_time.as_secs_f64(), shuffle_time.as_secs_f64(), open_check_time.as_secs_f64(), sacrifice_time.as_secs_f64());
    Ok(correct_triples)
}

type OptimisticMulResult<F> = (RssShareVec<F>, RssShareVec<F>, Vec<F>, Vec<F>);

#[allow(non_snake_case)]
pub fn optimistic_mul_mt<F: Field + Send>(
    party: &mut MainParty,
    M: usize,
) -> MpcResult<OptimisticMulResult<F>> {
    let ranges = party.split_range_equally(M);
    let thread_parties = party.create_thread_parties(ranges);
    let res = party.run_in_threadpool(|| {
        thread_parties
            .into_par_iter()
            .map(|mut thread_party| {
                let batch_size = thread_party.task_size();
                optimistic_mul(&mut thread_party, batch_size)
            })
            .collect::<MpcResult<Vec<OptimisticMulResult<F>>>>()
    })?;
    let mut a = Vec::with_capacity(M);
    let mut b = Vec::with_capacity(M);
    let mut ci = Vec::with_capacity(M);
    let mut cii = Vec::with_capacity(M);
    res.into_iter()
        .for_each(|(mut ax, mut bx, mut cix, mut ciix)| {
            a.append(&mut ax);
            b.append(&mut bx);
            ci.append(&mut cix);
            cii.append(&mut ciix);
        });
    party.wait_for_completion();
    Ok((a, b, ci, cii))
}

#[allow(non_snake_case)]
pub fn optimistic_mul<F: Field, P: Party>(party: &mut P, M: usize) -> MpcResult<OptimisticMulResult<F>> {
    let a = party.generate_random(M);
    let b = party.generate_random(M);

    let alphas = party.generate_alpha::<F>(M);
    let ci: Vec<_> = izip!(alphas, a.iter(), b.iter())
        .map(|(alpha_j, aj, bj)| alpha_j + aj.si * bj.si + aj.si * bj.sii + aj.sii * bj.si)
        .collect();
    // receive cii from P+1
    let rcv_cii = party.receive_field(Direction::Next, M);
    // send ci to P-1
    party.send_field_slice(Direction::Previous, &ci);
    let cii = rcv_cii.rcv()?;
    Ok((a, b, ci, cii))
}

fn shuffle<R: RngCore + CryptoRng, F: Field>(
    rng: &mut R,
    a: &mut [RssShare<F>],
    b: &mut [RssShare<F>],
    ci: &mut [F],
    cii: &mut [F],
) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), ci.len());
    debug_assert_eq!(a.len(), cii.len());

    fn shuffle_from_random_tape<T>(tape: &[usize], slice: &mut [T]) {
        for (tape_idx, i) in (1..slice.len()).rev().enumerate() {
            // invariant: elements with index > i have been locked in place.
            slice.swap(i, tape[tape_idx]);
        }
    }

    // generate the random tape first
    let tape: Vec<_> = (1..a.len())
        .rev()
        .map(|i| {
            // random number from 0 to i (inclusive)
            if i < (core::u32::MAX as usize) {
                rng.gen_range(0..=i as u32) as usize
            } else {
                rng.gen_range(0..=i)
            }
        })
        .collect();

    // apply to a, b, ci, and cii
    shuffle_from_random_tape(&tape, a);
    shuffle_from_random_tape(&tape, b);
    shuffle_from_random_tape(&tape, ci);
    shuffle_from_random_tape(&tape, cii);
}

fn shuffle_mt<R: RngCore + CryptoRng + Clone + Send, F: Field + Send>(
    party: &MainParty,
    rng: &mut R,
    a: &mut [RssShare<F>],
    b: &mut [RssShare<F>],
    ci: &mut [F],
    cii: &mut [F],
) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), ci.len());
    debug_assert_eq!(a.len(), cii.len());
    let mut rng_a = rng.clone();
    let mut rng_b = rng.clone();
    let mut rng_ci = rng.clone();
    let rng_cii = rng;
    party.run_in_threadpool_scoped(|scope| {
        scope.spawn(|_| a.shuffle(&mut rng_a));
        scope.spawn(|_| b.shuffle(&mut rng_b));
        scope.spawn(|_| ci.shuffle(&mut rng_ci));
        scope.spawn(|_| cii.shuffle(rng_cii));
    });
}

fn open_and_check<F: Field + PartialEq + Copy>(
    party: &mut MainParty,
    a: &[RssShare<F>],
    b: &[RssShare<F>],
    ci: &[F],
    cii: &[F],
) -> MpcResult<bool> {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), ci.len());
    debug_assert_eq!(a.len(), cii.len());

    let rcv = party.io().receive_field(Direction::Next, 3 * a.len());
    let aii_bii_cii = a
        .iter()
        .map(|rss| &rss.sii)
        .chain(b.iter().map(|rss| &rss.sii))
        .chain(cii);
    party.io().send_field::<F>(
        Direction::Previous,
        aii_bii_cii,
        a.len() + b.len() + cii.len(),
    );

    let aiii_biii_ciii = rcv.rcv()?;
    // check that all are correct
    for i in 0..a.len() {
        let ai = a[i].si + a[i].sii + aiii_biii_ciii[i];
        let bi = b[i].si + b[i].sii + aiii_biii_ciii[a.len() + i];
        let ci = ci[i] + cii[i] + aiii_biii_ciii[2 * a.len() + i];
        if ai * bi != ci {
            party.io().wait_for_completion();
            return Ok(false);
        }
    }
    party.io().wait_for_completion();
    Ok(true)
}

/// Computes the sacrificing one triple for another step with support for checking one triple by sacrificing multiple other triples (e.g. a bucket).
///
/// Parameters
///  - `n` denotes the number of triples to check
///  - `sacrifice_bucket_size` denotes the number of triples to sacrifice for **each** triple that is checked.
///  - `ai_to_check`, `aii_to_check`, `bi_to_check`, `bii_to_check`, `ci_to_check` and `cii_to_check` are slices of length `n` that contain the multiplication triple to check.
///  - `ai_to_sacrifice`, `aii_to_sacrifice`, `bi_to_sacrifice`, `bii_to_sacrifice`, `ci_to_sacrifice` and `cii_to_sacrifice` are slices of length `n * sacrifice_bucket_size` that contain the multiplication triple to sacrifice.
///
/// This function returns `Ok(())` if the `x_to_check` values form a correct multiplication triple, otherwise it returns Err.
#[allow(clippy::too_many_arguments)]
pub fn sacrifice<F: Field + DigestExt>(
    party: &mut MainParty,
    n: usize,
    sacrifice_bucket_size: usize,
    ai_to_check: &[F],
    aii_to_check: &[F],
    bi_to_check: &[F],
    bii_to_check: &[F],
    ci_to_check: &[F],
    cii_to_check: &[F],
    ai_to_sacrifice: &mut [F],
    aii_to_sacrifice: &mut [F],
    bi_to_sacrifice: &mut [F],
    bii_to_sacrifice: &mut [F],
    ci_to_sacrifice: &mut [F],
    cii_to_sacrifice: &mut [F],
) -> MpcResult<()> {
    let context = sacrifice_party(
        party,
        n,
        sacrifice_bucket_size,
        ai_to_check,
        aii_to_check,
        bi_to_check,
        bii_to_check,
        ci_to_check,
        cii_to_check,
        ai_to_sacrifice,
        aii_to_sacrifice,
        bi_to_sacrifice,
        bii_to_sacrifice,
        ci_to_sacrifice,
        cii_to_sacrifice,
    )?;
    party.io().wait_for_completion();
    party.compare_view(context).map_err(|mpc_err| {
        match mpc_err {
            MpcError::Broadcast => {
                println!("bucket triples failed");
                MpcError::Sacrifice // turn broadcast error into sacrifice error
            }
            _ => mpc_err,
        }
    })
}

/// Computes the sacrificing one triple for another step with support for checking one triple by sacrificing multiple other triples (e.g. a bucket) using multi-threading.
/// The function will panic if multi-threading is not available for this party.
///
/// Parameters
///  - `n` denotes the number of triples to check
///  - `sacrifice_bucket_size` denotes the number of triples to sacrifice for **each** triple that is checked.
///  - `ai_to_check`, `aii_to_check`, `bi_to_check`, `bii_to_check`, `ci_to_check` and `cii_to_check` are slices of length `n` that contain the multiplication triple to check.
///  - `ai_to_sacrifice`, `aii_to_sacrifice`, `bi_to_sacrifice`, `bii_to_sacrifice`, `ci_to_sacrifice` and `cii_to_sacrifice` are slices of length `n * sacrifice_bucket_size` that contain the multiplication triple to sacrifice.
///
/// This function returns `Ok(())` if the `x_to_check` values form a correct multiplication triple, otherwise it returns Err.
#[allow(clippy::too_many_arguments)]
#[rustfmt::skip]
pub fn sacrifice_mt<F: Field + DigestExt + Send + Sync>(
    party: &mut MainParty,
    n: usize,
    sacrifice_bucket_size: usize,
    ai_to_check: &[F],
    aii_to_check: &[F],
    bi_to_check: &[F],
    bii_to_check: &[F],
    ci_to_check: &[F],
    cii_to_check: &[F],
    ai_to_sacrifice: &mut [F],
    aii_to_sacrifice: &mut [F],
    bi_to_sacrifice: &mut [F],
    bii_to_sacrifice: &mut [F],
    ci_to_sacrifice: &mut [F],
    cii_to_sacrifice: &mut [F],
) -> MpcResult<()> {
    let ranges = party.split_range_equally(n);
    let chunk_size = ranges[0].1 - ranges[0].0;
    let sac_chunk_size = sacrifice_bucket_size * chunk_size;
    let thread_parties = party.create_thread_parties(ranges);

    let contexts = party.run_in_threadpool(|| {
        thread_parties
	.into_par_iter()
        .zip_eq(ai_to_check.par_chunks(chunk_size))
        .zip_eq(aii_to_check.par_chunks(chunk_size))
        .zip_eq(bi_to_check.par_chunks(chunk_size))
        .zip_eq(bii_to_check.par_chunks(chunk_size))
        .zip_eq(ci_to_check.par_chunks(chunk_size))
        .zip_eq(cii_to_check.par_chunks(chunk_size))
        .zip_eq(ai_to_sacrifice.par_chunks_mut(sac_chunk_size))
        .zip_eq(aii_to_sacrifice.par_chunks_mut(sac_chunk_size))
        .zip_eq(bi_to_sacrifice.par_chunks_mut(sac_chunk_size))
        .zip_eq(bii_to_sacrifice.par_chunks_mut(sac_chunk_size))
        .zip_eq(ci_to_sacrifice.par_chunks_mut(sac_chunk_size))
        .zip_eq(cii_to_sacrifice.par_chunks_mut(sac_chunk_size))
        .map(|((((((((((((mut thread_party, ai_to_check), aii_to_check), bi_to_check), bii_to_check), ci_to_check), cii_to_check), ai_to_sacrifice), aii_to_sacrifice), bi_to_sacrifice), bii_to_sacrifice), ci_to_sacrifice), cii_to_sacrifice)| {
            let batch_size = thread_party.task_size();
            sacrifice_party(&mut thread_party, batch_size, sacrifice_bucket_size, ai_to_check, aii_to_check, bi_to_check, bii_to_check, ci_to_check, cii_to_check, ai_to_sacrifice, aii_to_sacrifice, bi_to_sacrifice, bii_to_sacrifice, ci_to_sacrifice, cii_to_sacrifice)
        })
        .collect::<MpcResult<Vec<BroadcastContext>>>()
    })?;
    let context = BroadcastContext::join(contexts);

    party.io().wait_for_completion();
    party.compare_view(context).map_err(|mpc_err| {
        match mpc_err {
            MpcError::Broadcast => {
                println!("bucket triples failed");
                MpcError::Sacrifice // turn broadcast error into sacrifice error
            }
            _ => mpc_err,
        }
    })
}

/// Computes the sacrificing one triple for another step with support for checking one triple by sacrificing multiple other triples (e.g. a bucket).
///
/// Parameters
///  - `n` denotes the number of triples to check
///  - `sacrifice_bucket_size` denotes the number of triples to sacrifice for **each** triple that is checked.
///  - `ai_to_check`, `aii_to_check`, `bi_to_check`, `bii_to_check`, `ci_to_check` and `cii_to_check` are slices of length `n` that contain the multiplication triple to check.
///  - `ai_to_sacrifice`, `aii_to_sacrifice`, `bi_to_sacrifice`, `bii_to_sacrifice`, `ci_to_sacrifice` and `cii_to_sacrifice` are slices of length `n * sacrifice_bucket_size` that contain the multiplication triple to sacrifice.
///
/// This function returns `Ok(())` if the `x_to_check` values form a correct multiplication triple, otherwise it returns Err.
#[allow(clippy::too_many_arguments)]
fn sacrifice_party<P: Party, F: Field + DigestExt + Copy + AddAssign>(
    party: &mut P,
    n: usize,
    sacrifice_bucket_size: usize,
    ai_to_check: &[F],
    aii_to_check: &[F],
    bi_to_check: &[F],
    bii_to_check: &[F],
    ci_to_check: &[F],
    cii_to_check: &[F],
    ai_to_sacrifice: &mut [F],
    aii_to_sacrifice: &mut [F],
    bi_to_sacrifice: &mut [F],
    bii_to_sacrifice: &mut [F],
    ci_to_sacrifice: &mut [F],
    cii_to_sacrifice: &mut [F],
) -> MpcResult<BroadcastContext> {
    // the first n elements are to be checked
    // the other bucket_size-1 * n elements are sacrificed
    // for element j to be checked, we sacrifice elements j + n*i for i=1..bucket_size
    debug_assert_eq!(n, ai_to_check.len());
    debug_assert_eq!(n, aii_to_check.len());
    debug_assert_eq!(n, bi_to_check.len());
    debug_assert_eq!(n, bii_to_check.len());
    debug_assert_eq!(n, ci_to_check.len());
    debug_assert_eq!(n, cii_to_check.len());
    debug_assert_eq!(n * sacrifice_bucket_size, ai_to_sacrifice.len());
    debug_assert_eq!(n * sacrifice_bucket_size, aii_to_sacrifice.len());
    debug_assert_eq!(n * sacrifice_bucket_size, bi_to_sacrifice.len());
    debug_assert_eq!(n * sacrifice_bucket_size, bii_to_sacrifice.len());
    debug_assert_eq!(n * sacrifice_bucket_size, ci_to_sacrifice.len());
    debug_assert_eq!(n * sacrifice_bucket_size, cii_to_sacrifice.len());

    #[inline]
    fn add_to_bucket<F: Field + Copy + AddAssign>(
        bucket: &mut [F],
        el: &[F],
        sacrifice_bucket_size: usize,
    ) {
        debug_assert_eq!(bucket.len(), el.len() * sacrifice_bucket_size);
        let mut bucket_idx = 0;
        for elm in el {
            for _j in 0..sacrifice_bucket_size {
                bucket[bucket_idx] += *elm;
                bucket_idx += 1;
            }
        }
    }

    let rcv_rho_iii_sigma_iii = party.receive_field(Direction::Next, 2 * n * sacrifice_bucket_size);

    // x + a
    let rho_ii = {
        add_to_bucket(aii_to_sacrifice, aii_to_check, sacrifice_bucket_size);
        aii_to_sacrifice
    };
    // y + b
    let sigma_ii = {
        add_to_bucket(bii_to_sacrifice, bii_to_check, sacrifice_bucket_size);
        bii_to_sacrifice
    };

    // TODO party_send_chunks
    party.send_field::<F>(
        Direction::Previous,
        rho_ii.as_ref().iter().chain(sigma_ii.as_ref().iter()),
        rho_ii.len() + sigma_ii.len(),
    );

    // x + a
    let rho_i = {
        add_to_bucket(ai_to_sacrifice, ai_to_check, sacrifice_bucket_size);
        ai_to_sacrifice
    };
    // y + b
    let sigma_i = {
        add_to_bucket(bi_to_sacrifice, bi_to_check, sacrifice_bucket_size);
        bi_to_sacrifice
    };

    let rho_iii_sigma_iii = rcv_rho_iii_sigma_iii.rcv()?;
    let rho = {
        izip!(
            rho_i.iter_mut(),
            rho_ii.as_ref().iter(),
            rho_iii_sigma_iii.iter().take(n * sacrifice_bucket_size)
        )
        .for_each(|(si, sii, siii)| *si += *sii + *siii);
        rho_i
    };
    let sigma = {
        izip!(
            sigma_i.iter_mut(),
            sigma_ii.as_ref().iter(),
            rho_iii_sigma_iii
                .into_iter()
                .skip(n * sacrifice_bucket_size)
                .take(n * sacrifice_bucket_size)
        )
        .for_each(|(si, sii, siii)| *si += *sii + siii);
        sigma_i
    };

    let mut context = BroadcastContext::new();
    let mut bucket_idx = 0;
    for el_idx in 0..ai_to_check.len() {
        for _j in 0..sacrifice_bucket_size {
            let rho_times_sigma = party.constant(rho[bucket_idx] * sigma[bucket_idx]);
            let zero_i = ci_to_check[el_idx]
                + ci_to_sacrifice[bucket_idx]
                + sigma[bucket_idx] * ai_to_check[el_idx]
                + rho[bucket_idx] * bi_to_check[el_idx]
                + rho_times_sigma.si;
            let zero_ii = cii_to_check[el_idx]
                + cii_to_sacrifice[bucket_idx]
                + sigma[bucket_idx] * aii_to_check[el_idx]
                + rho[bucket_idx] * bii_to_check[el_idx]
                + rho_times_sigma.sii;

            // compare_view sends my prev_view to P+1 and compares it to that party's next_view
            // so we write zero_i to prev_view s.t. P+1 compares it to -zero_ii - zero_iii
            context.add_to_prev_view(&zero_i);
            context.add_to_next_view(&(-zero_i - zero_ii));

            bucket_idx += 1;
        }
    }

    Ok(context)
}

#[cfg(test)]
pub mod test {
    use itertools::{izip, Itertools};

    use crate::{
        furukawa::{offline::bucket_cut_and_choose, MulTripleVector},
        share::{gf8::GF8, test::consistent, Field},
    };
    use crate::rep3_core::{
        test::{simple_localhost_setup, PartySetup, TestSetup},
        party::MainParty,
        share::RssShare,
    };

    fn into_rss<'a: 'b, 'b: 'a, F: Field>(
        si: &'a [F],
        sii: &'b [F],
    ) -> impl Iterator<Item = RssShare<F>> + 'a + 'b {
        si.iter()
            .zip_eq(sii)
            .map(|(si, sii)| RssShare::from(si.clone(), sii.clone()))
    }

    #[test]
    fn correct_gf8_triples() {
        const N: usize = 1 << 10; // create 2^10 triples
                                  // generate N triples with soundness 2^-40
        let ((triples1, triples2, triples3), _) =
            simple_localhost_setup(|p| bucket_cut_and_choose::<GF8>(p, N).unwrap());

        assert_eq!(triples1.len(), N);
        assert_eq!(triples2.len(), N);
        assert_eq!(triples3.len(), N);

        for ((a1, b1, c1), (a2, b2, c2), (a3, b3, c3)) in izip!(triples1.into_rss_iter(), triples2.into_rss_iter(), triples3.into_rss_iter()) {
            // check consistent
            consistent(&a1, &a2, &a3);
            consistent(&b1, &b2, &b3);
            consistent(&c1, &c2, &c3);

            // check correct
            let a = a1.si + a2.si + a3.si;
            let b = b1.si + b2.si + b3.si;
            let c = c1.si + c2.si + c3.si;

            assert_eq!(a * b, c);
        }
    }

    #[test]
    fn correct_gf8_triples_mt() {
        const N_THREADS: usize = 3;
        const N: usize = 1 << 10; // create 2^10 triples
	
        // generate N triples with soundness 2^-40
        fn bcc(p: &mut MainParty) -> MulTripleVector<GF8> {
            bucket_cut_and_choose::<GF8>(p, N).unwrap()
        }

        let ((triples1, _), (triples2, _), (triples3, _)) = PartySetup::localhost_setup_multithreads(N_THREADS, bcc, bcc, bcc);

        assert_eq!(triples1.len(), N);
        assert_eq!(triples2.len(), N);
        assert_eq!(triples3.len(), N);
        
        for ((a1, b1, c1), (a2, b2, c2), (a3, b3, c3)) in izip!(triples1.into_rss_iter(), triples2.into_rss_iter(), triples3.into_rss_iter()) {
            // check consistent
            consistent(&a1, &a2, &a3);
            consistent(&b1, &b2, &b3);
            consistent(&c1, &c2, &c3);

            // check correct
            let a = a1.si + a2.si + a3.si;
            let b = b1.si + b2.si + b3.si;
            let c = c1.si + c2.si + c3.si;

            assert_eq!(a * b, c);
        }
    }
}
