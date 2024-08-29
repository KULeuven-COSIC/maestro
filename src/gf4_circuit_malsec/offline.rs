use itertools::izip;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::{furukawa, share::{gf4::BsGF4, Field}, util::mul_triple_vec::{BsGF4Encoder, MulTripleRecorder, MulTripleVector}, wollut16_malsec};
use crate::rep3_core::{network::task::Direction, party::{broadcast::{Broadcast, BroadcastContext}, error::{MpcError, MpcResult}, MainParty, Party}};


pub fn prepare_beaver_triples_recursive_check(party: &mut MainParty, dst: &mut MulTripleVector<BsGF4>, context: &mut BroadcastContext, n: usize) -> MpcResult<()> {
    println!("Preparing {} beaver triples", n);
    if party.has_multi_threading() {
        optimistic_mul_mt(party, dst, n)?;
    }else{
        optimistic_mul(party, dst, n)?;
        party.wait_for_completion();
    };
    
    // now check them
    let res = if party.has_multi_threading() {
        wollut16_malsec::mult_verification::verify_multiplication_triples_mt(party, context, &mut [&mut BsGF4Encoder(dst)], true)
    }else{
        wollut16_malsec::mult_verification::verify_multiplication_triples(party, context, &mut [&mut BsGF4Encoder(dst)], true)
    };
    match res {
        Ok(true) => {
            // check broadcast context
            let to_check = std::mem::replace(context, BroadcastContext::new());
            party.compare_view(to_check)
        },
        Ok(false) => Err(MpcError::MultCheck),
        Err(err) => Err(err),
    }
}

pub fn prepare_beaver_triples_bucket(party: &mut MainParty, dst: &mut MulTripleVector<BsGF4>, n: usize) -> MpcResult<()> {
    let triples = furukawa::offline::bucket_cut_and_choose(party, n)?;
    *dst = triples;
    Ok(())
}


pub fn optimistic_mul_mt<F: Field + Send>(
    party: &mut MainParty,
    dst: &mut MulTripleVector<F>,
    n: usize,
) -> MpcResult<()> {
    let ranges = party.split_range_equally(n);
    let thread_parties = party.create_thread_parties_with_additional_data(ranges, |range_start, range_end| Some(dst.create_thread_mul_triple_recorder(range_start, range_end)));
    let res = party.run_in_threadpool(|| {
        thread_parties
            .into_par_iter()
            .map(|mut thread_party| {
                let batch_size = thread_party.task_size();
                let mut rec = thread_party.additional_data.take().unwrap();
                optimistic_mul(&mut thread_party, &mut rec, batch_size).map(|()| rec)
            })
            .collect::<MpcResult<Vec<_>>>()
    })?;
    dst.join_thread_mul_triple_recorders(res);
    
    party.wait_for_completion();
    Ok(())
}

pub fn optimistic_mul<F: Field, P: Party, Rec: MulTripleRecorder<F>>(party: &mut P, rec: &mut Rec, n: usize) -> MpcResult<()> {
    let a = party.generate_random::<F>(n);
    let b = party.generate_random(n);

    let alphas = party.generate_alpha::<F>(n);
    let ci: Vec<_> = izip!(alphas, a.iter(), b.iter())
        .map(|(alpha_j, aj, bj)| alpha_j + aj.si * bj.si + aj.si * bj.sii + aj.sii * bj.si)
        .collect();
    // receive cii from P+1
    let rcv_cii = party.receive_field(Direction::Next, n);
    // send ci to P-1
    party.send_field_slice(Direction::Previous, &ci);

    let (ai, aii): (Vec<_>, Vec<_>) = a.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
    let (bi, bii): (Vec<_>, Vec<_>) = b.into_iter().map(|rss| (rss.si, rss.sii)).unzip();


    let cii = rcv_cii.rcv()?;
    rec.record_mul_triple(&ai, &aii, &bi, &bii, &ci, &cii);
    Ok(())
}

#[cfg(test)]
mod test {
    use std::fmt::Debug;

    use itertools::izip;

    use super::{optimistic_mul, optimistic_mul_mt, prepare_beaver_triples_recursive_check};
    use crate::{share::{gf4::BsGF4, test::{assert_eq, consistent}, Field}, util::mul_triple_vec::{MulTripleRecorder, MulTripleVector}};
    use crate::rep3_core::party::{broadcast::{Broadcast, BroadcastContext}, MainParty};
    use crate::rep3_core::test::localhost_setup;


    #[test]
    fn optimistic_mul_gf4() {
        const N: usize = 1537;
        let program = || {
            |p: &mut MainParty| {
                let mut rec = MulTripleVector::<BsGF4>::new();
                optimistic_mul(p, &mut rec, N).unwrap();
                rec
            }
        };

        let ((triples1, _), (triples2, _), (triples3, _)) = localhost_setup(program(), program(), program(), None);

        assert_eq!(triples1.len(), N);
        assert_eq!(triples2.len(), N);
        assert_eq!(triples3.len(), N);

        correct_triples(triples1, triples2, triples3);
    }

    #[test]
    fn optimistic_mul_mt_gf4() {
        const N: usize = 1537;
        const N_THREADS: usize = 3;
        let program = || {
            |p: &mut MainParty| {
                let mut rec = MulTripleVector::<BsGF4>::new();
                optimistic_mul_mt(p, &mut rec, N).unwrap();
                rec
            }
        };

        let ((triples1, _), (triples2, _), (triples3, _)) = localhost_setup(program(), program(), program(), Some(N_THREADS));

        assert_eq!(triples1.len(), N);
        assert_eq!(triples2.len(), N);
        assert_eq!(triples3.len(), N);

        correct_triples(triples1, triples2, triples3);
    }

    #[test]
    fn prepare_beaver_triples_gf4() {
        const N: usize = 401;
        let program = || {
            |p: &mut MainParty| {
                let mut rec = MulTripleVector::<BsGF4>::new();
                rec.reserve_for_more_triples(N);
                let mut context = BroadcastContext::new();
                prepare_beaver_triples_recursive_check(p, &mut rec, &mut context, N).unwrap();
                p.compare_view(context).unwrap(); // make sure compare-view works
                rec
            }
        };

        let ((triples1, _), (triples2, _), (triples3, _)) = localhost_setup(program(), program(), program(), None);

        assert_eq!(triples1.len(), N);
        assert_eq!(triples2.len(), N);
        assert_eq!(triples3.len(), N);

        correct_triples(triples1, triples2, triples3);
    }

    #[test]
    fn prepare_beaver_triples_mt_gf4() {
        const N: usize = 40001;
        const N_THREADS: usize = 3;
        let program = || {
            |p: &mut MainParty| {
                let mut rec = MulTripleVector::<BsGF4>::new();
                rec.reserve_for_more_triples(N);
                let mut context = BroadcastContext::new();
                prepare_beaver_triples_recursive_check(p, &mut rec, &mut context, N).unwrap();
                p.compare_view(context).unwrap(); // make sure compare-view works
                rec
            }
        };

        let ((triples1, _), (triples2, _), (triples3, _)) = localhost_setup(program(), program(), program(), Some(N_THREADS));

        assert_eq!(triples1.len(), N);
        assert_eq!(triples2.len(), N);
        assert_eq!(triples3.len(), N);

        correct_triples(triples1, triples2, triples3);
    }

    fn correct_triples<F: Field + Debug>(mut triples1: MulTripleVector<F>, mut triples2: MulTripleVector<F>, mut triples3: MulTripleVector<F>) {
        for (t1, t2, t3) in izip!(triples1.drain_into_rss_iter(), triples2.drain_into_rss_iter(), triples3.drain_into_rss_iter()) {
            consistent(&t1.0, &t2.0, &t3.0);
            consistent(&t1.1, &t2.1, &t3.1);
            consistent(&t1.2, &t2.2, &t3.2);

            let a = t1.0.si + t2.0.si + t3.0.si;
            let b = t1.1.si + t2.1.si + t3.1.si;
            assert_eq(t1.2, t2.2, t3.2, a*b);
        }
    }
}