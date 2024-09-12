use itertools::izip;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSliceMut;
use crate::rep3_core::party::{MainParty, Party};
use crate::rep3_core::share::{RssShare, RssShareVec};

use crate::aes::{AesVariant, GF8InvBlackBox};
use crate::util::ArithmeticBlackBox;
use crate::rep3_core::network::task::{Direction, IoLayerOwned};
use crate::rep3_core::party::error::MpcResult;
use crate::share::gf8::GF8;
use crate::share::Field;

use super::aes::VectorAesState;
use super::{ChidaBenchmarkParty, ChidaParty, ImplVariant};

impl<F: Field> ArithmeticBlackBox<F> for ChidaParty {

    fn pre_processing(&mut self, _n_multiplications: usize) -> MpcResult<()> {
        Ok(()) // no pre-processing needed
    }

    fn io(&self) -> &IoLayerOwned {
        self.0.io()
    }

    fn constant(&self, value: F) -> RssShare<F> {
        self.0.constant(value)
    }

    fn generate_random(&mut self, n: usize) -> RssShareVec<F> {
        self.0.generate_random(n)
    }

    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=F> {
        self.0.generate_alpha(n)
    }

    // all parties input the same number of inputs
    fn input_round(
        &mut self,
        my_input: &[F],
    ) -> MpcResult<(RssShareVec<F>, RssShareVec<F>, RssShareVec<F>)> {
        input_round(&mut self.0, my_input)
    }

    fn mul(
        &mut self,
        ci: &mut [F],
        cii: &mut [F],
        ai: &[F],
        aii: &[F],
        bi: &[F],
        bii: &[F],
    ) -> MpcResult<()> {
        mul(&mut self.0, ci, cii, ai, aii, bi, bii)
    }

    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        debug_assert_eq!(si.len(), sii.len());
        let rss: Vec<_> = si
            .iter()
            .zip(sii)
            .map(|(si, sii)| RssShare::from(*si, *sii))
            .collect();
        output_round(&mut self.0, &rss, &rss, &rss)
    }

    fn output_to(&mut self, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>> {
        output_round(&mut self.0, to_p1, to_p2, to_p3)
    }

    fn finalize(&mut self) -> MpcResult<()> {
        // nothing to do
        Ok(())
    }
}

impl GF8InvBlackBox for ChidaBenchmarkParty {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }
    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        match self.variant {
            ImplVariant::Simple => gf8_inv_layer(&mut self.inner, si, sii),
            ImplVariant::Optimized => {
                if self.inner.has_multi_threading() && si.len() >= self.inner.num_worker_threads() {
                    gf8_inv_layer_opt_mt(self.inner.as_party_mut(), si, sii)
                } else {
                    gf8_inv_layer_opt(self.inner.as_party_mut(), si, sii)
                }
            }
        }
    }
    fn do_preprocessing(&mut self, _n_keys: usize, _n_blocks: usize, _variant: AesVariant) -> MpcResult<()> {
        // no preprocessing needed
        Ok(())
    }
    fn main_party_mut(&mut self) -> &mut MainParty {
        &mut self.inner.0
    }
}

impl<F: Field> ArithmeticBlackBox<F> for ChidaBenchmarkParty {
    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        <ChidaParty as ArithmeticBlackBox<F>>::pre_processing(&mut self.inner, n_multiplications)
    }

    fn io(&self) -> &IoLayerOwned {
        <ChidaParty as ArithmeticBlackBox<F>>::io(&self.inner)
    }

    fn constant(&self, value: F) -> RssShare<F> {
        self.inner.constant(value)
    }

    fn generate_random(&mut self, n: usize) -> RssShareVec<F> {
        self.inner.generate_random(n)
    }

    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=F> {
        self.inner.generate_alpha(n)
    }

    // all parties input the same number of inputs
    fn input_round(
        &mut self,
        my_input: &[F],
    ) -> MpcResult<(RssShareVec<F>, RssShareVec<F>, RssShareVec<F>)> {
        self.inner.input_round(my_input)
    }

    fn mul(
        &mut self,
        ci: &mut [F],
        cii: &mut [F],
        ai: &[F],
        aii: &[F],
        bi: &[F],
        bii: &[F],
    ) -> MpcResult<()> {
        self.inner.mul(ci, cii, ai, aii, bi, bii)
    }

    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        self.inner.output_round(si, sii)
    }

    fn output_to(&mut self, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>> {
        self.inner.output_to(to_p1, to_p2, to_p3)
    }

    fn finalize(&mut self) -> MpcResult<()> {
        <ChidaParty as ArithmeticBlackBox<F>>::finalize(&mut self.inner)
    }
}

// the straight-forward gf8 inversion using 4 multiplication and only squaring (see Chida et al. "High-Throughput Secure AES Computation" in WAHC'18 [Figure 6])
pub fn gf8_inv_layer<Protocol: ArithmeticBlackBox<GF8>>(
    party: &mut Protocol,
    si: &mut [GF8],
    sii: &mut [GF8],
) -> MpcResult<()> {
    let n = si.len();
    // this is not yet the multiplication that chida et al use
    let x2 = (square_layer(si), square_layer(sii)); //square(&states);
                                                    // x^3 = x^2 * x
    let mut x3 = (vec![GF8(0); n], vec![GF8(0); n]); //VectorAesState::new(states.n);
    party.mul(&mut x3.0, &mut x3.1, si, sii, &x2.0, &x2.1)?;

    let x6 = (square_layer(&x3.0), square_layer(&x3.1));
    let x12 = (square_layer(&x6.0), square_layer(&x6.1));

    let x12_x12 = (append(&x12.0, &x12.0), append(&x12.1, &x12.1));
    let x3_x2 = (append(&x3.0, &x2.0), append(&x3.1, &x2.1));

    let mut x15_x14 = (vec![GF8(0); 2 * n], vec![GF8(0); 2 * n]); // VectorAesState::new(x12_x12.n);
                                                                  // x^15 = x^12 * x^3 and x^14 = x^12 * x^2 in one round
    party.mul(
        &mut x15_x14.0,
        &mut x15_x14.1,
        &x12_x12.0,
        &x12_x12.1,
        &x3_x2.0,
        &x3_x2.1,
    )?;

    // x^15 square in-place x^240 = (x^15)^16
    for i in 0..n {
        x15_x14.0[i] = x15_x14.0[i].square().square().square().square();
        x15_x14.1[i] = x15_x14.1[i].square().square().square().square();
    }
    // x^254 = x^240 * x^14
    // write directly to output buffers si,sii
    party.mul(
        si,
        sii,
        &x15_x14.0[..n],
        &x15_x14.1[..n],
        &x15_x14.0[n..],
        &x15_x14.1[n..],
    )
}

fn gf8_inv_layer_opt(party: &mut MainParty, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
    gf8_inv_layer_opt_party(party, si, sii)?;
    party.wait_for_completion();
    Ok(())
}

fn gf8_inv_layer_opt_mt(party: &mut MainParty, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
    debug_assert_eq!(si.len(), sii.len());
    let ranges = party.split_range_equally(si.len());
    let chunk_size = ranges[0].1 - ranges[0].0;
    let thread_party = party.create_thread_parties(ranges);
    party.run_in_threadpool(|| {
        thread_party
            .into_par_iter()
            .zip_eq(si.par_chunks_mut(chunk_size))
            .zip_eq(sii.par_chunks_mut(chunk_size))
            .map(|((mut thread_party, si), sii)| {
                gf8_inv_layer_opt_party(&mut thread_party, si, sii)
            })
            .collect::<MpcResult<Vec<()>>>()
    })?;
    party.wait_for_completion();
    Ok(())
}

fn gf8_inv_layer_opt_party<P: Party>(
    party: &mut P,
    si: &mut [GF8],
    sii: &mut [GF8],
) -> MpcResult<()> {
    let n = si.len();
    // MULT(x²,x)
    // receive from P-1
    let rcv_x3i = party.receive_field(Direction::Previous, n);

    let x3ii: Vec<GF8> = party
        .generate_alpha::<GF8>(n)
        .into_iter()
        .enumerate()
        .map(|(i, alpha)| alpha + si[i].cube() + (si[i] + sii[i]).cube())
        .collect();
    // send to P+1
    party.send_field_slice(Direction::Next, &x3ii);

    // MULT(x^12, x^2) and MULT(x^12, x^3)
    // receive from P-1
    let rcv_x14x15i = party.receive_field(Direction::Previous, 2 * n);
    let mut x14x15ii: Vec<GF8> = party.generate_alpha(2 * n).collect();
    let x3i = rcv_x3i.rcv()?;
    for i in 0..n {
        x14x15ii[i] += GF8::x4y2(x3i[i] + x3ii[i], si[i] + sii[i]) + GF8::x4y2(x3i[i], si[i]);
    }
    for i in 0..n {
        let tmp = x3i[i] + x3ii[i];
        x14x15ii[n + i] += GF8::x4y(tmp, tmp) + GF8::x4y(x3i[i], x3i[i]);
    }
    // send to P+1
    party.send_field_slice(Direction::Next, &x14x15ii);

    // MULT(x^240, x^14)
    let x14x15i = rcv_x14x15i.rcv()?;
    let x254ii: Vec<_> = party
        .generate_alpha::<GF8>(n)
        .into_iter()
        .enumerate()
        .map(|(i, alpha)| {
            alpha
                + GF8::x16y(x14x15i[n + i] + x14x15ii[n + i], x14x15i[i] + x14x15ii[i])
                + GF8::x16y(x14x15i[n + i], x14x15i[i])
        })
        .collect();
    sii.copy_from_slice(&x254ii);
    // receive from P-1
    let rcv_si = party.receive_field_slice(Direction::Previous, si);
    // send to P+1
    party.send_field_slice(Direction::Next, sii);

    rcv_si.rcv()?;
    Ok(())
}

#[inline]
fn square_layer(v: &[GF8]) -> Vec<GF8> {
    v.iter().map(|x| x.square()).collect()
}

#[inline]
fn append(a: &[GF8], b: &[GF8]) -> Vec<GF8> {
    let mut res = vec![GF8(0); a.len() + b.len()];
    res[..a.len()].copy_from_slice(a);
    res[a.len()..].copy_from_slice(b);
    res
}

// all parties input the same number of inputs (input.len() AES states)
pub fn input_round<F: Field>(
    party: &mut MainParty,
    input: &[F],
) -> MpcResult<(RssShareVec<F>, RssShareVec<F>, RssShareVec<F>)> {
    let n = input.len();
    // create 3n random elements
    let random = party.generate_random(3 * n);
    let my_random = output_round(party, &random[..n], &random[n..2 * n], &random[2 * n..])?;

    let (mut pi_random, pii_random, mut piii_random) = match party.i {
        0 => (
            random[..n].to_vec(),
            random[n..2 * n].to_vec(),
            random[2 * n..].to_vec(),
        ),
        1 => (
            random[n..2 * n].to_vec(),
            random[2 * n..].to_vec(),
            random[..n].to_vec(),
        ),
        2 => (
            random[2 * n..].to_vec(),
            random[..n].to_vec(),
            random[n..2 * n].to_vec(),
        ),
        _ => unreachable!(),
    };

    izip!(pi_random.iter_mut(), input, my_random)
        .for_each(|(pi_random, inp, rand)| pi_random.sii += *inp - rand);

    // send sii to P+1
    party
        .io()
        .send_field::<F>(Direction::Next, pi_random.iter().map(|rss| &rss.sii), n);
    // receive si from P-1
    let rcv_prev_si = party
        .io()
        .receive_field(Direction::Previous, piii_random.len());

    let my_input = pi_random;
    let next_input = pii_random;

    let prev_si = rcv_prev_si.rcv()?;
    for (i, prev) in prev_si.into_iter().enumerate() {
        piii_random[i].si = prev;
    }
    let prev_input = piii_random;
    let (in1, in2, in3) = match party.i {
        0 => (my_input, next_input, prev_input),
        1 => (prev_input, my_input, next_input),
        2 => (next_input, prev_input, my_input),
        _ => unreachable!(),
    };
    party.io().wait_for_completion();
    Ok((in1, in2, in3))
}

// all parties input the same number of inputs (input.len() AES states)
pub fn input_round_aes_states(
    party: &mut MainParty,
    input: Vec<Vec<GF8>>,
) -> MpcResult<(VectorAesState, VectorAesState, VectorAesState)> {
    let n = input.len();
    // create 3n*16 random elements
    let random = party.generate_random(3 * 16 * n);
    let my_random = output_round(
        party,
        &random[..n * 16],
        &random[n * 16..2 * n * 16],
        &random[2 * n * 16..],
    )?;

    let (mut pi_random, pii_random, mut piii_random) = match party.i {
        0 => (
            random[..n * 16].to_vec(),
            random[n * 16..2 * n * 16].to_vec(),
            random[2 * n * 16..].to_vec(),
        ),
        1 => (
            random[n * 16..2 * n * 16].to_vec(),
            random[2 * n * 16..].to_vec(),
            random[..n * 16].to_vec(),
        ),
        2 => (
            random[2 * n * 16..].to_vec(),
            random[..n * 16].to_vec(),
            random[n * 16..2 * n * 16].to_vec(),
        ),
        _ => unreachable!(),
    };

    for (i, input_block) in input.into_iter().enumerate() {
        debug_assert_eq!(input_block.len(), 16);
        for j in 0..16 {
            pi_random[16 * i + j].sii += input_block[j] - my_random[16 * i + j];
        }
    }

    // send sii to P+1
    party.io().send_field::<GF8>(
        Direction::Next,
        pi_random.iter().map(|rss| &rss.sii),
        16 * n,
    );
    // receive si from P-1
    let rcv_prev_si = party
        .io()
        .receive_field(Direction::Previous, piii_random.len());

    let my_input = pi_random;
    let next_input = pii_random;

    let prev_si = rcv_prev_si.rcv()?;
    for (i, prev) in prev_si.into_iter().enumerate() {
        piii_random[i].si = prev;
    }
    let prev_input = piii_random;
    let (in1, in2, in3) = match party.i {
        0 => (my_input, next_input, prev_input),
        1 => (prev_input, my_input, next_input),
        2 => (next_input, prev_input, my_input),
        _ => unreachable!(),
    };

    // reshape into VectorAesState
    let in1 = VectorAesState::from_bytes(in1);
    let in2 = VectorAesState::from_bytes(in2);
    let in3 = VectorAesState::from_bytes(in3);
    party.io().wait_for_completion();
    Ok((in1, in2, in3))
}

pub fn output_round<F: Field>(
    party: &mut MainParty,
    to_p1: &[RssShare<F>],
    to_p2: &[RssShare<F>],
    to_p3: &[RssShare<F>],
) -> MpcResult<Vec<F>> {
    let (my, siii) = match party.i {
        0 => {
            // send my share to P2
            party.io().send_field::<F>(
                Direction::Next,
                to_p2.iter().map(|rss| &rss.si),
                to_p2.len(),
            );
            // receive s3 from P3
            let s3 = party
                .io()
                .receive_field(Direction::Previous, to_p1.len())
                .rcv()?;
            (to_p1, s3)
        }
        1 => {
            // send my share to P3
            party.io().send_field::<F>(
                Direction::Next,
                to_p3.iter().map(|rss| &rss.si),
                to_p3.len(),
            );
            // receive s1 from P1
            let s1 = party
                .io()
                .receive_field(Direction::Previous, to_p2.len())
                .rcv()?;
            (to_p2, s1)
        }
        2 => {
            // send my share to P1
            party.io().send_field::<F>(
                Direction::Next,
                to_p1.iter().map(|rss| &rss.si),
                to_p1.len(),
            );
            // receive s2 from P2
            let s2 = party
                .io()
                .receive_field(Direction::Previous, to_p3.len())
                .rcv()?;
            (to_p3, s2)
        }
        _ => unreachable!(),
    };
    debug_assert_eq!(my.len(), siii.len());
    let sum = my
        .iter()
        .zip(siii)
        .map(|(rss, siii)| rss.si + rss.sii + siii)
        .collect();
    party.io().wait_for_completion();
    Ok(sum)
}

pub fn mul_no_sync<P: Party, F: Field>(
    party: &mut P,
    ci: &mut [F],
    cii: &mut [F],
    ai: &[F],
    aii: &[F],
    bi: &[F],
    bii: &[F],
) -> MpcResult<()> {
    debug_assert_eq!(ci.len(), ai.len());
    debug_assert_eq!(ci.len(), aii.len());
    debug_assert_eq!(ci.len(), bi.len());
    debug_assert_eq!(ci.len(), bii.len());
    debug_assert_eq!(ci.len(), cii.len());

    let alphas = party.generate_alpha(ci.len());
    for (i, alpha_i) in alphas.into_iter().enumerate() {
        ci[i] = ai[i] * bi[i] + ai[i] * bii[i] + aii[i] * bi[i] + alpha_i;
    }
    let rcv = party.receive_field_slice(Direction::Next, cii);
    party.send_field_slice(Direction::Previous, ci);
    rcv.rcv()?;
    Ok(())
}

pub fn mul<F: Field>(
    party: &mut MainParty,
    ci: &mut [F],
    cii: &mut [F],
    ai: &[F],
    aii: &[F],
    bi: &[F],
    bii: &[F],
) -> MpcResult<()> {
    mul_no_sync(party, ci, cii, ai, aii, bi, bii)?;
    party.wait_for_completion();
    Ok(())
}

#[cfg(any(test, feature = "benchmark-helper"))]
pub mod test {
    use crate::aes::test::{
        test_aes128_keyschedule_gf8, test_aes128_no_keyschedule_gf8, test_aes256_keyschedule_gf8, test_aes256_no_keyschedule_gf8, test_inv_aes128_no_keyschedule_gf8, test_sub_bytes
    };
    use crate::chida::online::{
        input_round, input_round_aes_states, mul, output_round, VectorAesState,
    };
    use crate::chida::{ChidaBenchmarkParty, ChidaParty, ImplVariant};
    use crate::rep3_core::network::ConnectedParty;
    use crate::rep3_core::test::{localhost_connect, PartySetup, TestSetup};
    use crate::rep3_core::party::{MainParty, RngExt};
    use crate::rep3_core::share::RssShare;
    use crate::share::gf8::GF8;
    use crate::share::test::{
        assert_eq, consistent, random_secret_shared_vector, secret_share_vector,
    };
    use rand::thread_rng;

    use super::square_layer;

    pub fn localhost_setup_chida<
        T1: Send,
        F1: Send + FnOnce(&mut ChidaParty) -> T1,
        T2: Send,
        F2: Send + FnOnce(&mut ChidaParty) -> T2,
        T3: Send,
        F3: Send + FnOnce(&mut ChidaParty) -> T3,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        n_threads: Option<usize>,
    ) -> (
        (T1, ChidaParty),
        (T2, ChidaParty),
        (T3, ChidaParty),
    ) {
        fn adapter<T, Fx: FnOnce(&mut ChidaParty) -> T>(
            conn: ConnectedParty,
            f: Fx,
            n_threads: Option<usize>,
        ) -> (T, ChidaParty) {
            let mut party = ChidaParty::setup(conn, n_threads, None).unwrap();
            let t = f(&mut party);
            party.0.teardown().unwrap();
            (t, party)
        }
        localhost_connect(
            move |conn_party| adapter(conn_party, f1, n_threads),
            move |conn_party| adapter(conn_party, f2, n_threads),
            move |conn_party| adapter(conn_party, f3, n_threads),
        )
    }

    pub fn localhost_setup_chida_benchmark<
        T1: Send,
        F1: Send + FnOnce(&mut ChidaBenchmarkParty) -> T1,
        T2: Send,
        F2: Send + FnOnce(&mut ChidaBenchmarkParty) -> T2,
        T3: Send,
        F3: Send + FnOnce(&mut ChidaBenchmarkParty) -> T3,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        variant: ImplVariant,
        n_worker_threads: Option<usize>,
    ) -> (
        (T1, ChidaBenchmarkParty),
        (T2, ChidaBenchmarkParty),
        (T3, ChidaBenchmarkParty),
    ) {
        fn adapter<T, Fx: FnOnce(&mut ChidaBenchmarkParty) -> T>(
            conn: ConnectedParty,
            f: Fx,
            variant: ImplVariant,
            n_worker_threads: Option<usize>,
        ) -> (T, ChidaBenchmarkParty) {
            let mut party = ChidaBenchmarkParty::setup(conn, variant, n_worker_threads, None).unwrap();
            let t = f(&mut party);
            party.inner.0.teardown().unwrap();
            (t, party)
        }
        localhost_connect(
            move |conn_party| adapter(conn_party, f1, variant, n_worker_threads),
            move |conn_party| adapter(conn_party, f2, variant, n_worker_threads),
            move |conn_party| adapter(conn_party, f3, variant, n_worker_threads),
        )
    }

    pub struct ChidaSetup;
    impl TestSetup<ChidaParty> for ChidaSetup {
        fn localhost_setup<
            T1: Send,
            F1: Send + FnOnce(&mut ChidaParty) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut ChidaParty) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut ChidaParty) -> T3,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, ChidaParty),
            (T2, ChidaParty),
            (T3, ChidaParty),
        ) {
            localhost_setup_chida(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<
            T1: Send,
            F1: Send + FnOnce(&mut ChidaParty) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut ChidaParty) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut ChidaParty) -> T3,
        >(
            n_threads: usize,
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, ChidaParty),
            (T2, ChidaParty),
            (T3, ChidaParty),
        ) {
            localhost_setup_chida(f1, f2, f3, Some(n_threads))
        }
    }

    pub struct ChidaSetupSimple;
    impl TestSetup<ChidaBenchmarkParty> for ChidaSetupSimple {
        fn localhost_setup<
            T1: Send,
            F1: Send + FnOnce(&mut ChidaBenchmarkParty) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut ChidaBenchmarkParty) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut ChidaBenchmarkParty) -> T3,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, ChidaBenchmarkParty),
            (T2, ChidaBenchmarkParty),
            (T3, ChidaBenchmarkParty),
        ) {
            localhost_setup_chida_benchmark(f1, f2, f3, ImplVariant::Simple, None)
        }
        fn localhost_setup_multithreads<
            T1: Send,
            F1: Send + FnOnce(&mut ChidaBenchmarkParty) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut ChidaBenchmarkParty) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut ChidaBenchmarkParty) -> T3,
        >(
            _n_threads: usize,
            _f1: F1,
            _f2: F2,
            _f3: F3,
        ) -> (
            (T1, ChidaBenchmarkParty),
            (T2, ChidaBenchmarkParty),
            (T3, ChidaBenchmarkParty),
        ) {
            unimplemented!()
        }
    }

    pub struct ChidaSetupOpt;
    impl TestSetup<ChidaBenchmarkParty> for ChidaSetupOpt {
        fn localhost_setup<
            T1: Send,
            F1: Send + FnOnce(&mut ChidaBenchmarkParty) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut ChidaBenchmarkParty) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut ChidaBenchmarkParty) -> T3,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, ChidaBenchmarkParty),
            (T2, ChidaBenchmarkParty),
            (T3, ChidaBenchmarkParty),
        ) {
            localhost_setup_chida_benchmark(f1, f2, f3, ImplVariant::Optimized, None)
        }
        fn localhost_setup_multithreads<
            T1: Send,
            F1: Send + FnOnce(&mut ChidaBenchmarkParty) -> T1,
            T2: Send,
            F2: Send + FnOnce(&mut ChidaBenchmarkParty) -> T2,
            T3: Send,
            F3: Send + FnOnce(&mut ChidaBenchmarkParty) -> T3,
        >(
            n_threads: usize,
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            (T1, ChidaBenchmarkParty),
            (T2, ChidaBenchmarkParty),
            (T3, ChidaBenchmarkParty),
        ) {
            localhost_setup_chida_benchmark(f1, f2, f3, ImplVariant::Optimized, Some(n_threads))
        }
    }

    #[test]
    fn square_gf8() {
        let x = (0..256).map(|i| GF8(i as u8)).collect::<Vec<_>>();
        let sq = square_layer(&x);
        for (x, x2) in x.into_iter().zip(sq) {
            assert_eq!(x * x, x2);
        }
    }

    #[test]
    fn mul_gf8() {
        const N: usize = 100;
        let (a, a1, a2, a3) = random_secret_shared_vector(N);
        let (b, b1, b2, b3) = random_secret_shared_vector(N);

        let program = |a: Vec<RssShare<GF8>>, b: Vec<RssShare<GF8>>| {
            move |p: &mut MainParty| {
                let mut ci = vec![GF8(0); a.len()];
                let mut cii = vec![GF8(0); a.len()];
                let (ai, aii): (Vec<_>, Vec<_>) = a.into_iter().map(|r| (r.si, r.sii)).unzip();
                let (bi, bii): (Vec<_>, Vec<_>) = b.into_iter().map(|r| (r.si, r.sii)).unzip();
                mul(p, &mut ci, &mut cii, &ai, &aii, &bi, &bii).unwrap();
                assert_eq!(ci.len(), cii.len());
                ci.into_iter()
                    .zip(cii)
                    .map(|(ci, cii)| RssShare::from(ci, cii))
                    .collect::<Vec<_>>()
            }
        };

        let ((c1, _), (c2, _), (c3, _)) =
            PartySetup::localhost_setup(program(a1, b1), program(a2, b2), program(a3, b3));

        assert_eq!(c1.len(), N);
        assert_eq!(c2.len(), N);
        assert_eq!(c3.len(), N);

        for i in 0..c1.len() {
            consistent(&c1[i], &c2[i], &c3[i]);
        }
        for (i, (c1, (c2, c3))) in c1.into_iter().zip(c2.into_iter().zip(c3)).enumerate() {
            assert_eq(c1, c2, c3, a[i] * b[i]);
        }
    }

    #[test]
    fn output() {
        let mut rng = thread_rng();
        let o1 = vec![GF8(1)];
        let o2 = vec![GF8(2), GF8(3)];
        let o3 = vec![GF8(4), GF8(5), GF8(6)];

        let (a1, a2, a3) = secret_share_vector(&mut rng, o1.iter());
        let (b1, b2, b3) = secret_share_vector(&mut rng, o2.iter());
        let (c1, c2, c3) = secret_share_vector(&mut rng, o3.iter());

        let program = |a: Vec<RssShare<GF8>>, b: Vec<RssShare<GF8>>, c: Vec<RssShare<GF8>>| {
            move |p: &mut MainParty| output_round(p, &a, &b, &c).unwrap()
        };

        let ((s1, _), (s2, _), (s3, _)) = PartySetup::localhost_setup(
            program(a1, b1, c1),
            program(a2, b2, c2),
            program(a3, b3, c3),
        );
        assert_eq!(o1, s1);
        assert_eq!(o2, s2);
        assert_eq!(o3, s3);
    }

    #[test]
    fn input_aesstate() {
        const N: usize = 10;
        let mut rng = thread_rng();
        let in1 = GF8::generate(&mut rng, 16 * N);
        let in2 = GF8::generate(&mut rng, 16 * N);
        let in3 = GF8::generate(&mut rng, 16 * N);
        let program = |my_input: Vec<GF8>| {
            move |p: &mut MainParty| {
                let mut v = Vec::with_capacity(N);
                for i in 0..N {
                    let mut block = Vec::with_capacity(16);
                    for j in 0..16 {
                        block.push(my_input[16 * i + j]);
                    }
                    v.push(block);
                }
                let (a, b, c) = input_round_aes_states(p, v).unwrap();
                (a, b, c)
            }
        };
        let (((a1, b1, c1), _), ((a2, b2, c2), _), ((a3, b3, c3), _)) = PartySetup::localhost_setup(
            program(in1.clone()),
            program(in2.clone()),
            program(in3.clone()),
        );

        fn check(
            expected_input: Vec<GF8>,
            x1: VectorAesState,
            x2: VectorAesState,
            x3: VectorAesState,
        ) {
            let x1 = x1.to_bytes();
            let x2 = x2.to_bytes();
            let x3 = x3.to_bytes();
            assert_eq!(expected_input.len(), x1.len());
            assert_eq!(expected_input.len(), x2.len());
            assert_eq!(expected_input.len(), x3.len());

            for (input, (x1, (x2, x3))) in expected_input
                .into_iter()
                .zip(x1.into_iter().zip(x2.into_iter().zip(x3)))
            {
                consistent(&x1, &x2, &x3);
                assert_eq(x1, x2, x3, input);
            }
        }

        check(in1, a1, a2, a3);
        check(in2, b1, b2, b3);
        check(in3, c1, c2, c3);
    }

    #[test]
    fn input_round_gf8() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let in1 = GF8::generate(&mut rng, N);
        let in2 = GF8::generate(&mut rng, N);
        let in3 = GF8::generate(&mut rng, N);
        let program = |my_input: Vec<GF8>| {
            move |p: &mut MainParty| {
                let (a, b, c) = input_round(p, &my_input).unwrap();
                (a, b, c)
            }
        };
        let (((a1, b1, c1), _), ((a2, b2, c2), _), ((a3, b3, c3), _)) = PartySetup::localhost_setup(
            program(in1.clone()),
            program(in2.clone()),
            program(in3.clone()),
        );

        fn check(
            expected_input: Vec<GF8>,
            x1: Vec<RssShare<GF8>>,
            x2: Vec<RssShare<GF8>>,
            x3: Vec<RssShare<GF8>>,
        ) {
            assert_eq!(expected_input.len(), x1.len());
            assert_eq!(expected_input.len(), x2.len());
            assert_eq!(expected_input.len(), x3.len());

            for (input, (x1, (x2, x3))) in expected_input
                .into_iter()
                .zip(x1.into_iter().zip(x2.into_iter().zip(x3)))
            {
                consistent(&x1, &x2, &x3);
                assert_eq(x1, x2, x3, input);
            }
        }

        check(in1, a1, a2, a3);
        check(in2, b1, b2, b3);
        check(in3, c1, c2, c3);
    }

    #[test]
    fn sub_bytes_simple() {
        test_sub_bytes::<ChidaSetupSimple, _>(None);
    }

    #[test]
    fn sub_bytes_optimized() {
        test_sub_bytes::<ChidaSetupOpt, _>(None);
    }

    #[test]
    fn sub_bytes_optimized_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<ChidaSetupOpt, _>(Some(N_THREADS));
    }

    #[test]
    fn aes128_no_keyschedule_gf8_simple() {
        test_aes128_no_keyschedule_gf8::<ChidaSetupSimple, _>(1, None);
    }

    #[test]
    fn aes128_no_keyschedule_gf8_optimized() {
        test_aes128_no_keyschedule_gf8::<ChidaSetupOpt, _>(1, None);
    }

    #[test]
    fn aes128_no_keyschedule_gf8_optimized_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<ChidaSetupOpt, _>(100, Some(N_THREADS));
    }

    #[test]
    fn aes128_keyschedule_gf8_simple() {
        test_aes128_keyschedule_gf8::<ChidaSetupSimple, _>(None);
    }

    #[test]
    fn aes128_keyschedule_gf8_optimized() {
        test_aes128_keyschedule_gf8::<ChidaSetupOpt, _>(None);
    }

    #[test]
    fn inv_aes128_no_keyschedule_gf8_simple() {
        test_inv_aes128_no_keyschedule_gf8::<ChidaSetupSimple, _>(1, None);
    }

    #[test]
    fn inv_aes128_no_keyschedule_gf8_optimized() {
        test_inv_aes128_no_keyschedule_gf8::<ChidaSetupOpt, _>(1, None);
    }

    #[test]
    fn inv_aes128_no_keyschedule_gf8_optimized_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<ChidaSetupOpt, _>(100, Some(N_THREADS));
    }

    #[test]
    fn aes256_keyschedule_gf8_optimized() {
        test_aes256_keyschedule_gf8::<ChidaSetupOpt, _>(None);
    }

    #[test]
    fn aes256_no_keyschedule_gf8_optimized() {
        test_aes256_no_keyschedule_gf8::<ChidaSetupOpt, _>(1, None);
    }

    #[test]
    fn aes256_no_keyschedule_gf8_optimized_mt() {
        const N_THREADS: usize = 3;
        test_aes256_no_keyschedule_gf8::<ChidaSetupOpt, _>(100, Some(N_THREADS));
    }
}
