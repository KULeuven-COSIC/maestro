use itertools::izip;
use rand_chacha::ChaCha20Rng;

use crate::aes::{ComputePhase, InputPhase, MPCProtocol, OutputPhase, PreProcessing};
use crate::network::task::Direction;
use crate::party::error::MpcResult;
use crate::party::Party;
use crate::share::field::GF8;
use crate::share::{Field, FieldRngExt, RssShare};

use super::aes::VectorAesState;
use super::ChidaParty;

impl<F: Field> InputPhase<F> for ChidaParty
where ChaCha20Rng: FieldRngExt<F>
{
    fn input_round(&mut self, my_input: &[F]) -> MpcResult<(Vec<RssShare<F>>, Vec<RssShare<F>>, Vec<RssShare<F>>)> {
        input_round(&mut self.0, my_input)
    }
}

impl MPCProtocol for ChidaParty {
    fn generate_random<F: Field>(&mut self, n: usize) -> Vec<RssShare<F>>
    where ChaCha20Rng: FieldRngExt<F>
    {
        self.0.generate_random(n)
    }
    fn constant<F: Field>(&self, value: F) -> RssShare<F> {
        self.0.constant(value)
    }
    fn check_input_phase(&mut self) -> MpcResult<()> {
        self.inner_mut().io().wait_for_completion();
        Ok(()) // nothing to do
    }
    fn finalize(&mut self) -> MpcResult<()> {
        self.inner_mut().io().wait_for_completion();
        Ok(()) // nothing to do
    }
}

impl<F: Field> ComputePhase<F> for ChidaParty
where ChaCha20Rng: FieldRngExt<F>
{
    fn mul(&mut self, ci: &mut [F], cii: &mut [F], ai: &[F], aii: &[F], bi: &[F], bii: &[F]) -> MpcResult<()> {
        mul(&mut self.0, ci, cii, ai, aii, bi, bii)
    }
}

impl<F: Field> OutputPhase<F> for ChidaParty {
    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        debug_assert_eq!(si.len(), sii.len());
        let rss: Vec<_> = si.iter().zip(sii).map(|(si,sii)| RssShare::from(*si, *sii)).collect();
        output_round(&mut self.0, &rss, &rss, &rss)
    }

    fn output_to(&mut self, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>> {
        output_round(&mut self.0, to_p1, to_p2, to_p3)
    }
}

impl<F: Field> PreProcessing<F> for ChidaParty {
    fn pre_processing(&mut self, _n_multiplications: usize) -> MpcResult<()> {
        self.inner_mut().io().wait_for_completion();
        Ok(()) // nothing to do
    }
}


// all parties input the same number of inputs (input.len() AES states)
pub fn input_round<F: Field>(party: &mut Party, input: &[F]) -> MpcResult<(Vec<RssShare<F>>, Vec<RssShare<F>>, Vec<RssShare<F>>)> where ChaCha20Rng: FieldRngExt<F> {
    let n = input.len();
    // create 3n random elements
    let random = party.generate_random(3*n);
    let my_random = output_round(party, &random[..n], &random[n..2*n], &random[2*n..])?;

    let (mut pi_random, pii_random, mut piii_random) = match party.i {
        0 => (random[..n].to_vec(), random[n..2*n].to_vec(), random[2*n..].to_vec()),
        1 => (random[n..2*n].to_vec(), random[2*n..].to_vec(), random[..n].to_vec()),
        2 => (random[2*n..].to_vec(), random[..n].to_vec(), random[n..2*n].to_vec()),
        _ => unreachable!(),
    };

    izip!(pi_random.iter_mut(), input, my_random).for_each(|(pi_random, inp, rand)| pi_random.sii += *inp - rand);

    // send sii to P+1
    party.io().send_field::<F>(Direction::Next, pi_random.iter().map(|rss| &rss.sii));
    // receive si from P-1
    let rcv_prev_si = party.io().receive_field(Direction::Previous, piii_random.len());

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
pub fn input_round_aes_states(party: &mut Party, input: Vec<Vec<GF8>>) -> MpcResult<(VectorAesState, VectorAesState, VectorAesState)> {
    let n = input.len();
    // create 3n*16 random elements
    let random = party.generate_random(3*16*n);
    let my_random = output_round(party, &random[..n*16], &random[n*16..2*n*16], &random[2*n*16..])?;

    let (mut pi_random, pii_random, mut piii_random) = match party.i {
        0 => (random[..n*16].to_vec(), random[n*16..2*n*16].to_vec(), random[2*n*16..].to_vec()),
        1 => (random[n*16..2*n*16].to_vec(), random[2*n*16..].to_vec(), random[..n*16].to_vec()),
        2 => (random[2*n*16..].to_vec(), random[..n*16].to_vec(), random[n*16..2*n*16].to_vec()),
        _ => unreachable!(),
    };

    for (i,input_block) in input.into_iter().enumerate() {
        debug_assert_eq!(input_block.len(), 16);
        for j in 0..16 {
            pi_random[16*i+j].sii += input_block[j] - my_random[16*i+j];
        }
    }

    // send sii to P+1
    party.io().send_field::<GF8>(Direction::Next, pi_random.iter().map(|rss| &rss.sii));
    // receive si from P-1
    let rcv_prev_si = party.io().receive_field(Direction::Previous, piii_random.len());

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

pub fn output_round<F: Field>(party: &mut Party, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>> {
    let (my, siii) = match party.i {
        0 => {
            // send my share to P2
            party.io().send_field::<F>(Direction::Next, to_p2.iter().map(|rss| &rss.si));
            // receive s3 from P3
            let s3 = party.io().receive_field(Direction::Previous, to_p1.len()).rcv()?;
            (to_p1, s3)
        },
        1 => {
            // send my share to P3
            party.io().send_field::<F>(Direction::Next, to_p3.iter().map(|rss| &rss.si));
            // receive s1 from P1
            let s1 = party.io().receive_field(Direction::Previous, to_p2.len()).rcv()?;
            (to_p2, s1)
        },
        2 => {
            // send my share to P1
            party.io().send_field::<F>(Direction::Next, to_p1.iter().map(|rss| &rss.si));
            // receive s2 from P2
            let s2 = party.io().receive_field(Direction::Previous, to_p3.len()).rcv()?;
            (to_p3, s2)
        },
        _ => unreachable!(),
    };
    debug_assert_eq!(my.len(), siii.len());
    let sum = my.into_iter().zip(siii).map(|(rss, siii)| rss.si + rss.sii + siii).collect();
    party.io().wait_for_completion();
    Ok(sum)
}

fn mul<F: Field>(party: &mut Party, ci: &mut [F], cii: &mut [F], ai: &[F], aii: &[F], bi: &[F], bii: &[F]) -> MpcResult<()> 
where ChaCha20Rng: FieldRngExt<F>
{
    debug_assert_eq!(ci.len(), ai.len());
    debug_assert_eq!(ci.len(), aii.len());
    debug_assert_eq!(ci.len(), bi.len());
    debug_assert_eq!(ci.len(), bii.len());
    debug_assert_eq!(ci.len(), cii.len());

    let alphas = party.generate_alpha(ci.len());
    for (i, alpha_i) in alphas.into_iter().enumerate() {
        ci[i] = ai[i] * bi[i] + ai[i] * bii[i] + aii[i] * bi[i] + alpha_i;
    }
    // println!("Writing {} elements to comm_prev", ci.len());
    party.io().send_field::<F>(Direction::Previous, ci.iter());
    // println!("Expecting {} elements from comm_next", cii.len());
    party.io().receive_field_slice(Direction::Next, cii).rcv()?;
    party.io().wait_for_completion();
    Ok(())
}



#[cfg(test)]
pub mod test {
    use std::thread::JoinHandle;

    use rand::thread_rng;
    use crate::chida::online::{input_round, input_round_aes_states, mul, output_round, VectorAesState};
    use crate::chida::ChidaParty;
    use crate::network::ConnectedParty;
    use crate::party::Party;
    use crate::party::test::{localhost_connect, localhost_setup, TestSetup};
    use crate::share::field::GF8;
    use crate::share::{FieldRngExt, RssShare};
    use crate::share::test::{assert_eq, consistent, random_secret_shared_vector, secret_share_vector};

    pub fn localhost_setup_chida<T1: Send + 'static, F1: Send + FnOnce(&mut ChidaParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut ChidaParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut ChidaParty) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,ChidaParty)>, JoinHandle<(T2,ChidaParty)>, JoinHandle<(T3,ChidaParty)>) {
        fn adapter<T, Fx: FnOnce(&mut ChidaParty)->T>(conn: ConnectedParty, f: Fx) -> (T,ChidaParty) {
            let mut party = ChidaParty::setup(conn).unwrap();
            let t = f(&mut party);
            party.0.teardown().unwrap();
            (t, party)
        }
        localhost_connect(|conn_party| adapter(conn_party, f1), |conn_party| adapter(conn_party, f2), |conn_party| adapter(conn_party, f3))
    }

    pub struct ChidaSetup;
    impl TestSetup<ChidaParty> for ChidaSetup {
        fn localhost_setup<T1: Send + 'static, F1: Send + FnOnce(&mut ChidaParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut ChidaParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut ChidaParty) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,ChidaParty)>, JoinHandle<(T2,ChidaParty)>, JoinHandle<(T3,ChidaParty)>) {
            localhost_setup_chida(f1, f2, f3)
        }
    }

    #[test]
    fn mul_gf8() {
        const N: usize = 100;
        let (a, a1, a2, a3) = random_secret_shared_vector(N);
        let (b, b1, b2, b3) = random_secret_shared_vector(N);

        let program = |a: Vec<RssShare<GF8>>, b: Vec<RssShare<GF8>>| {
            move |p: &mut Party| {
                let mut ci = vec![GF8(0); a.len()];
                let mut cii = vec![GF8(0); a.len()];
                let (ai, aii): (Vec<_>, Vec<_>) = a.into_iter().map(|r|(r.si, r.sii)).unzip();
                let (bi, bii): (Vec<_>, Vec<_>) = b.into_iter().map(|r|(r.si, r.sii)).unzip();
                mul(p, &mut ci, &mut cii, &ai, &aii, &bi, &bii).unwrap();
                assert_eq!(ci.len(), cii.len());
                ci.into_iter().zip(cii).map(|(ci, cii)| RssShare::from(ci, cii)).collect::<Vec<_>>()
            }
        };

        let (h1, h2, h3) = localhost_setup(program(a1, b1), program(a2, b2), program(a3, b3));
        let (c1, _) = h1.join().unwrap();
        let (c2, _) = h2.join().unwrap();
        let (c3, _) = h3.join().unwrap();

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
            move |p: &mut Party| {
                output_round(p, &a, &b, &c).unwrap()
            }
        };

        let (h1, h2, h3) = localhost_setup(program(a1, b1, c1), program(a2, b2, c2), program(a3, b3, c3));
        let (s1, _) = h1.join().unwrap();
        let (s2, _) = h2.join().unwrap();
        let (s3, _) = h3.join().unwrap();
        assert_eq!(o1, s1);
        assert_eq!(o2, s2);
        assert_eq!(o3, s3);
    }

    #[test]
    fn input_aesstate() {
        const N: usize = 10;
        let mut rng = thread_rng();
        let in1 = rng.generate(16*N);
        let in2 = rng.generate(16*N);
        let in3 = rng.generate(16*N);
        let program = |my_input: Vec<GF8>| {
            move |p: &mut Party| {
                let mut v = Vec::with_capacity(N);
                for i in 0..N {
                    let mut block = Vec::with_capacity(16);
                    for j in 0..16 {
                        block.push(my_input[16*i+j]);
                    }
                    v.push(block);
                }
                let (a,b,c) = input_round_aes_states(p, v).unwrap();
                (a,b,c)
            }
        };
        let (h1, h2, h3) = localhost_setup(program(in1.clone()), program(in2.clone()), program(in3.clone()));
        let ((a1, b1, c1), _) = h1.join().unwrap();
        let ((a2, b2, c2), _) = h2.join().unwrap();
        let ((a3, b3, c3), _) = h3.join().unwrap();

        fn check(expected_input: Vec<GF8>, x1: VectorAesState, x2: VectorAesState, x3: VectorAesState) {
            let x1 = x1.to_bytes();
            let x2 = x2.to_bytes();
            let x3 = x3.to_bytes();
            assert_eq!(expected_input.len(), x1.len());
            assert_eq!(expected_input.len(), x2.len());
            assert_eq!(expected_input.len(), x3.len());
            
            for (input, (x1, (x2, x3))) in expected_input.into_iter().zip(x1.into_iter().zip(x2.into_iter().zip(x3))) {
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
        let in1 = rng.generate(N);
        let in2 = rng.generate(N);
        let in3 = rng.generate(N);
        let program = |my_input: Vec<GF8>| {
            move |p: &mut Party| {
                let (a,b,c) = input_round(p, &my_input).unwrap();
                (a,b,c)
            }
        };
        let (h1, h2, h3) = localhost_setup(program(in1.clone()), program(in2.clone()), program(in3.clone()));
        let ((a1, b1, c1), _) = h1.join().unwrap();
        let ((a2, b2, c2), _) = h2.join().unwrap();
        let ((a3, b3, c3), _) = h3.join().unwrap();

        fn check(expected_input: Vec<GF8>, x1: Vec<RssShare<GF8>>, x2: Vec<RssShare<GF8>>, x3: Vec<RssShare<GF8>>) {
            assert_eq!(expected_input.len(), x1.len());
            assert_eq!(expected_input.len(), x2.len());
            assert_eq!(expected_input.len(), x3.len());
            
            for (input, (x1, (x2, x3))) in expected_input.into_iter().zip(x1.into_iter().zip(x2.into_iter().zip(x3))) {
                consistent(&x1, &x2, &x3);
                assert_eq(x1, x2, x3, input);
            }
        }

        check(in1, a1, a2, a3);
        check(in2, b1, b2, b3);
        check(in3, c1, c2, c3);
    }
}
