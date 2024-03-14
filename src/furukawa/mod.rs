use std::{ops::AddAssign, time::Instant};

use itertools::{izip, Itertools};
use rand::{CryptoRng, RngCore};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use rand::Rng;

use crate::{aes::{self, aes128_no_keyschedule, ArithmeticBlackBox, ImplVariant}, network::{task::{Direction, IoLayer}, ConnectedParty}, party::{broadcast::{Broadcast, BroadcastContext}, correlated_randomness::GlobalRng, error::{MpcError, MpcResult}, Party}, share::{Field, FieldDigestExt, FieldRngExt, RssShare}};

// simd: how many parallel AES calls
pub fn furukawa_benchmark(connected: ConnectedParty, simd: usize) {
    let mut party = FurukawaParty::setup(connected).unwrap();
    let inputs = aes::random_state(&mut party, simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(&mut party);

    let start = Instant::now();
    // ImplVariant::Optimized does not work with Furukawa since the custom multiplication (gf8_inv_opt) is not checked in the post-sacrifice step
    party.pre_processing(aes::get_required_mult_for_aes128_no_keyschedule(ImplVariant::Simple, simd)).unwrap();
    let prep_duration = start.elapsed();
    let start = Instant::now();
    let output = aes128_no_keyschedule(&mut party, inputs, &ks, ImplVariant::Simple).unwrap();
    let online_duration = start.elapsed();
    party.finalize().unwrap();
    let post_sacrifice_duration = start.elapsed();
    let _ = aes::output(&mut party, output).unwrap();
    party.inner.teardown().unwrap();
    
    println!("Finished benchmark");
    
    println!("Party {}: Furukawa et al. with SIMD={} took {}s (pre-processing), {}s (online), {}s (post-sacrifice), {}s (total)", party.inner.i, simd, prep_duration.as_secs_f64(), online_duration.as_secs_f64(), post_sacrifice_duration.as_secs_f64(), (prep_duration+online_duration+post_sacrifice_duration).as_secs_f64());
    party.inner.print_comm_statistics();
}

struct MulTripleVector<F> {
    // s.t. a*b = c
    ai: Vec<F>,
    aii: Vec<F>,
    bi: Vec<F>,
    bii: Vec<F>,
    ci: Vec<F>,
    cii: Vec<F>
}

impl<F> MulTripleVector<F> {
    pub fn new() -> Self {
        Self { ai: Vec::new(), aii: Vec::new(), bi: Vec::new(), bii: Vec::new(), ci: Vec::new(), cii: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.ai.len()
    }

    pub fn shrink(&mut self, new_length: usize) {
        self.ai.truncate(new_length);
        self.aii.truncate(new_length);
        self.bi.truncate(new_length);
        self.bii.truncate(new_length);
        self.ci.truncate(new_length);
        self.cii.truncate(new_length);
    }

    pub fn clear(&mut self) {
        self.ai.clear();
        self.aii.clear();
        self.bi.clear();
        self.bii.clear();
        self.ci.clear();
        self.cii.clear();
    }
}

pub struct FurukawaParty<F: Field + Copy> {
    inner: Party,
    triples_to_check: MulTripleVector<F>,
    pre_processing: Option<MulTripleVector<F>>,
}

impl<F: Field + Copy> FurukawaParty<F>
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
{

    pub fn setup(connected: ConnectedParty) -> MpcResult<Self> {
        Party::setup(connected).map(|party| Self {
            inner: party,
            triples_to_check: MulTripleVector::new(),
            pre_processing: None,
        })
    }

    pub fn prepare_multiplications(&mut self, n_mults: usize) -> MpcResult<()> where F: AddAssign {
        // run the bucket cut-and-choose
        if let Some(ref pre_processing) = self.pre_processing {
            println!("Discarding {} left-over triples", pre_processing.len());
            self.pre_processing = None;
        }
        self.pre_processing = Some(bucket_cut_and_choose(&mut self.inner, n_mults)?);
        Ok(())
    }
    
    pub fn start_input_phase(&mut self) -> InputPhase<F> {
        InputPhase::new(self)
    }

    pub fn inner(&self) -> &Party {
        &self.inner
    }
    
    #[inline]
    pub fn public_constant(&self, c: F) -> RssShare<F> {
        match self.inner.i {
            0 => RssShare::from(c, F::zero()),
            1 => RssShare::from(F::zero(), F::zero()),
            2 => RssShare::from(F::zero(), c),
            _ => unreachable!()
        }
    }

    pub fn mul(&mut self, ai: &[F], aii: &[F], bi: &[F], bii: &[F]) -> MpcResult<(Vec<F>, Vec<F>)>
    where F: Copy
    {
        debug_assert_eq!(ai.len(), aii.len());
        debug_assert_eq!(ai.len(), bi.len());
        debug_assert_eq!(ai.len(), bii.len());
    
        let ci: Vec<_> = izip!(self.inner.generate_alpha(ai.len()), ai, aii, bi, bii)
            .map(|(alpha_j, ai_j, aii_j, bi_j, bii_j)| {
                alpha_j + *ai_j * *bi_j + *ai_j * *bii_j + *aii_j * *bi_j
            })
            .collect();
        self.inner.io().send_field::<F>(Direction::Previous, ci.iter());
        let rcv_cii = self.inner.io().receive_field(Direction::Next, ci.len());
        // note down the observed multiplication triple
        // first the ones we already have
        self.triples_to_check.ai.extend_from_slice(ai);
        self.triples_to_check.aii.extend_from_slice(aii);
        self.triples_to_check.bi.extend_from_slice(bi);
        self.triples_to_check.bii.extend_from_slice(bii);
        self.triples_to_check.ci.extend(&ci);
        // then wait for the last one
        let cii = rcv_cii.rcv()?;
        self.triples_to_check.cii.extend(&cii);
        self.inner.io().wait_for_completion();
        Ok((ci, cii))
    }

    pub fn verify_multiplications(&mut self) -> MpcResult<()> {
        // check all recorded multiplications
        println!("post-sacrifice: checking {} multiplications", self.triples_to_check.len());
        if self.triples_to_check.len() > 0 {
            let prep = self.pre_processing.as_mut().expect("No pre-processed multiplication triples found. Use prepare_multiplications to generate them before the output phase");
            if prep.len() < self.triples_to_check.len() {
                panic!("Not enough pre-processed multiplication triples left: Required {} but found only {}", self.triples_to_check.len(), prep.len());
            }
            
            let leftover = prep.len() - self.triples_to_check.len();
            let err = sacrifice(&mut self.inner, self.triples_to_check.len(), 1, &self.triples_to_check.ai, &self.triples_to_check.aii, &self.triples_to_check.bi, &self.triples_to_check.bii, &self.triples_to_check.ci, &self.triples_to_check.cii, &mut prep.ai[leftover..], &mut prep.aii[leftover..], &mut prep.bi[leftover..], &mut prep.bii[leftover..], &mut prep.ci[leftover..], &mut prep.cii[leftover..]);
            // purge the sacrificed triples
            if leftover > 0 {
                prep.shrink(leftover);
            }else{
                self.pre_processing = None;
            }
            self.triples_to_check.clear();
            err // return the sacrifice error
        }else{
            Ok(())
        }
        
    }

    pub fn output_phase<T, OF: FnOnce(&mut OutputPhase<F>) -> MpcResult<T>>(&mut self, block: OF) -> MpcResult<T> where F: AddAssign {
        self.verify_multiplications()?;

        // now the output phase can begin
        let mut phase = OutputPhase::new(self);
        let res = block(&mut phase)?;
        phase.end_output_phase()?;
        Ok(res)
    }

}

pub struct InputPhase<'a, F: Field + Copy> {
    party: &'a mut FurukawaParty<F>,
    context: BroadcastContext
}

impl<'a, F: Field + Copy> InputPhase<'a, F>
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
{
    fn new(party: &'a mut FurukawaParty<F>) -> Self {
        Self {
            party,
            context: BroadcastContext::new(),
        }
    }

    pub fn my_input(&mut self, input: &[F]) -> MpcResult<Vec<RssShare<F>>> {
        let a = self.party.inner.generate_random(input.len());
        let b = self.party.inner.open_rss_to(&mut self.context, &a, self.party.inner.i)?;
        let mut b = b.unwrap(); // this is safe since we open to party.i
        for i in 0..b.len() {
            b[i] = b[i].clone() + input[i].clone();
        }
        self.party.inner.broadcast_round(&mut self.context, &mut [], &mut [], b.as_slice())?;
        Ok(a.into_iter().zip(b.into_iter()).map(|(ai,bi)| self.party.public_constant(bi) - ai).collect())
    }

    pub fn other_input(&mut self, input_party: usize, n_inputs: usize) -> MpcResult<Vec<RssShare<F>>> {
        assert_ne!(self.party.inner.i, input_party);
        let a = self.party.inner.generate_random(n_inputs);
        let b = self.party.inner.open_rss_to(&mut self.context, &a, input_party)?;
        debug_assert!(b.is_none());
        let mut b = vec![F::zero(); n_inputs];
        match (self.party.inner.i, input_party) {
            (0,2) | (1,0) | (2,1) => self.party.inner.broadcast_round(&mut self.context, &mut [], &mut b, &[])?,
            (0,1) | (1,2) | (2,0) => self.party.inner.broadcast_round(&mut self.context, &mut b, &mut [], &[])?,
            _ => unreachable!(),
        }
        Ok(a.into_iter().zip(b.into_iter()).map(|(ai,bi)| self.party.public_constant(bi) - ai).collect())
    }

    pub fn end_input_phase(self) -> MpcResult<()> {
        self.party.inner.compare_view(self.context)
    }
}

pub struct OutputPhase<'a, F: Field + Copy> {
    party: &'a mut FurukawaParty<F>,
    context: BroadcastContext,
}

impl<'a, F: Field + Copy> OutputPhase<'a, F>
where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F> {

    fn new(party: &'a mut FurukawaParty<F>) -> Self {
        Self {
            party,
            context: BroadcastContext::new(),
        }
    }

    pub fn output_to(&mut self, to_party: usize, si: &[F], sii: &[F]) -> MpcResult<Option<Vec<F>>> {
        debug_assert_eq!(si.len(), sii.len());
        let rss: Vec<_> = si.iter().zip(sii).map(|(si,sii)| RssShare::from(si.clone(), sii.clone())).collect();
        self.party.inner.open_rss_to(&mut self.context, &rss, to_party)
    }

    pub fn output(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        self.party.inner.open_rss(&mut self.context, si, sii)
    }

    fn end_output_phase(self) -> MpcResult<()> {
        self.party.inner.compare_view(self.context)
    }
}

impl<F: Field> ArithmeticBlackBox<F> for FurukawaParty<F>
where ChaCha20Rng: FieldRngExt<F>, Sha256: FieldDigestExt<F>,
{
    type Rng = ChaCha20Rng;
    type Digest = Sha256;

    fn io(&self) -> &IoLayer {
        self.inner.io()
    }

    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()> {
        self.prepare_multiplications(n_multiplications)
    }

    fn constant(&self, value: F) -> RssShare<F> {
        if self.inner.i == 0 {
            RssShare::from(value, F::zero())
        }else if self.inner.i == 2 {
            RssShare::from(F::zero(), value)
        }else{
            RssShare::from(F::zero(), F::zero())
        }
    }

    fn generate_random(&mut self, n: usize) -> Vec<RssShare<F>> {
        self.inner.generate_random(n)
    }

    fn input_round(&mut self, my_input: &[F]) -> MpcResult<(Vec<RssShare<F>>, Vec<RssShare<F>>, Vec<RssShare<F>>)> {
        let party_index = self.inner.i;
        let mut input_phase = self.start_input_phase();

        let in1 = if party_index == 0 {
            input_phase.my_input(my_input)
        }else{
            input_phase.other_input(0, my_input.len())
        }?;

        let in2 = if party_index == 1 {
            input_phase.my_input(my_input)
        }else{
            input_phase.other_input(1, my_input.len())
        }?;

        let in3 = if party_index == 2 {
            input_phase.my_input(my_input)
        }else{
            input_phase.other_input(2, my_input.len())
        }?;
        input_phase.end_input_phase()?;
        Ok((in1, in2, in3))
    }

    fn mul(&mut self, ci: &mut [F], cii: &mut [F], ai: &[F], aii: &[F], bi: &[F], bii: &[F]) -> MpcResult<()> {
        let (vci, vcii) = self.mul(ai, aii, bi, bii)?;
        ci.copy_from_slice(&vci);
        cii.copy_from_slice(&vcii);
        Ok(())
    }

    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>> {
        self.output_phase(|of| {
            of.output(si, sii)
        })
    }

    fn finalize(&mut self) -> MpcResult<()> {
        self.verify_multiplications()
    }
}

// required bucket size B for B=C for 2^10, 2^11, ..., 2^19; all batches > 2^19 use B=3; all batches < 2^10 use B=5
const BUCKET_SIZE: [usize; 10] = [5, 5, 5, 4, 4, 4, 4, 4, 4, 3];

#[allow(non_snake_case)]
fn bucket_cut_and_choose<F: Field + PartialEq + Copy + AddAssign>(party: &mut Party, n: usize) -> MpcResult<MulTripleVector<F>> 
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
    let mul_triples_time = Instant::now();
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
    let mul_triples_time = mul_triples_time.elapsed();

    // obtain fresh global randomness
    let mut rng = GlobalRng::setup_global(party)?;

    let shuffle_time = Instant::now();
    shuffle(rng.as_mut(), &mut a, &mut b, &mut ci, &mut cii);
    let shuffle_time = shuffle_time.elapsed();

    let open_check_time = Instant::now();
    // open and check the first C triples
    let ok = open_and_check(party, &a[..C], &b[..C], &ci[..C], &cii[..C])?;
    let open_check_time = open_check_time.elapsed();
    if !ok {
        println!("First C triples don't check out");
        return Err(MpcError::SacrificeError);
    }

    let sacrifice_time = Instant::now();
    let (mut ai, mut aii): (Vec<F>, Vec<F>) = a.into_iter().skip(C).map(|rss| (rss.si, rss.sii)).unzip();
    let (mut bi, mut bii): (Vec<F>, Vec<F>) = b.into_iter().skip(C).map(|rss| (rss.si, rss.sii)).unzip();

    let (ai_check, ai_sac) = ai.split_at_mut(N);
    let (aii_check, aii_sac) = aii.split_at_mut(N);
    let (bi_check, bi_sac) = bi.split_at_mut(N);
    let (bii_check, bii_sac) = bii.split_at_mut(N);
    let (ci_check, ci_sac) = ci[C..].split_at_mut(N);
    let (cii_check, cii_sac) = cii[C..].split_at_mut(N);

    sacrifice(party, N, B-1, ai_check, aii_check, bi_check, bii_check, ci_check, cii_check, ai_sac, aii_sac, bi_sac, bii_sac, ci_sac, cii_sac)?;
    
    let correct_triples = MulTripleVector {
        ai: ai.into_iter().take(n).collect(),
        aii: aii.into_iter().take(n).collect(),
        bi: bi.into_iter().take(n).collect(),
        bii: bii.into_iter().take(n).collect(),
        ci: ci.into_iter().skip(C).take(n).collect(),
        cii: cii.into_iter().skip(C).take(n).collect()
    };
    let sacrifice_time = sacrifice_time.elapsed();
    println!("Bucket cut-and-choose: optimistic multiplication: {}s, shuffle: {}s, open: {}s, sacrifice: {}s", mul_triples_time.as_secs_f64(), shuffle_time.as_secs_f64(), open_check_time.as_secs_f64(), sacrifice_time.as_secs_f64());
    Ok(correct_triples)
}

fn shuffle<R: RngCore + CryptoRng, F: Field>(rng: &mut R, a: &mut [RssShare<F>], b: &mut [RssShare<F>], ci: &mut [F], cii: &mut [F]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), ci.len());
    debug_assert_eq!(a.len(), cii.len());

    fn shuffle_from_random_tape<T>(tape: &[usize], slice: &mut [T]) {
        let mut tape_idx = 0;
        for i in (1..slice.len()).rev() {
            // invariant: elements with index > i have been locked in place.
            slice.swap(i, tape[tape_idx]);
            tape_idx += 1;
        }
    }

    // generate the random tape first
    let tape: Vec<_> = (1..a.len()).rev().map(|i| {
        // random number from 0 to i (inclusive)
        if i < (core::u32::MAX as usize) {
            rng.gen_range(0..=i as u32) as usize
        } else {
            rng.gen_range(0..=i)
        }
    }).collect();

    // apply to a, b, ci, and cii
    shuffle_from_random_tape(&tape, a);
    shuffle_from_random_tape(&tape, b);
    shuffle_from_random_tape(&tape, ci);
    shuffle_from_random_tape(&tape, cii);
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

fn sacrifice<F: Field + Copy + AddAssign>(party: &mut Party, n: usize, sacrifice_bucket_size: usize, 
    ai_to_check: &[F], aii_to_check: &[F], bi_to_check: &[F], bii_to_check: &[F], ci_to_check: &[F], cii_to_check: &[F],
    ai_to_sacrifice: &mut [F], aii_to_sacrifice: &mut [F], bi_to_sacrifice: &mut [F], bii_to_sacrifice: &mut [F], ci_to_sacrifice: &mut [F], cii_to_sacrifice: &mut [F],
) -> MpcResult<()>
where Sha256: FieldDigestExt<F>
{
    // the first n elements are to be checked
    // the other bucket_size-1 * n elements are sacrificed
    // for element j to be checked, we sacrifice elements j + n*i for i=1..bucket_size
    debug_assert_eq!(n, ai_to_check.len());
    debug_assert_eq!(n, aii_to_check.len());
    debug_assert_eq!(n, bi_to_check.len());
    debug_assert_eq!(n, bii_to_check.len());
    debug_assert_eq!(n, ci_to_check.len());
    debug_assert_eq!(n, cii_to_check.len());
    debug_assert_eq!(n*sacrifice_bucket_size, ai_to_sacrifice.len());
    debug_assert_eq!(n*sacrifice_bucket_size, aii_to_sacrifice.len());
    debug_assert_eq!(n*sacrifice_bucket_size, bi_to_sacrifice.len());
    debug_assert_eq!(n*sacrifice_bucket_size, bii_to_sacrifice.len());
    debug_assert_eq!(n*sacrifice_bucket_size, ci_to_sacrifice.len());
    debug_assert_eq!(n*sacrifice_bucket_size, cii_to_sacrifice.len());

    #[inline]
    fn add_to_bucket<F: Field + Copy + AddAssign>(bucket: &mut[F], el: &[F], sacrifice_bucket_size: usize) {
        debug_assert_eq!(bucket.len(), el.len() * sacrifice_bucket_size);
        let mut bucket_idx = 0;
        for el_idx in 0..el.len() {
            for _j in 0..sacrifice_bucket_size {
                bucket[bucket_idx] += el[el_idx];
                bucket_idx += 1;
            }
        }
    }

    let rcv_rho_iii_sigma_iii = party.io().receive_field(Direction::Next, 2*n*sacrifice_bucket_size);

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
    
    
    party.io().send_field::<F>(Direction::Previous, rho_ii.as_ref().iter().chain(sigma_ii.as_ref().iter()));
    
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
        izip!(rho_i.iter_mut(), rho_ii.as_ref().iter(), rho_iii_sigma_iii.iter().take(n*sacrifice_bucket_size)).for_each(|(si, sii, siii)| *si += *sii + *siii);
        rho_i
    };
    let sigma = {
        izip!(sigma_i.iter_mut(), sigma_ii.as_ref().iter(), rho_iii_sigma_iii.into_iter().skip(n*sacrifice_bucket_size).take(n*sacrifice_bucket_size)).for_each(|(si, sii, siii)| *si += *sii + siii);
        sigma_i
    };

    let mut context = BroadcastContext::new();
    let mut bucket_idx = 0;
    for el_idx in 0..ai_to_check.len() {
        for _j in 0..sacrifice_bucket_size {
            let rho_times_sigma = rho[bucket_idx] * sigma[bucket_idx];
            let mut zero_i = ci_to_check[el_idx] + ci_to_sacrifice[bucket_idx] + sigma[bucket_idx] * ai_to_check[el_idx] + rho[bucket_idx] * bi_to_check[el_idx];
            if party.i == 0 {
                zero_i += rho_times_sigma;
            }
            let mut zero_ii = cii_to_check[el_idx] + cii_to_sacrifice[bucket_idx] + sigma[bucket_idx] * aii_to_check[el_idx] + rho[bucket_idx] * bii_to_check[el_idx];
            if party.i == 2 {
                zero_ii += rho_times_sigma;
            }
            // compare_view sends my prev_view to P+1 and compares it to that party's next_view
            // so we write zero_i to prev_view s.t. P+1 compares it to -zero_ii - zero_iii
            context.add_to_prev_view(&zero_i);
            context.add_to_next_view(&(-zero_i - zero_ii));
            
            bucket_idx += 1;
        }
    }

    party.io().wait_for_completion();
    party.compare_view(context).map_err(|mpc_err| {
        match mpc_err {
            MpcError::BroadcastError => {
                println!("bucket triples failed");
                MpcError::SacrificeError // turn broadcast error into sacrifice error
            },
            _ => mpc_err
        }
    })
}

#[cfg(test)]
pub mod test {
    use std::thread::JoinHandle;

    use itertools::{izip, Itertools};
    use rand::thread_rng;
    use rand_chacha::ChaCha20Rng;
    use sha2::Sha256;
    use crate::aes::ArithmeticBlackBox;
    use crate::party::test::TestSetup;
    use crate::share::test::{assert_eq, consistent};

    use crate::{furukawa::bucket_cut_and_choose, network::ConnectedParty, party::test::{localhost_connect, simple_localhost_setup}, share::{field::GF8, Field, FieldDigestExt, FieldRngExt, RssShare}};

    use super::{FurukawaParty, MulTripleVector};

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
        const N: usize = 1 << 10; // create 2^10 triples
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

    pub fn localhost_setup_furukawa<F: Field + Send + 'static + Copy, T1: Send + 'static, F1: Send + FnOnce(&mut FurukawaParty<F>) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut FurukawaParty<F>) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut FurukawaParty<F>) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,FurukawaParty<F>)>, JoinHandle<(T2,FurukawaParty<F>)>, JoinHandle<(T3,FurukawaParty<F>)>)
    where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
    {
        fn adapter<F: Field + Copy, T, Fx: FnOnce(&mut FurukawaParty<F>)->T>(conn: ConnectedParty, f: Fx) -> (T,FurukawaParty<F>)
        where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
        {
            let mut party = FurukawaParty::setup(conn).unwrap();
            let t = f(&mut party);
            party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(|conn_party| adapter(conn_party, f1), |conn_party| adapter(conn_party, f2), |conn_party| adapter(conn_party, f3))
    }

    pub struct FurukawaSetup;
    impl<F: Field + Send + 'static> TestSetup<FurukawaParty<F>> for FurukawaSetup
    where Sha256: FieldDigestExt<F>, ChaCha20Rng: FieldRngExt<F>
    {
        fn localhost_setup<T1: Send + 'static, F1: Send + FnOnce(&mut FurukawaParty<F>) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut FurukawaParty<F>) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut FurukawaParty<F>) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,FurukawaParty<F>)>, JoinHandle<(T2,FurukawaParty<F>)>, JoinHandle<(T3,FurukawaParty<F>)>) {
            localhost_setup_furukawa(f1, f2, f3)
        }
    }

    #[test]
    fn input_gf8() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let x1 = rng.generate(N);
        let x2 = rng.generate(N);
        let x3 = rng.generate(N);

        let program = |x: Vec<GF8>| {
            move |p: &mut FurukawaParty<GF8>| {
                // let party_index = p.inner().i;
                p.input_round(&x).unwrap()
            }
        };

        let (h1, h2, h3) = localhost_setup_furukawa(program(x1.clone()), program(x2.clone()), program(x3.clone()));
        let ((x11, x21, x31), _) = h1.join().unwrap();
        let ((x12, x22, x32), _) = h2.join().unwrap();
        let ((x13, x23, x33), _) = h3.join().unwrap();

        fn check(x: Vec<GF8>, share1: Vec<RssShare<GF8>>, share2: Vec<RssShare<GF8>>, share3: Vec<RssShare<GF8>>) {
            assert_eq!(x.len(), share1.len());
            assert_eq!(x.len(), share2.len());
            assert_eq!(x.len(), share3.len());
            for (xi, (s1, (s2, s3))) in x.into_iter().zip(share1.into_iter().zip(share2.into_iter().zip(share3))) {
                consistent(&s1, &s2, &s3);
                assert_eq(s1, s2, s3, xi);
            }
        }

        check(x1, x11, x12, x13);
        check(x2, x21, x22, x23);
        check(x3, x31, x32, x33);
    }
}
