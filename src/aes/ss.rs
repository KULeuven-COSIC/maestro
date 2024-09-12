use std::mem;

use itertools::Itertools;
use crate::rep3_core::{network::task::Direction, party::{error::MpcResult, MainParty, Party}, share::RssShare};

use crate::share::gf8::GF8;

use super::{AesKeyState, VectorAesState};


pub trait GF8InvBlackBoxSS {
    /// returns a (3,3) sharing of the public constant `value`
    fn constant(&self, value: GF8) -> GF8;
    /// computes inversion of the (3,3) sharing of s in-place
    fn gf8_inv(&mut self, s: &mut [GF8]) -> MpcResult<()>;

    /// run any required pre-processing phase to prepare for computation of the key schedule with n_keys and n_blocks many AES-128 block calls
    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()>;

    /// Do any finalize or check protocols
    fn finalize(&mut self) -> MpcResult<()>;

    /// Reveals data to all parties
    fn output(&mut self, data: &[GF8]) -> MpcResult<Vec<GF8>>;

    /// Returns a mutable reference to the underlying [MainParty]
    fn main_party_mut(&mut self) -> &mut MainParty;
}

/// Maliciously secure implementation of [GF8InvBlackBoxSS].
pub trait GF8InvBlackBoxSSMal {
    /// returns a (3,3) sharing of the public constant `value`
    fn constant(&self, value: GF8) -> GF8;

    /// returns a (2,3) sharing of the public constant `value`
    fn constant_rss(&self, value: GF8) -> RssShare<GF8>;

    /// run any required pre-processing phase to prepare for computation of the key schedule with n_keys and n_blocks many AES-128 block calls
    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()>;

    /// computes inversion of the (2,3) sharing of s returning a (3,3) sharing in out
    fn gf8_inv_rss_to_ss(&mut self, out: &mut[GF8], si: &[GF8], sii: &[GF8]) -> MpcResult<()>;

    /// computes inversion of the (3,3) sharing of s in-place and returns a (2,3) sharing of s
    fn gf8_inv_and_rss_output(&mut self, s: &mut[GF8], out_i: &mut[GF8], out_ii: &mut[GF8]) -> MpcResult<()>;

    /// Registers a S-box input/output pair y = Sbox(x) for verification
    fn register_sbox_pair(&mut self, xi: &[GF8], xii: &[GF8], yi: &[GF8], yii: &[GF8]);

    /// Do any finalize or check protocols
    fn finalize(&mut self) -> MpcResult<()>;

    /// Reveals data to all parties
    fn output(&mut self, data_i: &[GF8], data_ii: &[GF8]) -> MpcResult<Vec<GF8>>;

    /// Returns a mutable reference to the underlying [MainParty]
    fn main_party_mut(&mut self) -> &mut MainParty;
}

// contains n AES States in parallel (ie si has length n * 16) in (3,3) sharing
#[derive(Clone)]
pub struct VectorAesStateSS {
    s: Vec<GF8>,
    n: usize,
}

pub fn aes128_no_keyschedule<Protocol: GF8InvBlackBoxSS>(
    party: &mut Protocol,
    inputs: VectorAesStateSS,
    round_key: &[AesKeyState],
) -> MpcResult<VectorAesStateSS> {
    debug_assert_eq!(round_key.len(), 11);
    let mut state = inputs;

    add_round_key(&mut state, &round_key[0]);

    #[allow(clippy::needless_range_loop)]
    for r in 1..=9 {
        sbox_layer(party, &mut state.s)?;
        
        state.shift_rows();
        
        state.mix_columns();
        
        add_round_key(&mut state, &round_key[r]);
    }
    
    sbox_layer(party, &mut state.s)?;
    state.shift_rows();
    add_round_key(&mut state, &round_key[10]);

    Ok(state)
}

pub fn aes128_no_keyschedule_mal<Protocol: GF8InvBlackBoxSSMal>(
    party: &mut Protocol,
    inputs: VectorAesState,
    round_key: &[AesKeyState],
) -> MpcResult<VectorAesState> {
    debug_assert_eq!(round_key.len(), 11);
    let mut state_rss = inputs;
    // AddRoundKey on (2,3) shares
    super::add_round_key(&mut state_rss, &round_key[0]);

    // First SubBytes uses (2,3) -> (3,3) LUT
    let mut state_ss = VectorAesStateSS::new(state_rss.n);
    party.gf8_inv_rss_to_ss(&mut state_ss.s, &state_rss.si, &state_rss.sii)?;
    
    
    // apply affine transform
    let c = party.constant(GF8(0x63));
    let c_rss = party.constant_rss(GF8(0x63));
    // state_ss.s.iter_mut().for_each(|dst| *dst = dst.aes_sbox_affine_transform() + c);

    let mut x_prev = state_rss;
    let mut y = VectorAesState::new(x_prev.n);
    let mut x_r = VectorAesState::new(x_prev.n);

    for r in 1..=9 {
        // apply affine transform
        state_ss.s.iter_mut().for_each(|dst| *dst = dst.aes_sbox_affine_transform() + c);

        state_ss.shift_rows();
        state_ss.mix_columns();
        add_round_key(&mut state_ss, &round_key[r]);
        
        party.gf8_inv_and_rss_output(&mut state_ss.s, &mut x_r.si, &mut x_r.sii)?;

        // invert y
        add_round_key_out(&mut y, &x_r, &round_key[r]);
        y.inv_mix_columns();
        y.inv_shift_rows();
        // undo affine transform
        y.si.iter_mut().for_each(|si| *si = (*si + c_rss.si).inv_aes_sbox_affine_transform());
        y.sii.iter_mut().for_each(|sii| *sii = (*sii + c_rss.sii).inv_aes_sbox_affine_transform());

        // register S-box triples to check
        party.register_sbox_pair(&x_prev.si, &x_prev.sii, &y.si, &y.sii);
        mem::swap(&mut x_prev, &mut x_r);
    }
    
    // Reshare
    let l = state_ss.s.len();
    state_ss.s.iter_mut().zip_eq(party.main_party_mut().generate_alpha(l)).for_each(|(s, alpha)| *s += alpha);
    let rcv = party.main_party_mut().receive_field_slice(Direction::Next, &mut x_r.sii);
    party.main_party_mut().send_field_slice(Direction::Previous, &state_ss.s);
    rcv.rcv()?;
    x_r.si = state_ss.s;

    party.register_sbox_pair(&x_prev.si, &x_prev.sii, &x_r.si, &x_r.sii);

    // afine transform
    state_rss = x_r;
    state_rss.si.iter_mut().for_each(|si| *si = si.aes_sbox_affine_transform() + c_rss.si);
    state_rss.sii.iter_mut().for_each(|sii| *sii = sii.aes_sbox_affine_transform() + c_rss.sii);

    state_rss.shift_rows();
    super::add_round_key(&mut state_rss, &round_key[10]);

    Ok(state_rss)
}

fn add_round_key_out(out: &mut VectorAesState, inp: &VectorAesState, round_key: &AesKeyState) {
    debug_assert_eq!(out.n, inp.n);
    for j in 0..inp.n {
        for i in 0..16 {
            out.si[16 * j + i] = inp.si[16 * j + i] + round_key.si[i];
            out.sii[16 * j + i] = inp.sii[16 * j + i] + round_key.sii[i];
        }
    }
}

pub fn aes128_inv_no_keyschedule<Protocol: GF8InvBlackBoxSS>(
    party: &mut Protocol,
    inputs: VectorAesStateSS,
    key_schedule: &[AesKeyState],
) -> MpcResult<VectorAesStateSS> {
    debug_assert_eq!(key_schedule.len(), 11);
    let mut state = inputs;

    add_round_key(&mut state, &key_schedule[10]);
    for r in (1..=9).rev() {
        state.inv_shift_rows();
        inv_sbox_layer(party, &mut state.s)?;
        add_round_key(&mut state, &key_schedule[r]);
        state.inv_mix_columns();
    }
    state.inv_shift_rows();
    inv_sbox_layer(party, &mut state.s)?;
    add_round_key(&mut state, &key_schedule[0]);
    Ok(state)
}

pub fn random_state<Protocol: Party>(
    party: &mut Protocol,
    size: usize,
) -> VectorAesStateSS {
    let rand = party.generate_random(size * 16).into_iter()
        .map(|rss| rss.si).collect();
    VectorAesStateSS::from_bytes(rand)
}

pub fn output<Protocol: GF8InvBlackBoxSS>(
    party: &mut Protocol,
    data: VectorAesStateSS
) -> MpcResult<Vec<GF8>> {
    party.output(&data.to_bytes())
}

impl VectorAesStateSS {
    pub fn new(n: usize) -> Self {
        Self {
            s: vec![GF8(0u8); n * 16],
            n,
        }
    }

    // fills AES states column-wise (as in FIPS 97)
    // bytes.len() must be a multiple of 16
    pub fn from_bytes(bytes: Vec<GF8>) -> Self {
        let n = bytes.len() / 16;
        debug_assert_eq!(16 * n, bytes.len());
        let mut state = Self::new(n);
        for k in 0..n {
            for i in 0..4 {
                for j in 0..4 {
                    state.s[16 * k + 4 * i + j] = bytes[16 * k + 4 * j + i];
                }
            }
        }
        state
    }

    // outputs the AES states column-wise (as in FIPS 97)
    pub fn to_bytes(&self) -> Vec<GF8> {
        let mut vec = Vec::with_capacity(self.n * 16);
        for k in 0..self.n {
            for i in 0..4 {
                for j in 0..4 {
                    vec.push(self.s[16 * k + 4 * j + i]);
                }
            }
        }
        vec
    }

    fn with_capacity(n: usize) -> Self {
        Self {
            s: Vec::with_capacity(16 * n),
            n,
        }
    }

    // pub fn append(&mut self, mut other: Self) {
    //     self.si.append(&mut other.si);
    //     self.sii.append(&mut other.sii);
    //     self.n += other.n;
    // }

    #[inline]
    fn permute4(&mut self, start: usize, perm: [usize; 4]) {
        let tmp = [
            self.s[start],
            self.s[start + 1],
            self.s[start + 2],
            self.s[start + 3],
        ];
        for i in 0..4 {
            self.s[start + i] = tmp[perm[i]];
        }
    }

    pub fn shift_rows(&mut self) {
        for i in 0..self.n {
            // rotate row 2 by 1 to the left
            self.permute4(16 * i + 4, [1, 2, 3, 0]);
            // rotate row 3 by 2 to the left
            self.permute4(16 * i + 8, [2, 3, 0, 1]);
            // rotate row 4 by 3 to the left
            self.permute4(16 * i + 12, [3, 0, 1, 2]);
        }
    }

    pub fn inv_shift_rows(&mut self) {
        for i in 0..self.n {
            // rotate row 2 by 1 to the right
            self.permute4(16 * i + 4, [3, 0, 1, 2]);
            // rotate row 3 by 2 to the right
            self.permute4(16 * i + 8, [2, 3, 0, 1]);
            // rotate row 4 by 3 to the right
            self.permute4(16 * i + 12, [1, 2, 3, 0]);
        }
    }

    #[inline]
    fn mix_single_column(&mut self, start: usize) {
        let c0 = self.s[start];
        let c1 = self.s[start + 4];
        let c2 = self.s[start + 8];
        let c3 = self.s[start + 12];

        let m0 = c0 * GF8(0x2) + c1 * GF8(0x3) + c2 + c3;
        let m1 = c0 + c1 * GF8(0x2) + c2 * GF8(0x3) + c3;
        let m2 = c0 + c1 + c2 * GF8(0x2) + c3 * GF8(0x3);
        let m3 = c0 * GF8(0x3) + c1 + c2 + c3 * GF8(0x2);
        self.s[start] = m0;
        self.s[start + 4] = m1;
        self.s[start + 8] = m2;
        self.s[start + 12] = m3;
    }

    pub fn mix_columns(&mut self) {
        for i in 0..self.n {
            self.mix_single_column(16 * i);
            self.mix_single_column(16 * i + 1);
            self.mix_single_column(16 * i + 2);
            self.mix_single_column(16 * i + 3);
        }
    }

    #[inline]
    fn inv_mix_single_column(&mut self, start: usize) {
        let c0 = self.s[start];
        let c1 = self.s[start + 4];
        let c2 = self.s[start + 8];
        let c3 = self.s[start + 12];

        let m0 = c0 * GF8(0xe) + c1 * GF8(0xb) + c2 * GF8(0xd) + c3 * GF8(0x9);
        let m1 = c0 * GF8(0x9) + c1 * GF8(0xe) + c2 * GF8(0xb) + c3 * GF8(0xd);
        let m2 = c0 * GF8(0xd) + c1 * GF8(0x9) + c2 * GF8(0xe) + c3 * GF8(0xb);
        let m3 = c0 * GF8(0xb) + c1 * GF8(0xd) + c2 * GF8(0x9) + c3 * GF8(0xe);
        self.s[start] = m0;
        self.s[start + 4] = m1;
        self.s[start + 8] = m2;
        self.s[start + 12] = m3;
    }

    pub fn inv_mix_columns(&mut self) {
        for i in 0..self.n {
            self.inv_mix_single_column(16 * i);
            self.inv_mix_single_column(16 * i + 1);
            self.inv_mix_single_column(16 * i + 2);
            self.inv_mix_single_column(16 * i + 3);
        }
    }
}

fn add_round_key(states: &mut VectorAesStateSS, round_key: &AesKeyState) {
    for j in 0..states.n {
        for i in 0..16 {
            states.s[16 * j + i] += round_key.si[i];
        }
    }
}

fn sbox_layer<Protocol: GF8InvBlackBoxSS>(
    party: &mut Protocol,
    s: &mut [GF8],
) -> MpcResult<()> {
    // first inverse, then affine transform
    party.gf8_inv(s)?;

    // apply affine transform
    let c = party.constant(GF8(0x63));
    s.iter_mut().for_each(|dst| *dst = dst.aes_sbox_affine_transform() + c);
    Ok(())
}

fn inv_sbox_layer<Protocol: GF8InvBlackBoxSS>(
    party: &mut Protocol,
    s: &mut [GF8],
) -> MpcResult<()> {
    // first inverse affine transform, then gf8 inverse
    // apply inverse affine transform
    let c = party.constant(GF8(0x63));
    s.iter_mut().for_each(|dst| *dst = (*dst + c).inv_aes_sbox_affine_transform());

    // gf8 inverse
    party.gf8_inv(s)
}

#[cfg(test)]
pub mod test {
    use itertools::{izip, repeat_n, Itertools};
    use rand::{thread_rng, CryptoRng, Rng};
    use crate::rep3_core::test::TestSetup;

    use crate::aes::ss::{aes128_inv_no_keyschedule, aes128_no_keyschedule};
    use crate::aes::test::{secret_share_aes_key_state, AES_SBOX, AES128_TEST_EXPECTED_OUTPUT, AES128_TEST_INPUT, AES128_TEST_ROUNDKEYS};
    use crate::aes::AesKeyState;
    use crate::share::gf8::GF8;
    use crate::share::Field;

    use super::{sbox_layer, GF8InvBlackBoxSS, VectorAesStateSS};

    pub fn secret_share_ss<R: Rng + CryptoRng, F: Field>(rng: &mut R, values: &[F]) -> (Vec<F>, Vec<F>, Vec<F>) {
        let s1 = F::generate(rng, values.len());
        let s2 = F::generate(rng, values.len());
        let s3 = values.iter().enumerate().map(|(i, &v)| v - s1[i] - s2[i]).collect();
        (s1, s2, s3)
    }

    fn secret_share_vectorstate_ss<R: Rng + CryptoRng>(rng: &mut R, state: &[GF8]) -> (VectorAesStateSS, VectorAesStateSS, VectorAesStateSS) {
        assert_eq!(state.len() % 16, 0);
        let (s1, s2, s3) = secret_share_ss(rng, state);
        let state1 = VectorAesStateSS::from_bytes(s1);
        let state2 = VectorAesStateSS::from_bytes(s2);
        let state3 = VectorAesStateSS::from_bytes(s3);
        (state1, state2, state3)
    }

    pub fn test_sub_bytes_ss<S: TestSetup<P>, P: GF8InvBlackBoxSS>(n_worker_threads: Option<usize>) {
        // check all possible S-box inputs by using 16 AES states in parallel
        let mut rng = thread_rng();
        let inputs = (0..256).map(|x| GF8(x as u8)).collect_vec();
        let inputs = secret_share_ss(&mut rng, &inputs);

        let program = |mut state: Vec<GF8>| {
            move |p: &mut P| {
                p.do_preprocessing(0, 2).unwrap();
                sbox_layer(p, &mut state).unwrap();
                state
            }
        };
        let ((s1, _), (s2, _), (s3, _)) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(
                n_worker_threads,
                program(inputs.0),
                program(inputs.1),
                program(inputs.2),
            ),
            None => S::localhost_setup(program(inputs.0), program(inputs.1), program(inputs.2)),
        };

        assert_eq!(s1.len(), 256);
        assert_eq!(s2.len(), 256);
        assert_eq!(s3.len(), 256);

        for (i, (s1, s2, s3)) in izip!(s1, s2, s3).enumerate() {
            assert_eq!(s1 + s2 + s3, GF8(AES_SBOX[i]));
        }
    }

    pub fn test_aes128_no_keyschedule_gf8_ss<
        S: TestSetup<P>,
        P: GF8InvBlackBoxSS,
    >(
        n_blocks: usize,
        n_worker_threads: Option<usize>,
    ) {
        let input: Vec<_> = repeat_n(AES128_TEST_INPUT, n_blocks)
            .flatten()
            .map(|x| GF8(x))
            .collect();
        let mut rng = thread_rng();
        let (in1, in2, in3) = secret_share_vectorstate_ss(&mut rng, &input);
        let mut ks1 = Vec::with_capacity(11);
        let mut ks2 = Vec::with_capacity(11);
        let mut ks3 = Vec::with_capacity(11);
        for i in 0..11 {
            let (s1, s2, s3) = secret_share_aes_key_state(&mut rng, &AES128_TEST_ROUNDKEYS[i].map(|x| GF8(x)));
            ks1.push(s1);
            ks2.push(s2);
            ks3.push(s3);
        }

        let program = |input: VectorAesStateSS, ks: Vec<AesKeyState>| {
            move |p: &mut P| {
                p.do_preprocessing(0, input.n).unwrap();
                let output = aes128_no_keyschedule(p, input, &ks).unwrap();
                p.finalize().unwrap();
                // p.io().wait_for_completion();
                output
            }
        };
        let ((s1, _), (s2, _), (s3, _)) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(
                n_worker_threads,
                program(in1, ks1),
                program(in2, ks2),
                program(in3, ks3),
            ),
            None => S::localhost_setup(program(in1, ks1), program(in2, ks2), program(in3, ks3)),
        };
        assert_eq!(s1.n, n_blocks);
        assert_eq!(s2.n, n_blocks);
        assert_eq!(s3.n, n_blocks);

        let shares: Vec<_> = s1
            .to_bytes()
            .into_iter()
            .zip(s2.to_bytes().into_iter().zip(s3.to_bytes()))
            .map(|(s1, (s2, s3))| (s1, s2, s3))
            .collect();

        for (i, (s1, s2, s3)) in shares.into_iter().enumerate() {
            assert_eq!(s1 + s2 + s3, GF8(AES128_TEST_EXPECTED_OUTPUT[i % 16]));
        }
    }

    pub fn test_inv_aes128_no_keyschedule_gf8_ss<
        S: TestSetup<P>,
        P: GF8InvBlackBoxSS,
    >(
        n_blocks: usize,
        n_worker_threads: Option<usize>,
    ) {
        let input: Vec<_> = repeat_n(AES128_TEST_EXPECTED_OUTPUT, n_blocks)
            .flatten()
            .map(|x| GF8(x))
            .collect();
        let mut rng = thread_rng();
        let (in1, in2, in3) = secret_share_vectorstate_ss(&mut rng, &input);
        let mut ks1 = Vec::with_capacity(11);
        let mut ks2 = Vec::with_capacity(11);
        let mut ks3 = Vec::with_capacity(11);
        for i in 0..11 {
            let (s1, s2, s3) = secret_share_aes_key_state(&mut rng, &AES128_TEST_ROUNDKEYS[i].map(|x| GF8(x)));
            ks1.push(s1);
            ks2.push(s2);
            ks3.push(s3);
        }

        let program = |input: VectorAesStateSS, ks: Vec<AesKeyState>| {
            move |p: &mut P| {
                p.do_preprocessing(0, input.n).unwrap();
                let output = aes128_inv_no_keyschedule(p, input, &ks).unwrap();
                p.finalize().unwrap();
                output
            }
        };
        let ((s1, _), (s2, _), (s3, _)) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(
                n_worker_threads,
                program(in1, ks1),
                program(in2, ks2),
                program(in3, ks3),
            ),
            None => S::localhost_setup(program(in1, ks1), program(in2, ks2), program(in3, ks3)),
        };
        assert_eq!(s1.n, n_blocks);
        assert_eq!(s2.n, n_blocks);
        assert_eq!(s3.n, n_blocks);

        let shares: Vec<_> = s1
            .to_bytes()
            .into_iter()
            .zip(s2.to_bytes().into_iter().zip(s3.to_bytes()))
            .map(|(s1, (s2, s3))| (s1, s2, s3))
            .collect();

        for (i, (s1, s2, s3)) in shares.into_iter().enumerate() {
            assert_eq!(s1 + s2 + s3, GF8(AES128_TEST_INPUT[i % 16]));
        }
    }
}