use rep3_core::party::{error::MpcResult, MainParty, Party};

use crate::share::gf8::GF8;

use super::AesKeyState;


pub trait GF8InvBlackBoxSS {
    /// returns a (3,3) sharing of the public constant `value`
    fn constant(&self, value: GF8) -> GF8;
    /// computes inversion of the (3,3) sharing of s in-place
    fn gf8_inv(&mut self, s: &mut [GF8]) -> MpcResult<()>;

    /// computes inversion of the (3,3) sharing of s in-place and returns a (2,3) sharing of s
    // fn gf8_inv_and_rss_output(&mut self, s: &mut[GF8]) -> MpcResult<(Vec<GF8>, Vec<GF8>)>;

    /// run any required pre-processing phase to prepare for computation of the key schedule with n_keys and n_blocks many AES-128 block calls
    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()>;

    /// Do any finalize or check protocols
    fn finalize(&mut self) -> MpcResult<()>;

    /// Reveals data to all parties
    fn output(&mut self, data: &[GF8]) -> MpcResult<Vec<GF8>>;

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
    use rep3_core::test::TestSetup;

    use crate::aes::ss::{aes128_inv_no_keyschedule, aes128_no_keyschedule};
    use crate::aes::test::{secret_share_aes_key_state, AES_SBOX};
    use crate::aes::AesKeyState;
    use crate::share::gf8::GF8;
    use crate::share::Field;

    use super::{sbox_layer, GF8InvBlackBoxSS, VectorAesStateSS};

    fn secret_share_ss<R: Rng + CryptoRng, F: Field>(rng: &mut R, values: &[F]) -> (Vec<F>, Vec<F>, Vec<F>) {
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
        let (h1, h2, h3) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(
                n_worker_threads,
                program(inputs.0),
                program(inputs.1),
                program(inputs.2),
            ),
            None => S::localhost_setup(program(inputs.0), program(inputs.1), program(inputs.2)),
        };
        let (s1, _) = h1.join().unwrap();
        let (s2, _) = h2.join().unwrap();
        let (s3, _) = h3.join().unwrap();

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
        // FIPS 197 Appendix B
        let input: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        let input: Vec<_> = repeat_n(input, n_blocks)
            .flatten()
            .map(|x| GF8(x))
            .collect();
        let round_keys: [[u8; 16]; 11] = [
            // already in row-first representation
            [0x2b, 0x28, 0xab, 0x09, 0x7e, 0xae, 0xf7, 0xcf, 0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c],
            [0xa0, 0x88, 0x23, 0x2a, 0xfa, 0x54, 0xa3, 0x6c, 0xfe, 0x2c, 0x39, 0x76, 0x17, 0xb1, 0x39, 0x05],
            [0xf2, 0x7a, 0x59, 0x73, 0xc2, 0x96, 0x35, 0x59, 0x95, 0xb9, 0x80, 0xf6, 0xf2, 0x43, 0x7a, 0x7f],
            [0x3d, 0x47, 0x1e, 0x6d, 0x80, 0x16, 0x23, 0x7a, 0x47, 0xfe, 0x7e, 0x88, 0x7d, 0x3e, 0x44, 0x3b],
            [0xef, 0xa8, 0xb6, 0xdb, 0x44, 0x52, 0x71, 0x0b, 0xa5, 0x5b, 0x25, 0xad, 0x41, 0x7f, 0x3b, 0x00],
            [0xd4, 0x7c, 0xca, 0x11, 0xd1, 0x83, 0xf2, 0xf9, 0xc6, 0x9d, 0xb8, 0x15, 0xf8, 0x87, 0xbc, 0xbc],
            [0x6d, 0x11, 0xdb, 0xca, 0x88, 0x0b, 0xf9, 0x00, 0xa3, 0x3e, 0x86, 0x93, 0x7a, 0xfd, 0x41, 0xfd],
            [0x4e, 0x5f, 0x84, 0x4e, 0x54, 0x5f, 0xa6, 0xa6, 0xf7, 0xc9, 0x4f, 0xdc, 0x0e, 0xf3, 0xb2, 0x4f],
            [0xea, 0xb5, 0x31, 0x7f, 0xd2, 0x8d, 0x2b, 0x8d, 0x73, 0xba, 0xf5, 0x29, 0x21, 0xd2, 0x60, 0x2f],
            [0xac, 0x19, 0x28, 0x57, 0x77, 0xfa, 0xd1, 0x5c, 0x66, 0xdc, 0x29, 0x00, 0xf3, 0x21, 0x41, 0x6e],
            [0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63, 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6],
        ];
        let expected = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
        let mut rng = thread_rng();
        let (in1, in2, in3) = secret_share_vectorstate_ss(&mut rng, &input);
        let mut ks1 = Vec::with_capacity(11);
        let mut ks2 = Vec::with_capacity(11);
        let mut ks3 = Vec::with_capacity(11);
        for i in 0..11 {
            let (s1, s2, s3) = secret_share_aes_key_state(&mut rng, &round_keys[i].map(|x| GF8(x)));
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
        let (h1, h2, h3) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(
                n_worker_threads,
                program(in1, ks1),
                program(in2, ks2),
                program(in3, ks3),
            ),
            None => S::localhost_setup(program(in1, ks1), program(in2, ks2), program(in3, ks3)),
        };
        let (s1, _) = h1.join().unwrap();
        let (s2, _) = h2.join().unwrap();
        let (s3, _) = h3.join().unwrap();
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
            assert_eq!(s1 + s2 + s3, GF8(expected[i % 16]));
        }
    }

    pub fn test_inv_aes128_no_keyschedule_gf8_ss<
        S: TestSetup<P>,
        P: GF8InvBlackBoxSS,
    >(
        n_blocks: usize,
        n_worker_threads: Option<usize>,
    ) {
        // FIPS 197 Appendix B
        let input: [u8; 16] = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]; //[0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34];
        let input: Vec<_> = repeat_n(input, n_blocks)
            .flatten()
            .map(|x| GF8(x))
            .collect();
        let round_keys: [[u8; 16]; 11] = [
            // already in row-first representation
            [0x2b, 0x28, 0xab, 0x09, 0x7e, 0xae, 0xf7, 0xcf, 0x15, 0xd2, 0x15, 0x4f, 0x16, 0xa6, 0x88, 0x3c],
            [0xa0, 0x88, 0x23, 0x2a, 0xfa, 0x54, 0xa3, 0x6c, 0xfe, 0x2c, 0x39, 0x76, 0x17, 0xb1, 0x39, 0x05],
            [0xf2, 0x7a, 0x59, 0x73, 0xc2, 0x96, 0x35, 0x59, 0x95, 0xb9, 0x80, 0xf6, 0xf2, 0x43, 0x7a, 0x7f],
            [0x3d, 0x47, 0x1e, 0x6d, 0x80, 0x16, 0x23, 0x7a, 0x47, 0xfe, 0x7e, 0x88, 0x7d, 0x3e, 0x44, 0x3b],
            [0xef, 0xa8, 0xb6, 0xdb, 0x44, 0x52, 0x71, 0x0b, 0xa5, 0x5b, 0x25, 0xad, 0x41, 0x7f, 0x3b, 0x00],
            [0xd4, 0x7c, 0xca, 0x11, 0xd1, 0x83, 0xf2, 0xf9, 0xc6, 0x9d, 0xb8, 0x15, 0xf8, 0x87, 0xbc, 0xbc],
            [0x6d, 0x11, 0xdb, 0xca, 0x88, 0x0b, 0xf9, 0x00, 0xa3, 0x3e, 0x86, 0x93, 0x7a, 0xfd, 0x41, 0xfd],
            [0x4e, 0x5f, 0x84, 0x4e, 0x54, 0x5f, 0xa6, 0xa6, 0xf7, 0xc9, 0x4f, 0xdc, 0x0e, 0xf3, 0xb2, 0x4f],
            [0xea, 0xb5, 0x31, 0x7f, 0xd2, 0x8d, 0x2b, 0x8d, 0x73, 0xba, 0xf5, 0x29, 0x21, 0xd2, 0x60, 0x2f],
            [0xac, 0x19, 0x28, 0x57, 0x77, 0xfa, 0xd1, 0x5c, 0x66, 0xdc, 0x29, 0x00, 0xf3, 0x21, 0x41, 0x6e],
            [0xd0, 0xc9, 0xe1, 0xb6, 0x14, 0xee, 0x3f, 0x63, 0xf9, 0x25, 0x0c, 0x0c, 0xa8, 0x89, 0xc8, 0xa6],
        ];
        let expected = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        let mut rng = thread_rng();
        let (in1, in2, in3) = secret_share_vectorstate_ss(&mut rng, &input);
        let mut ks1 = Vec::with_capacity(11);
        let mut ks2 = Vec::with_capacity(11);
        let mut ks3 = Vec::with_capacity(11);
        for i in 0..11 {
            let (s1, s2, s3) = secret_share_aes_key_state(&mut rng, &round_keys[i].map(|x| GF8(x)));
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
        let (h1, h2, h3) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(
                n_worker_threads,
                program(in1, ks1),
                program(in2, ks2),
                program(in3, ks3),
            ),
            None => S::localhost_setup(program(in1, ks1), program(in2, ks2), program(in3, ks3)),
        };
        let (s1, _) = h1.join().unwrap();
        let (s2, _) = h2.join().unwrap();
        let (s3, _) = h3.join().unwrap();
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
            assert_eq!(s1 + s2 + s3, GF8(expected[i % 16]));
        }
    }
}