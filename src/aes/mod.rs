use crate::{party::{error::MpcResult, ArithmeticBlackBox}, share::{gf8::GF8, RssShare}};
#[cfg(feature = "verbose-timing")]
use {std::time::Instant, crate::party::PARTY_TIMER};
pub trait GF8InvBlackBox {
    /// returns a (2,3) sharing of the public constant `value`
    fn constant(&self, value: GF8) -> RssShare<GF8>;
    /// computes inversion of the (2,3) sharing of s (si,sii) in-place
    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()>;

    /// run any required pre-processing phase to prepare for computation of the key schedule with n_keys and n_blocks many AES-128 block calls
    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()>;
}

// contains n AES States in parallel (ie si has length n * 16)
#[derive(Clone)]
pub struct VectorAesState {
    si: Vec<GF8>,
    sii: Vec<GF8>,
    n: usize
}

impl VectorAesState {
    pub fn new(n: usize) -> Self {
        Self {
            si: vec![GF8(0u8); n*16],
            sii: vec![GF8(0u8); n*16],
            n
        }
    }

    // fills AES states column-wise (as in FIPS 97)
    // bytes.len() must be a multiple of 16
    pub fn from_bytes(bytes: Vec<RssShare<GF8>>) -> Self {
        let n = bytes.len() / 16;
        debug_assert_eq!(16*n, bytes.len());
        let mut state = Self::new(n);
        for k in 0..n {
            for i in 0..4 {
                for j in 0..4 {
                    state.si[16*k + 4*i+j] = bytes[16*k + 4*j+i].si;
                    state.sii[16*k + 4*i+j] = bytes[16*k + 4*j+i].sii;
                }
            }
        }
        state
    }

    // outputs the AES states column-wise (as in FIPS 97)
    pub fn to_bytes(self) -> Vec<RssShare<GF8>> {
        let mut vec = Vec::with_capacity(self.n*16);
        for k in 0..self.n {
            for i in 0..4 {
                for j in 0..4 {
                    vec.push(RssShare::from(self.si[16*k + 4*j+i], self.sii[16*k + 4*j+i]));
                }
            }
        }
        vec
    }

    fn with_capacity(n: usize) -> Self {
        Self {
            si: Vec::with_capacity(16*n),
            sii: Vec::with_capacity(16*n),
            n
        }
    }

    pub fn append(&mut self, mut other: Self) {
        self.si.append(&mut other.si);
        self.sii.append(&mut other.sii);
        self.n += other.n;
    }

    #[inline]
    fn permute4(&mut self, start: usize, perm: [usize; 4]) {
        let tmp_i = [self.si[start], self.si[start+1], self.si[start+2], self.si[start+3]];
        let tmp_ii = [self.sii[start], self.sii[start+1], self.sii[start+2], self.sii[start+3]];
        for i in 0..4 {
            self.si[start+i] = tmp_i[perm[i]];
            self.sii[start+i] = tmp_ii[perm[i]];
        }
    }

    pub fn shift_rows(&mut self) {
        for i in 0..self.n {
            // rotate row 2 by 1 to the left
            self.permute4(16*i+4, [1,2,3,0]);
            // rotate row 3 by 2 to the left
            self.permute4(16*i+8, [2,3,0,1]);
            // rotate row 4 by 3 to the left
            self.permute4(16*i+12, [3,0,1,2]);
        }
    }

    pub fn inv_shift_rows(&mut self) {
        for i in 0..self.n {
            // rotate row 2 by 1 to the right
            self.permute4(16*i+4, [3,0,1,2]);
            // rotate row 3 by 2 to the right
            self.permute4(16*i+8, [2,3,0,1]);
            // rotate row 4 by 3 to the right
            self.permute4(16*i+12, [1,2,3,0]);
        }
    }

    #[inline]
    fn mix_single_column(&mut self, start: usize) {
        let c0 = RssShare::from(self.si[start], self.sii[start]);
        let c1 = RssShare::from(self.si[start+4], self.sii[start+4]);
        let c2 = RssShare::from(self.si[start+8], self.sii[start+8]);
        let c3 = RssShare::from(self.si[start+12], self.sii[start+12]);

        let m0 = c0 * GF8(0x2) + c1 * GF8(0x3) + c2 + c3;
        let m1 = c0 + c1 * GF8(0x2) + c2 * GF8(0x3) + c3;
        let m2 = c0 + c1 + c2 * GF8(0x2) + c3 * GF8(0x3);
        let m3 = c0 * GF8(0x3) + c1 + c2 + c3 * GF8(0x2);
        self.si[start] = m0.si;
        self.sii[start] = m0.sii;
        self.si[start+4] = m1.si;
        self.sii[start+4] = m1.sii;
        self.si[start+8] = m2.si;
        self.sii[start+8] = m2.sii;
        self.si[start+12] = m3.si;
        self.sii[start+12] = m3.sii;
    }

    pub fn mix_columns(&mut self) {
        for i in 0..self.n {
            self.mix_single_column(16*i);
            self.mix_single_column(16*i+1);
            self.mix_single_column(16*i+2);
            self.mix_single_column(16*i+3);
        }
    }

    #[inline]
    fn inv_mix_single_column(&mut self, start: usize) {
        let c0 = RssShare::from(self.si[start], self.sii[start]);
        let c1 = RssShare::from(self.si[start+4], self.sii[start+4]);
        let c2 = RssShare::from(self.si[start+8], self.sii[start+8]);
        let c3 = RssShare::from(self.si[start+12], self.sii[start+12]);

        let m0 = c0 * GF8(0xe) + c1 * GF8(0xb) + c2 * GF8(0xd) + c3 * GF8(0x9);
        let m1 = c0 * GF8(0x9) + c1 * GF8(0xe) + c2 * GF8(0xb) + c3 * GF8(0xd);
        let m2 = c0 * GF8(0xd) + c1 * GF8(0x9) + c2 * GF8(0xe) + c3 * GF8(0xb);
        let m3 = c0 * GF8(0xb) + c1 * GF8(0xd) + c2 * GF8(0x9) + c3 * GF8(0xe);
        self.si[start] = m0.si;
        self.sii[start] = m0.sii;
        self.si[start+4] = m1.si;
        self.sii[start+4] = m1.sii;
        self.si[start+8] = m2.si;
        self.sii[start+8] = m2.sii;
        self.si[start+12] = m3.si;
        self.sii[start+12] = m3.sii;
    }

    pub fn inv_mix_columns(&mut self) {
        for i in 0..self.n {
            self.inv_mix_single_column(16*i);
            self.inv_mix_single_column(16*i+1);
            self.inv_mix_single_column(16*i+2);
            self.inv_mix_single_column(16*i+3);
        }
    }
}

/// A row-wise representation of the AES (round) key
#[derive(Clone)]
pub struct AesKeyState {
    si: [GF8; 16],
    sii: [GF8; 16]
}

impl AesKeyState {
    /// Returns a all zero state
    pub fn new() -> Self {
        Self {
            si: [GF8(0); 16],
            sii: [GF8(0); 16],
        }
    }

    // vec is interpreted as column-wise (see FIPS 97)
    pub fn from_bytes(vec: Vec<RssShare<GF8>>) -> Self {
        debug_assert_eq!(vec.len(), 16);
        let mut state = Self::new();
        for i in 0..4 {
            for j in 0..4 {
                state.si[4*i+j] = vec[4*j+i].si;
                state.sii[4*i+j] = vec[4*j+i].sii;
            }
        }
        return state;
    }

    // vec must be in row-wise representation
    pub fn from_rss_vec(vec: Vec<RssShare<GF8>>) -> Self {
        debug_assert_eq!(16, vec.len());
        let mut state = Self::new();
        for (i,x) in vec.into_iter().enumerate() {
            state.si[i] = x.si;
            state.sii[i] = x.sii;
        };
        return state;
    }

    pub fn to_rss_vec(self) -> Vec<RssShare<GF8>> {
        let mut out = Vec::with_capacity(16);
        for i in 0..16 {
            out.push(RssShare::from(self.si[i], self.sii[i]));
        }
        return out;
    }
}

pub fn random_state<Protocol: ArithmeticBlackBox<GF8>>(party: &mut Protocol, size: usize) -> VectorAesState {
    VectorAesState::from_bytes(party.generate_random(size * 16))
}

/// returns random key states for benchmarking purposes
pub fn random_keyschedule<Protocol: ArithmeticBlackBox<GF8>>(party: &mut Protocol) -> Vec<AesKeyState> {
    (0..11).map(|_| {
        let rk = party.generate_random(16);
        AesKeyState::from_rss_vec(rk)
    })
    .collect()
}

macro_rules! timer {
    ($a:literal, {$b:expr;}) => {
        #[cfg(feature = "verbose-timing")]
        let time_start = Instant::now();
        $b;
        #[cfg(feature = "verbose-timing")]
        PARTY_TIMER.lock().unwrap().report_time($a, time_start.elapsed());
    };
}

pub fn aes128_no_keyschedule<Protocol: GF8InvBlackBox>(party: &mut Protocol, inputs: VectorAesState, round_key: &Vec<AesKeyState>) -> MpcResult<VectorAesState> {
    debug_assert_eq!(round_key.len(), 11);
    let mut state = inputs;

    timer!("aes_add_rk", {
        add_round_key(&mut state, &round_key[0]);
    });

    for r in 1..= 9 {
        timer!("aes_sbox", {
            sbox_layer(party, &mut state.si, &mut state.sii)?;
        });
        timer!("aes_shift_rows", {
            state.shift_rows();
        });
        timer!("aes_mix_columns", {
            state.mix_columns();
        });
        timer!("aes_add_rk", {
            add_round_key(&mut state, &round_key[r]);
        });
    }
    timer!("aes_sbox", {
        sbox_layer(party, &mut state.si, &mut state.sii)?;
    });
    timer!("aes_shift_rows", {
    state.shift_rows();
    });

    timer!("aes_add_rk", {
        add_round_key(&mut state, &round_key[10]);
    });

    Ok(state)
}

pub fn aes128_inv_no_keyschedule<Protocol: GF8InvBlackBox>(party: &mut Protocol, inputs: VectorAesState, key_schedule: &Vec<AesKeyState>) -> MpcResult<VectorAesState> {
    debug_assert_eq!(key_schedule.len(), 11);
    let mut state = inputs;

    add_round_key(&mut state, &key_schedule[10]);
    for r in (1..=9).rev() {
        state.inv_shift_rows();
        inv_sbox_layer(party, &mut state.si, &mut state.sii)?;
        add_round_key(&mut state, &key_schedule[r]);
        state.inv_mix_columns();
    }
    state.inv_shift_rows();
    inv_sbox_layer(party, &mut state.si, &mut state.sii)?;
    add_round_key(&mut state, &key_schedule[0]);
    Ok(state)
}

fn aes128_keyschedule_round<Protocol: GF8InvBlackBox>(party: &mut Protocol, rk: &AesKeyState, rcon: GF8) -> MpcResult<AesKeyState> {
    let mut rot_i = [rk.si[7], rk.si[11], rk.si[15], rk.si[3]];
    let mut rot_ii = [rk.sii[7], rk.sii[11], rk.sii[15], rk.sii[3]];
    sbox_layer(party, &mut rot_i, &mut rot_ii)?;
    
    let mut output = rk.clone();
    for i in 0..4 {
        output.si[4*i] += rot_i[i];
        output.sii[4*i] += rot_ii[i];
    }
    let rcon = party.constant(rcon);
    output.si[0] += rcon.si;
    output.sii[0] += rcon.sii;
    
    for j in 1..4 {
        for i in 0..4 {
            output.si[4*i+j] += output.si[4*i+j-1];
            output.sii[4*i+j] += output.sii[4*i+j-1];
        }
    }
    Ok(output)
}

pub fn aes128_keyschedule<Protocol: GF8InvBlackBox>(party: &mut Protocol, key: Vec<RssShare<GF8>>) -> MpcResult<Vec<AesKeyState>> {
    debug_assert_eq!(key.len(), 16);
    const ROUND_CONSTANTS: [GF8; 10] = [GF8(0x01), GF8(0x02), GF8(0x04), GF8(0x08), GF8(0x10), GF8(0x20), GF8(0x40), GF8(0x80), GF8(0x1b), GF8(0x36)];
    let mut ks = Vec::with_capacity(11);
    ks.push(AesKeyState::from_bytes(key)); // rk0
    for i in 1..=10 {
        let rki = aes128_keyschedule_round(party, &ks[i-1], ROUND_CONSTANTS[i-1])?;
        ks.push(rki);
    }
    Ok(ks)
}

pub fn output<Protocol: ArithmeticBlackBox<GF8>>(party: &mut Protocol, blocks: VectorAesState) -> MpcResult<Vec<GF8>> {
    let shares = blocks.to_bytes();
    let (si, sii): (Vec<_>, Vec<_>) = shares.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
    party.output_round(&si, &sii)
}

fn add_round_key(states: &mut VectorAesState, round_key: &AesKeyState) {
    for j in 0..states.n {
        for i in 0..16 {
            states.si[16*j+i] += round_key.si[i];
            states.sii[16*j+i] += round_key.sii[i];
        }
    }
}

fn sbox_layer<Protocol: GF8InvBlackBox>(party: &mut Protocol, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
    // first inverse, then affine transform
    party.gf8_inv(si, sii)?;
        
    // apply affine transform
    let c = party.constant(GF8(0x63));
    for i in 0..si.len() {
        si[i] = si[i].aes_sbox_affine_transform() + c.si;
        sii[i] = sii[i].aes_sbox_affine_transform() + c.sii;
    }
    Ok(())
}



fn inv_sbox_layer<Protocol: GF8InvBlackBox>(party: &mut Protocol, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
    // first inverse affine transform, then gf8 inverse
    // apply inverse affine transform
    let c = party.constant(GF8(0x63));
    for i in 0..si.len() {
        si[i] = (si[i] + c.si).inv_aes_sbox_affine_transform();
        sii[i] = (sii[i] + c.sii).inv_aes_sbox_affine_transform();
    }
    party.gf8_inv(si, sii)
}

pub const INV_GF8: [u8; 256] = [0x0, 0x1, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5, 0xc7, 0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f, 0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40, 0xee, 0xb2, 0x3a, 0x6e, 0x5a, 0xf1, 0x55, 0x4d, 0xa8, 0xc9, 0xc1, 0xa, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2, 0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20, 0x6f, 0x77, 0xbb, 0x59, 0x19, 0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69, 0xa7, 0x64, 0xab, 0x13, 0x54, 0x25, 0xe9, 0x9, 0xed, 0x5c, 0x5, 0xca, 0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e, 0x22, 0xf0, 0x51, 0xec, 0x61, 0x17, 0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4, 0x47, 0x91, 0xdf, 0x33, 0x93, 0x21, 0x3b, 0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c, 0xb6, 0x70, 0xd0, 0x6, 0xa1, 0xfa, 0x81, 0x82, 0x83, 0x7e, 0x7f, 0x80, 0x96, 0x73, 0xbe, 0x56, 0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x2, 0xb9, 0xa4, 0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72, 0x2a, 0x14, 0x9f, 0x88, 0xf9, 0xdc, 0x89, 0x9a, 0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48, 0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62, 0xc, 0xe0, 0x1f, 0xef, 0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57, 0xb, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0xf, 0xa9, 0x27, 0x53, 0x4, 0x1b, 0xfc, 0xac, 0xe6, 0x7a, 0x7, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea, 0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b, 0xb1, 0xd, 0xd6, 0xeb, 0xc6, 0xe, 0xcf, 0xad, 0x8, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3, 0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x3, 0x8c, 0xdd, 0x9c, 0x7d, 0xa0, 0xcd, 0x1a, 0x41, 0x1c];
#[cfg(any(test, feature = "benchmark-helper"))]
pub mod test {

    use itertools::repeat_n;
    use rand::{thread_rng, CryptoRng, Rng};

    use crate::{aes::{aes128_inv_no_keyschedule, aes128_keyschedule, aes128_no_keyschedule, sbox_layer, INV_GF8}, party::test::TestSetup, share::{gf8::GF8, test::{assert_eq, consistent, secret_share}, RssShare}};

    use super::{AesKeyState, ArithmeticBlackBox, GF8InvBlackBox, VectorAesState};

    const AES_SBOX: [u8; 256] = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16];

    fn into_rss_share(s1: VectorAesState, s2: VectorAesState, s3: VectorAesState) -> Vec<(RssShare<GF8>,RssShare<GF8>,RssShare<GF8>)> {
        assert_eq!(s1.n, s2.n);
        assert_eq!(s2.n, s3.n);
        (0..s1.si.len()).map(|i| {
            (RssShare::from(s1.si[i], s1.sii[i]), RssShare::from(s2.si[i], s2.sii[i]), RssShare::from(s3.si[i], s3.sii[i]))
        }).collect()
    }
    
    #[test]
    fn mix_columns() {
        // test vector from FIPS 197
        let input: [u8; 16] = [0xd4, 0xe0, 0xb8, 0x1e, 0xbf, 0xb4, 0x41, 0x27, 0x5d, 0x52, 0x11, 0x98, 0x30, 0xae, 0xf1, 0xe5];
        let expected: [u8; 16] = [0x04, 0xe0, 0x48, 0x28, 0x66, 0xcb, 0xf8, 0x06, 0x81, 0x19, 0xd3, 0x26, 0xe5, 0x9a, 0x7a, 0x4c];
        let mut state = VectorAesState::with_capacity(1);
        state.si.append(&mut input.iter().map(|x|GF8(*x)).collect());
        state.sii.append(&mut (0..input.len()).map(|_|GF8(0)).collect());
        state.mix_columns();
        for (i,e) in expected.into_iter().enumerate() {
            assert_eq!(state.si[i].0, e);
        }
    }

    #[test]
    fn aes_sbox_affine() {
        for i in 0..256 {
            let x = GF8(i as u8);
            let x_inv = GF8(INV_GF8[x.0 as usize]);
            let x_affine = x_inv.aes_sbox_affine_transform();
            let x_sbox = x_affine + GF8(0x63);
            assert_eq!(x_sbox.0, AES_SBOX[i]);
        }
    }

    pub fn test_sub_bytes<S: TestSetup<P>, P: GF8InvBlackBox>(n_worker_threads: Option<usize>)
    {
        // check all possible S-box inputs by using 16 AES states in parallel
        let mut rng = thread_rng();
        let inputs: Vec<_> = (0..256).map(|x| secret_share(&mut rng, &GF8(x as u8)))
            .collect();
        let s1: Vec<_> = inputs.iter().map(|(s1,_, _)|s1.si).collect();
        let s2: Vec<_> = inputs.iter().map(|(_,s2,_)|s2.si).collect();
        let s3: Vec<_> = inputs.iter().map(|(_,_,s3)|s3.si).collect();
        let state1 = VectorAesState {
            si: s1.clone(),
            sii: s2.clone(),
            n: 16,
        };
        let state2 = VectorAesState {
            si: s2,
            sii: s3.clone(),
            n: 16,
        };
        let state3 = VectorAesState {
            si: s3,
            sii: s1,
            n: 16,
        };

        let program = |mut state: VectorAesState| {
            move |p: &mut P| {
                p.do_preprocessing(0, 2).unwrap();
                sbox_layer(p, &mut state.si, &mut state.sii).unwrap();
                state
            }
        };
        let (h1, h2, h3) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(n_worker_threads, program(state1), program(state2), program(state3)),
            None => S::localhost_setup(program(state1), program(state2), program(state3)),
        };
        let (s1, _) = h1.join().unwrap();
        let (s2, _) = h2.join().unwrap();
        let (s3, _) = h3.join().unwrap();

        // convert to regular rss shares
        assert_eq!(s1.n, 16);
        assert_eq!(s2.n, 16);
        assert_eq!(s3.n, 16);
        let shares = into_rss_share(s1, s2, s3);

        for (s1,s2,s3) in &shares {
            consistent(s1, s2, s3);
        }

        for (i,(s1, s2, s3)) in shares.into_iter().enumerate() {
            assert_eq(s1, s2, s3, GF8(AES_SBOX[i]));
        }
    }

    pub fn secret_share_aes_key_state<R: Rng + CryptoRng>(rng: &mut R, state: &[GF8]) -> (AesKeyState, AesKeyState, AesKeyState) {
        let mut state1 = AesKeyState::new();
        let mut state2 = AesKeyState::new();
        let mut state3 = AesKeyState::new();
        for (i, (s1, s2, s3)) in state.iter().map(|x| secret_share(rng, x)).enumerate() {
            state1.si[i] = s1.si;
            state1.sii[i] = s1.sii;
            state2.si[i] = s2.si;
            state2.sii[i] = s2.sii;
            state3.si[i] = s3.si;
            state3.sii[i] = s3.sii;
        }
        (state1, state2, state3)
    }

    pub fn secret_share_vectorstate<R: Rng + CryptoRng>(rng: &mut R, state: &[GF8]) -> (VectorAesState, VectorAesState, VectorAesState) {
        assert_eq!(state.len() % 16, 0);
        let n = state.len()/16;
        let mut s1 = Vec::with_capacity(n*16);
        let mut s2 = Vec::with_capacity(n*16);
        let mut s3 = Vec::with_capacity(n*16);
        for xi in state {
            let (share1, share2, share3) = secret_share(rng, xi);
            s1.push(share1);
            s2.push(share2);
            s3.push(share3);
        }
        let state1 = VectorAesState::from_bytes(s1);
        let state2 = VectorAesState::from_bytes(s2);
        let state3 = VectorAesState::from_bytes(s3);
        (state1, state2, state3)
    }

    pub fn test_aes128_no_keyschedule_gf8<S: TestSetup<P>, P: GF8InvBlackBox + ArithmeticBlackBox<GF8>>(n_blocks: usize, n_worker_threads: Option<usize>)
    {
        // FIPS 197 Appendix B
        let input: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        let input: Vec<_> = repeat_n(input, n_blocks).flatten().map(|x|GF8(x)).collect();
        let round_keys: [[u8; 16]; 11] = [ // already in row-first representation
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
        let (in1, in2, in3) = secret_share_vectorstate(&mut rng, &input);
        let mut ks1 = Vec::with_capacity(11);
        let mut ks2 = Vec::with_capacity(11);
        let mut ks3 = Vec::with_capacity(11);
        for i in 0..11 {
            let (s1, s2, s3) = secret_share_aes_key_state(&mut rng, &round_keys[i].map(|x|GF8(x)));
            ks1.push(s1);
            ks2.push(s2);
            ks3.push(s3);
        }

        let program = |input: VectorAesState, ks: Vec<AesKeyState>| {
            move |p: &mut P| {
                p.do_preprocessing(0, input.n).unwrap();
                let output = aes128_no_keyschedule(p, input, &ks).unwrap();
                p.finalize().unwrap();
                p.io().wait_for_completion();
                output
            }
        };
        let (h1, h2, h3) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(n_worker_threads, program(in1, ks1), program(in2, ks2), program(in3, ks3)),
            None => S::localhost_setup(program(in1, ks1), program(in2, ks2), program(in3, ks3)),
        };
        let (s1, _) = h1.join().unwrap();
        let (s2, _) = h2.join().unwrap();
        let (s3, _) = h3.join().unwrap();
        assert_eq!(s1.n, n_blocks);
        assert_eq!(s2.n, n_blocks);
        assert_eq!(s3.n, n_blocks);

        let shares: Vec<_> = s1.to_bytes().into_iter().zip(s2.to_bytes().into_iter().zip(s3.to_bytes()))
            .map(|(s1, (s2,s3))| (s1, s2, s3)).collect();

        for (s1,s2,s3) in &shares {
            consistent(s1, s2, s3);
        }

        for (i,(s1, s2, s3)) in shares.into_iter().enumerate() {
            assert_eq(s1, s2, s3, GF8(expected[i % 16]));
        }
    }

    fn transpose<T>(v: impl IntoIterator<Item=(T,T,T)>) -> (Vec<T>, Vec<T>, Vec<T>) {
        let mut v1 = Vec::new();
        let mut v2 = Vec::new();
        let mut v3 = Vec::new();
        for (x1, x2, x3) in v {
            v1.push(x1);
            v2.push(x2);
            v3.push(x3);
        }
        (v1, v2, v3)
    }

    pub fn test_aes128_keyschedule_gf8<S: TestSetup<P>, P: GF8InvBlackBox + ArithmeticBlackBox<GF8>>(n_worker_threads: Option<usize>) {
        let mut rng = thread_rng();
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let (key1, key2, key3) = transpose(key.into_iter().map(|x| secret_share(&mut rng, &GF8(x))));

        let program = |key: Vec<RssShare<GF8>>| {
            move |p: &mut P| {
                p.do_preprocessing(1, 0).unwrap();
                let ks = aes128_keyschedule(p, key).unwrap();
                p.finalize().unwrap();
                p.io().wait_for_completion();
                ks
            }
        };

        let (h1, h2, h3) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(n_worker_threads, program(key1), program(key2), program(key3)),
            None => S::localhost_setup(program(key1), program(key2), program(key3)),
        };
        let (ks1, _) = h1.join().unwrap();
        let (ks2, _) = h2.join().unwrap();
        let (ks3, _) = h3.join().unwrap();

        assert_eq!(ks1.len(), 11);
        assert_eq!(ks2.len(), 11);
        assert_eq!(ks3.len(), 11);

        let mut ks = Vec::with_capacity(11);
        for (ks1, (ks2, ks3)) in ks1.into_iter().zip(ks2.into_iter().zip(ks3)) {
            let mut rk = Vec::with_capacity(16);
            let ks1 = ks1.to_rss_vec();
            let ks2 = ks2.to_rss_vec();
            let ks3 = ks3.to_rss_vec();
            assert_eq!(ks1.len(), 16);
            assert_eq!(ks2.len(), 16);
            assert_eq!(ks3.len(), 16);
            for i in 0..16 {
                consistent(&ks1[i], &ks2[i], &ks3[i]);
                rk.push((ks1[i], ks2[i], ks3[i]));
            }
            ks.push(rk);
        }
        // round keys in row-first notation
        let round_keys: [[u8; 16]; 11] = [
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
        for i in 0..11 {
            for j in 0..16 {
                let (x1, x2, x3) = ks[i][j];
                assert_eq(x1, x2, x3, GF8(round_keys[i][j]));
            }
        }
    }

    #[test]
    fn inv_shift_rows() {
        let mut state = VectorAesState::new(1);
        // fill with sequence
        state.si.copy_from_slice(&(0..16).map(|x|GF8(x)).collect::<Vec<_>>());

        let mut copy = state.clone();
        copy.shift_rows();
        copy.inv_shift_rows();
        assert_eq!(state.si, copy.si);
    }

    pub fn test_inv_aes128_no_keyschedule_gf8<S: TestSetup<P>, P: GF8InvBlackBox + ArithmeticBlackBox<GF8>>(n_blocks: usize, n_worker_threads: Option<usize>) {
        // FIPS 197 Appendix B
        let input: [u8; 16] = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]; //[0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34];
        let input: Vec<_> = repeat_n(input, n_blocks).flatten().map(|x|GF8(x)).collect();
        let round_keys: [[u8; 16]; 11] = [ // already in row-first representation
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
        let expected = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]; //[0x39, 0x02, 0xdc, 0x19, 0x25, 0xdc, 0x11, 0x6a, 0x84, 0x09, 0x85, 0x0b, 0x1d, 0xfb, 0x97, 0x32];
        let mut rng = thread_rng();
        let (in1, in2, in3) = secret_share_vectorstate(&mut rng, &input);
        let mut ks1 = Vec::with_capacity(11);
        let mut ks2 = Vec::with_capacity(11);
        let mut ks3 = Vec::with_capacity(11);
        for i in 0..11 {
            let (s1, s2, s3) = secret_share_aes_key_state(&mut rng, &round_keys[i].map(|x|GF8(x)));
            ks1.push(s1);
            ks2.push(s2);
            ks3.push(s3);
        }

        let program = |input: VectorAesState, ks: Vec<AesKeyState>| {
            move |p: &mut P| {
                p.do_preprocessing(0, input.n).unwrap();
                let output = aes128_inv_no_keyschedule(p, input, &ks).unwrap();
                p.finalize().unwrap();
                p.io().wait_for_completion();
                output
            }
        };
        let (h1, h2, h3) = match n_worker_threads {
            Some(n_worker_threads) => S::localhost_setup_multithreads(n_worker_threads, program(in1, ks1), program(in2, ks2), program(in3, ks3)),
            None => S::localhost_setup(program(in1, ks1), program(in2, ks2), program(in3, ks3)),
        };
        let (s1, _) = h1.join().unwrap();
        let (s2, _) = h2.join().unwrap();
        let (s3, _) = h3.join().unwrap();
        assert_eq!(s1.n, n_blocks);
        assert_eq!(s2.n, n_blocks);
        assert_eq!(s3.n, n_blocks);

        let shares: Vec<_> = s1.to_bytes().into_iter().zip(s2.to_bytes().into_iter().zip(s3.to_bytes()))
            .map(|(s1, (s2,s3))| (s1, s2, s3)).collect();

        for (s1,s2,s3) in &shares {
            consistent(s1, s2, s3);
        }

        for (i,(s1, s2, s3)) in shares.into_iter().enumerate() {
            assert_eq(s1, s2, s3, GF8(expected[i % 16]));
        }
    }
}
