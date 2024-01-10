use std::fmt::{Debug, Formatter};
use std::ops::{Add, AddAssign, Mul, Neg, Sub};
use rand::{CryptoRng, Rng};
use sha2::Digest;
use crate::network::CommChannel;
use crate::share::{Field, FieldDigestExt, FieldRngExt, FieldVectorCommChannel};
use crate::share::gf8_tables;

#[derive(Copy, Clone, Default, PartialEq)]
pub struct GF8(pub u8);

impl GF8 {
    pub fn square(self) -> Self {
        Self(SQ_TABLE[self.0 as usize])
    }

    pub fn cube(self) -> Self {
        Self(CUB_TABLE[self.0 as usize])
    }

    pub fn x4y2(x: Self, y: Self) -> Self {
        Self(gf8_tables::X4Y2[x.0 as usize][y.0 as usize])
    }

    pub fn x4y(x: Self, y: Self) -> Self {
        Self(gf8_tables::X4Y[x.0 as usize][y.0 as usize])
    }

    pub fn x16y(x: Self, y: Self) -> Self {
        Self(gf8_tables::X16Y[x.0 as usize][y.0 as usize])
    }

    pub fn aes_sbox_affine_transform(self) -> Self {
        Self(AFFINE_TABLE[self.0 as usize])
    }

    pub fn inv_aes_sbox_affine_transform(self) -> Self {
        Self(INV_AFFINE_TABLE[self.0 as usize])
    }
}

impl Field for GF8 {
    fn size() -> usize { 1 }

    fn zero() -> Self {
        Self(0u8)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl Add for GF8 {
    type Output = GF8;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl AddAssign for GF8 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Sub for GF8 {
    type Output = GF8;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Neg for GF8 {
    type Output = GF8;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Debug for GF8 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GF8(0x{:02x})", self.0)
    }
}

const SQ_TABLE: [u8; 256] = [0x0, 0x1, 0x4, 0x5, 0x10, 0x11, 0x14, 0x15, 0x40, 0x41, 0x44, 0x45, 0x50, 0x51, 0x54, 0x55, 0x1b, 0x1a, 0x1f, 0x1e, 0xb, 0xa, 0xf, 0xe, 0x5b, 0x5a, 0x5f, 0x5e, 0x4b, 0x4a, 0x4f, 0x4e, 0x6c, 0x6d, 0x68, 0x69, 0x7c, 0x7d, 0x78, 0x79, 0x2c, 0x2d, 0x28, 0x29, 0x3c, 0x3d, 0x38, 0x39, 0x77, 0x76, 0x73, 0x72, 0x67, 0x66, 0x63, 0x62, 0x37, 0x36, 0x33, 0x32, 0x27, 0x26, 0x23, 0x22, 0xab, 0xaa, 0xaf, 0xae, 0xbb, 0xba, 0xbf, 0xbe, 0xeb, 0xea, 0xef, 0xee, 0xfb, 0xfa, 0xff, 0xfe, 0xb0, 0xb1, 0xb4, 0xb5, 0xa0, 0xa1, 0xa4, 0xa5, 0xf0, 0xf1, 0xf4, 0xf5, 0xe0, 0xe1, 0xe4, 0xe5, 0xc7, 0xc6, 0xc3, 0xc2, 0xd7, 0xd6, 0xd3, 0xd2, 0x87, 0x86, 0x83, 0x82, 0x97, 0x96, 0x93, 0x92, 0xdc, 0xdd, 0xd8, 0xd9, 0xcc, 0xcd, 0xc8, 0xc9, 0x9c, 0x9d, 0x98, 0x99, 0x8c, 0x8d, 0x88, 0x89, 0x9a, 0x9b, 0x9e, 0x9f, 0x8a, 0x8b, 0x8e, 0x8f, 0xda, 0xdb, 0xde, 0xdf, 0xca, 0xcb, 0xce, 0xcf, 0x81, 0x80, 0x85, 0x84, 0x91, 0x90, 0x95, 0x94, 0xc1, 0xc0, 0xc5, 0xc4, 0xd1, 0xd0, 0xd5, 0xd4, 0xf6, 0xf7, 0xf2, 0xf3, 0xe6, 0xe7, 0xe2, 0xe3, 0xb6, 0xb7, 0xb2, 0xb3, 0xa6, 0xa7, 0xa2, 0xa3, 0xed, 0xec, 0xe9, 0xe8, 0xfd, 0xfc, 0xf9, 0xf8, 0xad, 0xac, 0xa9, 0xa8, 0xbd, 0xbc, 0xb9, 0xb8, 0x31, 0x30, 0x35, 0x34, 0x21, 0x20, 0x25, 0x24, 0x71, 0x70, 0x75, 0x74, 0x61, 0x60, 0x65, 0x64, 0x2a, 0x2b, 0x2e, 0x2f, 0x3a, 0x3b, 0x3e, 0x3f, 0x6a, 0x6b, 0x6e, 0x6f, 0x7a, 0x7b, 0x7e, 0x7f, 0x5d, 0x5c, 0x59, 0x58, 0x4d, 0x4c, 0x49, 0x48, 0x1d, 0x1c, 0x19, 0x18, 0xd, 0xc, 0x9, 0x8, 0x46, 0x47, 0x42, 0x43, 0x56, 0x57, 0x52, 0x53, 0x6, 0x7, 0x2, 0x3, 0x16, 0x17, 0x12, 0x13];
const CUB_TABLE: [u8; 256] = [0x0, 0x1, 0x8, 0xf, 0x40, 0x55, 0x78, 0x6b, 0x36, 0x7f, 0x9e, 0xd1, 0xed, 0xb0, 0x75, 0x2e, 0xab, 0xa1, 0xd5, 0xd9, 0x9c, 0x82, 0xd2, 0xca, 0x29, 0x6b, 0xf7, 0xb3, 0x85, 0xd3, 0x6b, 0x3b, 0x2f, 0x62, 0x7f, 0x34, 0xf2, 0xab, 0x92, 0xcd, 0x8c, 0x89, 0x7c, 0x7f, 0xca, 0xdb, 0xa, 0x1d, 0x53, 0x15, 0x75, 0x35, 0xf9, 0xab, 0xef, 0xbb, 0x44, 0x4a, 0xc2, 0xca, 0x75, 0x6f, 0xc3, 0xdf, 0x63, 0x89, 0x3d, 0xd1, 0xd5, 0x2b, 0xbb, 0x43, 0xd1, 0x73, 0x2f, 0x8b, 0xfc, 0x4a, 0x32, 0x82, 0xc, 0xed, 0x24, 0xc3, 0xcd, 0x38, 0xd5, 0x26, 0xa, 0xa3, 0x82, 0x2d, 0x50, 0xed, 0xe8, 0x53, 0xae, 0x8, 0xa8, 0x8, 0x85, 0x37, 0xb3, 0x7, 0x89, 0x67, 0x2f, 0xc7, 0x39, 0xc3, 0xaf, 0x53, 0x16, 0xbb, 0x66, 0xcd, 0x4a, 0xf3, 0xa, 0xb5, 0x85, 0x60, 0x55, 0xb6, 0x42, 0xb3, 0xa2, 0x55, 0x35, 0x2e, 0x24, 0x39, 0xf3, 0xfc, 0xd2, 0xdb, 0xf2, 0xa1, 0x43, 0x16, 0xaf, 0xe8, 0x2e, 0x6f, 0xd2, 0xc2, 0xb5, 0xa3, 0x63, 0x67, 0x34, 0x36, 0xa1, 0xf9, 0x66, 0x38, 0x8b, 0xc7, 0x7c, 0x36, 0x60, 0x37, 0x29, 0x78, 0x3b, 0x78, 0x42, 0x7, 0x32, 0x2d, 0xdb, 0xc2, 0xf2, 0xf9, 0x2b, 0x26, 0x50, 0xc, 0x6f, 0x35, 0x7c, 0x34, 0x73, 0x3d, 0xb6, 0xa2, 0x29, 0x3b, 0x1, 0x1, 0xae, 0xa8, 0x7, 0xf7, 0x40, 0xb6, 0x37, 0xd3, 0x40, 0xa2, 0x44, 0xfc, 0xa3, 0x1d, 0xef, 0x43, 0x38, 0x92, 0x24, 0xdf, 0x15, 0xe8, 0x63, 0x8c, 0x62, 0x8b, 0xd3, 0x60, 0x42, 0xf7, 0xf, 0xa8, 0xae, 0xf, 0xb0, 0xc, 0xaf, 0x15, 0x1d, 0xb5, 0x32, 0x9c, 0x66, 0x92, 0xd9, 0x2b, 0x50, 0xb0, 0xdf, 0x39, 0x44, 0xf3, 0x2d, 0x9c, 0x9e, 0x3d, 0xc7, 0x62, 0x26, 0xd9, 0xef, 0x16, 0x67, 0x8c, 0x9e, 0x73];
const AFFINE_TABLE: [u8; 256] = [0x0, 0x1f, 0x3e, 0x21, 0x7c, 0x63, 0x42, 0x5d, 0xf8, 0xe7, 0xc6, 0xd9, 0x84, 0x9b, 0xba, 0xa5, 0xf1, 0xee, 0xcf, 0xd0, 0x8d, 0x92, 0xb3, 0xac, 0x9, 0x16, 0x37, 0x28, 0x75, 0x6a, 0x4b, 0x54, 0xe3, 0xfc, 0xdd, 0xc2, 0x9f, 0x80, 0xa1, 0xbe, 0x1b, 0x4, 0x25, 0x3a, 0x67, 0x78, 0x59, 0x46, 0x12, 0xd, 0x2c, 0x33, 0x6e, 0x71, 0x50, 0x4f, 0xea, 0xf5, 0xd4, 0xcb, 0x96, 0x89, 0xa8, 0xb7, 0xc7, 0xd8, 0xf9, 0xe6, 0xbb, 0xa4, 0x85, 0x9a, 0x3f, 0x20, 0x1, 0x1e, 0x43, 0x5c, 0x7d, 0x62, 0x36, 0x29, 0x8, 0x17, 0x4a, 0x55, 0x74, 0x6b, 0xce, 0xd1, 0xf0, 0xef, 0xb2, 0xad, 0x8c, 0x93, 0x24, 0x3b, 0x1a, 0x5, 0x58, 0x47, 0x66, 0x79, 0xdc, 0xc3, 0xe2, 0xfd, 0xa0, 0xbf, 0x9e, 0x81, 0xd5, 0xca, 0xeb, 0xf4, 0xa9, 0xb6, 0x97, 0x88, 0x2d, 0x32, 0x13, 0xc, 0x51, 0x4e, 0x6f, 0x70, 0x8f, 0x90, 0xb1, 0xae, 0xf3, 0xec, 0xcd, 0xd2, 0x77, 0x68, 0x49, 0x56, 0xb, 0x14, 0x35, 0x2a, 0x7e, 0x61, 0x40, 0x5f, 0x2, 0x1d, 0x3c, 0x23, 0x86, 0x99, 0xb8, 0xa7, 0xfa, 0xe5, 0xc4, 0xdb, 0x6c, 0x73, 0x52, 0x4d, 0x10, 0xf, 0x2e, 0x31, 0x94, 0x8b, 0xaa, 0xb5, 0xe8, 0xf7, 0xd6, 0xc9, 0x9d, 0x82, 0xa3, 0xbc, 0xe1, 0xfe, 0xdf, 0xc0, 0x65, 0x7a, 0x5b, 0x44, 0x19, 0x6, 0x27, 0x38, 0x48, 0x57, 0x76, 0x69, 0x34, 0x2b, 0xa, 0x15, 0xb0, 0xaf, 0x8e, 0x91, 0xcc, 0xd3, 0xf2, 0xed, 0xb9, 0xa6, 0x87, 0x98, 0xc5, 0xda, 0xfb, 0xe4, 0x41, 0x5e, 0x7f, 0x60, 0x3d, 0x22, 0x3, 0x1c, 0xab, 0xb4, 0x95, 0x8a, 0xd7, 0xc8, 0xe9, 0xf6, 0x53, 0x4c, 0x6d, 0x72, 0x2f, 0x30, 0x11, 0xe, 0x5a, 0x45, 0x64, 0x7b, 0x26, 0x39, 0x18, 0x7, 0xa2, 0xbd, 0x9c, 0x83, 0xde, 0xc1, 0xe0, 0xff];
const INV_AFFINE_TABLE: [u8; 256] = [0x00, 0x4a, 0x94, 0xde, 0x29, 0x63, 0xbd, 0xf7, 0x52, 0x18, 0xc6, 0x8c, 0x7b, 0x31, 0xef, 0xa5, 0xa4, 0xee, 0x30, 0x7a, 0x8d, 0xc7, 0x19, 0x53, 0xf6, 0xbc, 0x62, 0x28, 0xdf, 0x95, 0x4b, 0x01, 0x49, 0x03, 0xdd, 0x97, 0x60, 0x2a, 0xf4, 0xbe, 0x1b, 0x51, 0x8f, 0xc5, 0x32, 0x78, 0xa6, 0xec, 0xed, 0xa7, 0x79, 0x33, 0xc4, 0x8e, 0x50, 0x1a, 0xbf, 0xf5, 0x2b, 0x61, 0x96, 0xdc, 0x02, 0x48, 0x92, 0xd8, 0x06, 0x4c, 0xbb, 0xf1, 0x2f, 0x65, 0xc0, 0x8a, 0x54, 0x1e, 0xe9, 0xa3, 0x7d, 0x37, 0x36, 0x7c, 0xa2, 0xe8, 0x1f, 0x55, 0x8b, 0xc1, 0x64, 0x2e, 0xf0, 0xba, 0x4d, 0x07, 0xd9, 0x93, 0xdb, 0x91, 0x4f, 0x05, 0xf2, 0xb8, 0x66, 0x2c, 0x89, 0xc3, 0x1d, 0x57, 0xa0, 0xea, 0x34, 0x7e, 0x7f, 0x35, 0xeb, 0xa1, 0x56, 0x1c, 0xc2, 0x88, 0x2d, 0x67, 0xb9, 0xf3, 0x04, 0x4e, 0x90, 0xda, 0x25, 0x6f, 0xb1, 0xfb, 0x0c, 0x46, 0x98, 0xd2, 0x77, 0x3d, 0xe3, 0xa9, 0x5e, 0x14, 0xca, 0x80, 0x81, 0xcb, 0x15, 0x5f, 0xa8, 0xe2, 0x3c, 0x76, 0xd3, 0x99, 0x47, 0x0d, 0xfa, 0xb0, 0x6e, 0x24, 0x6c, 0x26, 0xf8, 0xb2, 0x45, 0x0f, 0xd1, 0x9b, 0x3e, 0x74, 0xaa, 0xe0, 0x17, 0x5d, 0x83, 0xc9, 0xc8, 0x82, 0x5c, 0x16, 0xe1, 0xab, 0x75, 0x3f, 0x9a, 0xd0, 0x0e, 0x44, 0xb3, 0xf9, 0x27, 0x6d, 0xb7, 0xfd, 0x23, 0x69, 0x9e, 0xd4, 0x0a, 0x40, 0xe5, 0xaf, 0x71, 0x3b, 0xcc, 0x86, 0x58, 0x12, 0x13, 0x59, 0x87, 0xcd, 0x3a, 0x70, 0xae, 0xe4, 0x41, 0x0b, 0xd5, 0x9f, 0x68, 0x22, 0xfc, 0xb6, 0xfe, 0xb4, 0x6a, 0x20, 0xd7, 0x9d, 0x43, 0x09, 0xac, 0xe6, 0x38, 0x72, 0x85, 0xcf, 0x11, 0x5b, 0x5a, 0x10, 0xce, 0x84, 0x73, 0x39, 0xe7, 0xad, 0x08, 0x42, 0x9c, 0xd6, 0x21, 0x6b, 0xb5, 0xff];

impl Mul for GF8 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(gf8_tables::MUL_TABLE[self.0 as usize][rhs.0 as usize])
    }
}

impl<R: Rng + CryptoRng> FieldRngExt<GF8> for R {
    fn generate(&mut self, n: usize) -> Vec<GF8> {
        let mut r = vec![0; n];
        // r.fill(0);
        // debug_assert_eq!(r.len(), n);
        self.fill_bytes(&mut r);
        r.into_iter().map(|x| GF8(x)).collect()
    }

    fn fill(&mut self, buf: &mut [GF8]) {
        let mut v = vec![0u8; buf.len()];
        self.fill_bytes(&mut v);
        buf.iter_mut().zip(v).for_each(|(x, r)| x.0 = r)
    }
}

impl<D: Digest> FieldDigestExt<GF8> for D {
    fn update(&mut self, message: &[GF8]) {
        for x in message {
            self.update(&[x.0]);
        }
    }
}

impl FieldVectorCommChannel<GF8> for CommChannel {
    fn write_vector(&mut self, vector: &[GF8]) -> std::io::Result<()> {
        let mut buf = vec![0; vector.len()];
        for i in 0..vector.len() {
            buf[i] = vector[i].0;
        }
        self.write(&mut buf)
    }

    fn read_vector(&mut self, buffer: &mut [GF8]) -> std::io::Result<()> {
        let mut buf = vec![0; buffer.len()];
        self.read(&mut buf)?;
        for i in 0..buffer.len() {
            buffer[i] = GF8(buf[i]);
        }
        Ok(())
    }
}