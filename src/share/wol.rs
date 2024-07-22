//! This module provides the WOL transformations.
//!
//! The WOL transformations are efficient isomorphisms between GF(2^8) and GF(2^4^2)
//! proposed by Wolkerstorfer et al. in "An ASIC Implementation of the AES S-Boxes"
//! in CT-RSA 2002, <https://doi.org/10.1007/3-540-45760-7_6>.
//!

use super::{gf4::GF4, gf8::GF8};

#[rustfmt::skip]
const WOL_TABLE: [(u8, u8); 256] = [
    (0x00, 0x00), (0x00, 0x01), (0x02, 0x06), (0x02, 0x07), (0x04, 0x0a), (0x04, 0x0b), (0x06, 0x0c), (0x06, 0x0d),
    (0x04, 0x00), (0x04, 0x01), (0x06, 0x06), (0x06, 0x07), (0x00, 0x0a), (0x00, 0x0b), (0x02, 0x0c), (0x02, 0x0d),
    (0x03, 0x09), (0x03, 0x08), (0x01, 0x0f), (0x01, 0x0e), (0x07, 0x03), (0x07, 0x02), (0x05, 0x05), (0x05, 0x04),
    (0x07, 0x09), (0x07, 0x08), (0x05, 0x0f), (0x05, 0x0e), (0x03, 0x03), (0x03, 0x02), (0x01, 0x05), (0x01, 0x04),
    (0x0d, 0x01), (0x0d, 0x00), (0x0f, 0x07), (0x0f, 0x06), (0x09, 0x0b), (0x09, 0x0a), (0x0b, 0x0d), (0x0b, 0x0c),
    (0x09, 0x01), (0x09, 0x00), (0x0b, 0x07), (0x0b, 0x06), (0x0d, 0x0b), (0x0d, 0x0a), (0x0f, 0x0d), (0x0f, 0x0c),
    (0x0e, 0x08), (0x0e, 0x09), (0x0c, 0x0e), (0x0c, 0x0f), (0x0a, 0x02), (0x0a, 0x03), (0x08, 0x04), (0x08, 0x05),
    (0x0a, 0x08), (0x0a, 0x09), (0x08, 0x0e), (0x08, 0x0f), (0x0e, 0x02), (0x0e, 0x03), (0x0c, 0x04), (0x0c, 0x05),
    (0x03, 0x01), (0x03, 0x00), (0x01, 0x07), (0x01, 0x06), (0x07, 0x0b), (0x07, 0x0a), (0x05, 0x0d), (0x05, 0x0c),
    (0x07, 0x01), (0x07, 0x00), (0x05, 0x07), (0x05, 0x06), (0x03, 0x0b), (0x03, 0x0a), (0x01, 0x0d), (0x01, 0x0c),
    (0x00, 0x08), (0x00, 0x09), (0x02, 0x0e), (0x02, 0x0f), (0x04, 0x02), (0x04, 0x03), (0x06, 0x04), (0x06, 0x05),
    (0x04, 0x08), (0x04, 0x09), (0x06, 0x0e), (0x06, 0x0f), (0x00, 0x02), (0x00, 0x03), (0x02, 0x04), (0x02, 0x05),
    (0x0e, 0x00), (0x0e, 0x01), (0x0c, 0x06), (0x0c, 0x07), (0x0a, 0x0a), (0x0a, 0x0b), (0x08, 0x0c), (0x08, 0x0d),
    (0x0a, 0x00), (0x0a, 0x01), (0x08, 0x06), (0x08, 0x07), (0x0e, 0x0a), (0x0e, 0x0b), (0x0c, 0x0c), (0x0c, 0x0d),
    (0x0d, 0x09), (0x0d, 0x08), (0x0f, 0x0f), (0x0f, 0x0e), (0x09, 0x03), (0x09, 0x02), (0x0b, 0x05), (0x0b, 0x04),
    (0x09, 0x09), (0x09, 0x08), (0x0b, 0x0f), (0x0b, 0x0e), (0x0d, 0x03), (0x0d, 0x02), (0x0f, 0x05), (0x0f, 0x04),
    (0x0e, 0x04), (0x0e, 0x05), (0x0c, 0x02), (0x0c, 0x03), (0x0a, 0x0e), (0x0a, 0x0f), (0x08, 0x08), (0x08, 0x09),
    (0x0a, 0x04), (0x0a, 0x05), (0x08, 0x02), (0x08, 0x03), (0x0e, 0x0e), (0x0e, 0x0f), (0x0c, 0x08), (0x0c, 0x09),
    (0x0d, 0x0d), (0x0d, 0x0c), (0x0f, 0x0b), (0x0f, 0x0a), (0x09, 0x07), (0x09, 0x06), (0x0b, 0x01), (0x0b, 0x00),
    (0x09, 0x0d), (0x09, 0x0c), (0x0b, 0x0b), (0x0b, 0x0a), (0x0d, 0x07), (0x0d, 0x06), (0x0f, 0x01), (0x0f, 0x00),
    (0x03, 0x05), (0x03, 0x04), (0x01, 0x03), (0x01, 0x02), (0x07, 0x0f), (0x07, 0x0e), (0x05, 0x09), (0x05, 0x08),
    (0x07, 0x05), (0x07, 0x04), (0x05, 0x03), (0x05, 0x02), (0x03, 0x0f), (0x03, 0x0e), (0x01, 0x09), (0x01, 0x08),
    (0x00, 0x0c), (0x00, 0x0d), (0x02, 0x0a), (0x02, 0x0b), (0x04, 0x06), (0x04, 0x07), (0x06, 0x00), (0x06, 0x01),
    (0x04, 0x0c), (0x04, 0x0d), (0x06, 0x0a), (0x06, 0x0b), (0x00, 0x06), (0x00, 0x07), (0x02, 0x00), (0x02, 0x01),
    (0x0d, 0x05), (0x0d, 0x04), (0x0f, 0x03), (0x0f, 0x02), (0x09, 0x0f), (0x09, 0x0e), (0x0b, 0x09), (0x0b, 0x08),
    (0x09, 0x05), (0x09, 0x04), (0x0b, 0x03), (0x0b, 0x02), (0x0d, 0x0f), (0x0d, 0x0e), (0x0f, 0x09), (0x0f, 0x08),
    (0x0e, 0x0c), (0x0e, 0x0d), (0x0c, 0x0a), (0x0c, 0x0b), (0x0a, 0x06), (0x0a, 0x07), (0x08, 0x00), (0x08, 0x01),
    (0x0a, 0x0c), (0x0a, 0x0d), (0x08, 0x0a), (0x08, 0x0b), (0x0e, 0x06), (0x0e, 0x07), (0x0c, 0x00), (0x0c, 0x01),
    (0x00, 0x04), (0x00, 0x05), (0x02, 0x02), (0x02, 0x03), (0x04, 0x0e), (0x04, 0x0f), (0x06, 0x08), (0x06, 0x09),
    (0x04, 0x04), (0x04, 0x05), (0x06, 0x02), (0x06, 0x03), (0x00, 0x0e), (0x00, 0x0f), (0x02, 0x08), (0x02, 0x09),
    (0x03, 0x0d), (0x03, 0x0c), (0x01, 0x0b), (0x01, 0x0a), (0x07, 0x07), (0x07, 0x06), (0x05, 0x01), (0x05, 0x00),
    (0x07, 0x0d), (0x07, 0x0c), (0x05, 0x0b), (0x05, 0x0a), (0x03, 0x07), (0x03, 0x06), (0x01, 0x01), (0x01, 0x00),
];

#[rustfmt::skip]
const INV_WOL_TABLE: [[u8; 16]; 16] = [
    [ 0x00, 0x01, 0x5c, 0x5d, 0xe0, 0xe1, 0xbc, 0xbd, 0x50, 0x51, 0x0c, 0x0d, 0xb0, 0xb1, 0xec, 0xed, ], 
    [ 0xff, 0xfe, 0xa3, 0xa2, 0x1f, 0x1e, 0x43, 0x42, 0xaf, 0xae, 0xf3, 0xf2, 0x4f, 0x4e, 0x13, 0x12, ], 
    [ 0xbe, 0xbf, 0xe2, 0xe3, 0x5e, 0x5f, 0x02, 0x03, 0xee, 0xef, 0xb2, 0xb3, 0x0e, 0x0f, 0x52, 0x53, ], 
    [ 0x41, 0x40, 0x1d, 0x1c, 0xa1, 0xa0, 0xfd, 0xfc, 0x11, 0x10, 0x4d, 0x4c, 0xf1, 0xf0, 0xad, 0xac, ], 
    [ 0x08, 0x09, 0x54, 0x55, 0xe8, 0xe9, 0xb4, 0xb5, 0x58, 0x59, 0x04, 0x05, 0xb8, 0xb9, 0xe4, 0xe5, ], 
    [ 0xf7, 0xf6, 0xab, 0xaa, 0x17, 0x16, 0x4b, 0x4a, 0xa7, 0xa6, 0xfb, 0xfa, 0x47, 0x46, 0x1b, 0x1a, ], 
    [ 0xb6, 0xb7, 0xea, 0xeb, 0x56, 0x57, 0x0a, 0x0b, 0xe6, 0xe7, 0xba, 0xbb, 0x06, 0x07, 0x5a, 0x5b, ], 
    [ 0x49, 0x48, 0x15, 0x14, 0xa9, 0xa8, 0xf5, 0xf4, 0x19, 0x18, 0x45, 0x44, 0xf9, 0xf8, 0xa5, 0xa4, ], 
    [ 0xd6, 0xd7, 0x8a, 0x8b, 0x36, 0x37, 0x6a, 0x6b, 0x86, 0x87, 0xda, 0xdb, 0x66, 0x67, 0x3a, 0x3b, ], 
    [ 0x29, 0x28, 0x75, 0x74, 0xc9, 0xc8, 0x95, 0x94, 0x79, 0x78, 0x25, 0x24, 0x99, 0x98, 0xc5, 0xc4, ], 
    [ 0x68, 0x69, 0x34, 0x35, 0x88, 0x89, 0xd4, 0xd5, 0x38, 0x39, 0x64, 0x65, 0xd8, 0xd9, 0x84, 0x85, ], 
    [ 0x97, 0x96, 0xcb, 0xca, 0x77, 0x76, 0x2b, 0x2a, 0xc7, 0xc6, 0x9b, 0x9a, 0x27, 0x26, 0x7b, 0x7a, ], 
    [ 0xde, 0xdf, 0x82, 0x83, 0x3e, 0x3f, 0x62, 0x63, 0x8e, 0x8f, 0xd2, 0xd3, 0x6e, 0x6f, 0x32, 0x33, ], 
    [ 0x21, 0x20, 0x7d, 0x7c, 0xc1, 0xc0, 0x9d, 0x9c, 0x71, 0x70, 0x2d, 0x2c, 0x91, 0x90, 0xcd, 0xcc, ], 
    [ 0x60, 0x61, 0x3c, 0x3d, 0x80, 0x81, 0xdc, 0xdd, 0x30, 0x31, 0x6c, 0x6d, 0xd0, 0xd1, 0x8c, 0x8d, ], 
    [ 0x9f, 0x9e, 0xc3, 0xc2, 0x7f, 0x7e, 0x23, 0x22, 0xcf, 0xce, 0x93, 0x92, 0x2f, 0x2e, 0x73, 0x72, ],
];

/// Maps an element of `GF(2^8)` to `GF(2^4)^2` using the WOL transform.
pub fn wol_map(a: &GF8) -> (GF4, GF4) {
    let (ah, al) = WOL_TABLE[a.0 as usize];
    (GF4::new_unchecked(ah), GF4::new_unchecked(al))
}

/// Maps an element `GF(2^4)^2` to of `GF(2^8)` using the inverse WOL transform.
pub fn wol_inv_map(ah: &GF4, al: &GF4) -> GF8 {
    GF8(INV_WOL_TABLE[ah.as_u8() as usize][al.as_u8() as usize])
}

#[cfg(test)]
mod test {
    use crate::share::{
        gf8::GF8,
        wol::{wol_inv_map, wol_map},
    };

    #[test]
    fn test_is_bijective() {
        for x in 0..=255 {
            let a = GF8(x);
            let (ah, al) = wol_map(&a);
            assert_eq!(wol_inv_map(&ah, &al), a, "Should be the identity map")
        }
    }
}
