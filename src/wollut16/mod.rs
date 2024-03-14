//! This module implements the semi-honest oblivious AES protocol "WOL LUT 16".
//!
//!

use crate::party::Party;

mod online;

// Party for WOLLUT16
pub struct WL16Party(Party);

impl WL16Party {}

pub fn wollut16_benchmark() {}
