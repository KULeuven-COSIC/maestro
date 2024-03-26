//! This module implements the semi-honest oblivious AES protocol "WOL LUT 16".
//!
//!

use crate::party::Party;

mod online;
mod offline;

// Party for WOLLUT16
pub struct WL16Party(Party);

// a random one-hot vector of size 16
#[derive(PartialEq,Debug)]
struct RndOhv16(u16);

impl WL16Party {}

pub fn wollut16_benchmark() {}
