use rand_chacha::ChaCha20Rng;

use crate::network::task::IoLayer;

use super::correlated_randomness::SharedRng;

pub struct ThreadParty<'a> {
    /// Party index 0, 1 or 2
    i: usize,
    range_start: usize,
    /// exclusive
    range_end: usize,
    random_next: SharedRng,
    random_prev: SharedRng,
    random_local: ChaCha20Rng,
    io_layer: &'a IoLayer
}

impl<'a> ThreadParty<'a> {
    pub fn new(i: usize, range_start: usize, range_end: usize, random_next: SharedRng, random_prev: SharedRng, random_local: ChaCha20Rng, io_layer: &'a IoLayer) -> Self {
        Self { i, range_start, range_end, random_next, random_prev, random_local, io_layer }
    }
}