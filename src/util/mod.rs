use crate::rep3_core::{network::task::IoLayerOwned, party::error::MpcResult, share::{RssShare, RssShareVec}};

use crate::share::Field;

pub(crate) mod un_bitslice;
#[macro_use]
pub(crate) mod mul_triple_vec;

pub trait ArithmeticBlackBox<F: Field> {
    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()>;
    fn generate_random(&mut self, n: usize) -> RssShareVec<F>;
    /// returns alpha_i s.t. alpha_1 + alpha_2 + alpha_3 = 0
    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=F>;
    fn io(&self) -> &IoLayerOwned;

    fn input_round(
        &mut self,
        my_input: &[F],
    ) -> MpcResult<(RssShareVec<F>, RssShareVec<F>, RssShareVec<F>)>;
    fn constant(&self, value: F) -> RssShare<F>;
    fn mul(
        &mut self,
        ci: &mut [F],
        cii: &mut [F],
        ai: &[F],
        aii: &[F],
        bi: &[F],
        bii: &[F],
    ) -> MpcResult<()>;
    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>>;
    fn output_to(&mut self, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>>;
    fn finalize(&mut self) -> MpcResult<()>;
}