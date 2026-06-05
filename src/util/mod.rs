use std::ops::Add;

use crate::rep3_core::{network::{NetSerializable, task::IoLayerOwned}, party::{DigestExt, MainParty, broadcast::{Broadcast, BroadcastContext}, error::MpcResult}, share::{RssShare, RssShareVec}};

use crate::share::Field;

pub(crate) mod un_bitslice;
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
    fn finalize(&mut self) -> MpcResult<()>;
}

/// Opens the replicated share vector (si, sii) to all parties and runs compare-view to verify all broadcasts so far made in the given context.
/// This check replaces the [BroadcastContext] with a fresh (empty) one.
/// Outputs the reconstructed vector, or errors.
pub(crate) fn output_rss_and_compare_view<F>(party: &mut MainParty, context: &mut BroadcastContext, si: &[F], sii: &[F]) -> MpcResult<Vec<F>>
where F : NetSerializable + Add<Output = F> + Clone + DigestExt
{
    let output = party.open_rss(context, si, sii)?;
    let context = std::mem::replace(context, BroadcastContext::new());
    party.compare_view(context)?;
    Ok(output)
}