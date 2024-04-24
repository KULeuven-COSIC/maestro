use crate::{party::error::MpcResult, wollut16::{self, RndOhvOutput}};

use super::WL16ASParty;


pub fn generate_random_ohv16(party: &mut WL16ASParty, n: usize) -> MpcResult<Vec<RndOhvOutput>> {
    wollut16::offline::generate_random_ohv16(&mut party.inner, &mut party.gf2_triples_to_check, n)
}