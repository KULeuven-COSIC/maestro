use crate::rep3_core::network::task::{Direction, IoLayerOwned};
use crate::rep3_core::network::CommChannel;
use crate::rep3_core::party::broadcast::{Broadcast, BroadcastContext};
use crate::rep3_core::party::error::{MpcError, MpcResult};
use crate::rep3_core::party::{commitment, MainParty};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const CR_SEC_PARAM: usize = 128 / 8;

/// Randomness source shared between multiple parties setup via a shared, short, random seed to a local RNG
pub struct SharedRng(ChaCha20Rng);

pub struct GlobalRng(ChaCha20Rng);

impl SharedRng {
    pub fn setup_pairwise<LocalRng: Rng + CryptoRng>(
        rng: &mut LocalRng,
        channel: &mut CommChannel,
        my_id: usize,
        to_id: usize,
    ) -> MpcResult<Self> {
        // create random seed part
        let mut seed = [0u8; CR_SEC_PARAM];
        rng.fill_bytes(&mut seed);
        // commit to it
        let commitment = commitment::commit(rng, &seed);
        let mut other_commit = [0u8; commitment::COMMITMENT_SIZE];
        let mut other_seed = [0u8; CR_SEC_PARAM];
        if my_id < to_id {
            // send my commitment first
            channel.write(&commitment)?;
            // then read the other
            channel.read(&mut other_commit)?;
            // send my seed
            channel.write(&seed)?;
            // then read the other seed
            channel.read(&mut other_seed)?;
        } else {
            // first read the other commitment
            channel.read(&mut other_commit)?;
            // then send my commitment
            channel.write(&commitment)?;
            // first read the other seed
            channel.read(&mut other_seed)?;
            // then send my seed
            channel.write(&seed)?;
        }

        // verify the commitment
        if let Ok(()) = commitment::open(&other_commit, &other_seed) {
            // xor seeds
            let mut common_seed = [0u8; 32];
            for i in 0..CR_SEC_PARAM {
                common_seed[i] = seed[i] ^ other_seed[i];
            }

            let seeded_rng = ChaCha20Rng::from_seed(common_seed);
            Ok(Self(seeded_rng))
        } else {
            Err(MpcError::Commitment)
        }
    }

    pub fn setup_all_pairwise_semi_honest<LocalRng: Rng + CryptoRng>(
        rng: &mut LocalRng,
        io: &IoLayerOwned,
    ) -> MpcResult<(Self, Self)> {
        // receive seed from P+1
        let mut seed_next = [0u8; 32];
        let rcv_seed_next = io.receive_slice(Direction::Next, &mut seed_next[0..CR_SEC_PARAM]);

        // create random seed part
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed[0..CR_SEC_PARAM]);
        // send my seed to P-1
        io.send(Direction::Previous, seed[0..CR_SEC_PARAM].to_vec());
        rcv_seed_next.rcv()?;
        io.wait_for_completion();

        Ok((
            Self(ChaCha20Rng::from_seed(seed)),
            Self(ChaCha20Rng::from_seed(seed_next)),
        ))
    }

    pub fn seeded_from(other: &mut Self) -> Self {
        Self(ChaCha20Rng::from_rng(&mut other.0).unwrap())
    }
}

impl GlobalRng {
    pub fn setup_global(party: &mut MainParty) -> MpcResult<Self> {
        // create random seed part
        let mut seed = [0u8; CR_SEC_PARAM];
        party.random_local.fill_bytes(&mut seed);
        // commit to it
        let commitment = commitment::commit(&mut party.random_local, &seed);

        let mut next_commit = [0u8; commitment::COMMITMENT_SIZE];
        let mut prev_commit = [0u8; commitment::COMMITMENT_SIZE];

        let mut context = BroadcastContext::new();

        party
            .broadcast_round_bytes(
                &mut context,
                &mut next_commit,
                &mut prev_commit,
                &commitment,
            )
            .unwrap();

        let mut next_seed = [0u8; CR_SEC_PARAM];
        let mut prev_seed = [0u8; CR_SEC_PARAM];
        party
            .broadcast_round_bytes(&mut context, &mut next_seed, &mut prev_seed, &seed)
            .unwrap();

        // verify broadcast
        if let Ok(()) = party.compare_view(context) {
            // verify the commitments
            if let (Ok(()), Ok(())) = (
                commitment::open(&next_commit, &next_seed),
                commitment::open(&prev_commit, &prev_seed),
            ) {
                // xor seeds
                let mut common_seed = [0u8; 32];
                for i in 0..CR_SEC_PARAM {
                    common_seed[i] = seed[i] ^ next_seed[i] ^ prev_seed[i];
                }
                Ok(Self(ChaCha20Rng::from_seed(common_seed)))
            } else {
                Err(MpcError::Commitment)
            }
        } else {
            Err(MpcError::Broadcast)
        }
    }
}

impl AsMut<ChaCha20Rng> for SharedRng {
    fn as_mut(&mut self) -> &mut ChaCha20Rng {
        &mut self.0
    }
}

impl AsMut<ChaCha20Rng> for GlobalRng {
    fn as_mut(&mut self) -> &mut ChaCha20Rng {
        &mut self.0
    }
}

#[cfg(test)]
mod test {
    use crate::rep3_core::party::correlated_randomness::GlobalRng;
    use crate::rep3_core::party::test_export::simple_localhost_setup;
    use rand::RngCore;

    #[test]
    fn setup_global() {
        let ((mut rng1, mut rng2, mut rng3), _) =
            simple_localhost_setup(|p| GlobalRng::setup_global(p).unwrap());

        let mut buf1 = [0u8; 100];
        let mut buf2 = [0u8; 100];
        let mut buf3 = [0u8; 100];

        rng1.as_mut().fill_bytes(&mut buf1);
        rng2.as_mut().fill_bytes(&mut buf2);
        rng3.as_mut().fill_bytes(&mut buf3);

        assert_eq!(&buf1, &buf2);
        assert_eq!(&buf2, &buf3);
    }
}
