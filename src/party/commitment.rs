use rand::{CryptoRng, Rng};
use sha2::{Sha256, Digest};
use crate::party::error::{MpcError, MpcResult};

const COMMITMENT_SEC_PARAM: usize = 128 / 8;
const SHA256_OUTPUT_SIZE: usize = 256 / 8;

pub const COMMITMENT_SIZE: usize = COMMITMENT_SEC_PARAM + SHA256_OUTPUT_SIZE;

pub fn commit<Random: Rng + CryptoRng>(rand: &mut Random, msg: &[u8]) -> Vec<u8> {
    let mut commitment = [0u8; COMMITMENT_SIZE];
    rand.fill_bytes(&mut commitment[..COMMITMENT_SEC_PARAM]);
    let mut hasher = Sha256::new();
    hasher.update(&commitment[..COMMITMENT_SEC_PARAM]);
    hasher.update(msg);

    let hash = hasher.finalize();
    commitment[COMMITMENT_SEC_PARAM..].copy_from_slice(&hash);
    return Vec::from(commitment);
}

pub fn open(commitment: &[u8], msg: &[u8]) -> MpcResult<()> {
    let mut hasher = Sha256::new();
    hasher.update(&commitment[..COMMITMENT_SEC_PARAM]);
    hasher.update(msg);
    let hash = hasher.finalize();

    for i in 0..SHA256_OUTPUT_SIZE {
        if commitment[COMMITMENT_SEC_PARAM + i] != hash[i] {
            return Err(MpcError::CommitmentError);
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use rand::thread_rng;
    use crate::party::commitment::{commit, open};
    use crate::party::error::MpcError;

    #[test]
    fn correctness() {
        let mut rng = thread_rng();
        let message = "This is a message I commit to.".as_bytes();
        for _ in 0..10 {
            let commitment = commit(&mut rng, &message);
            open(&commitment, &message).unwrap()
        }
    }

    #[test]
    fn soundness() {
        let mut rng = thread_rng();
        let mut message = "This is a message I commit to.".as_bytes().to_vec();

        let mut commitment = commit(&mut rng, &message);

        // try open different message
        message[5] ^= 0x4;
        if let Err(MpcError::CommitmentError) = open(&commitment, &message) {
            // ok
        }else{
            panic!()
        }

        message[5] ^= 0x4;
        // try different commitment
        commitment[3] ^= 0x80;
        if let Err(MpcError::CommitmentError) = open(&commitment, &message) {
            // ok
        }else{
            panic!()
        }
    }
}