use std::{io, slice};

use itertools::{repeat_n, Itertools};

use crate::{aes::{self, AesKeyState, ComputeInverse, ComputePhase, ImplVariant, MPCProtocol, OutputPhase, VectorAesState}, chida::ChidaParty, party::error::{MpcError, MpcResult}, share::{field::GF8, Field, RssShare}};

use self::gf128::{GF128, TryFromGF128SliceError};
pub mod gf128;



fn ghash_key_and_aes_gcm_cnt<Protocol: MPCProtocol + ComputePhase<GF8> + ComputeInverse<GF8>>(party: &mut Protocol, iv: &[u8], n_blocks: usize, aes_keyschedule: &Vec<AesKeyState>) -> MpcResult<Vec<RssShare<GF8>>> {
    assert_eq!(iv.len(), 12, "The only supported IV length is 96 bits");
    let mut counter_input = Vec::with_capacity(32 + 16*n_blocks); // the first block computes the GHASH key H, the second block computes the GHASH output mask

    // first block all 0
    let zero = party.constant(GF8(0));
    counter_input.extend(repeat_n(zero, 16));
    
    let iv = iv.iter().map(|iv_byte| party.constant(GF8(*iv_byte))).collect_vec();

    // n_blocks+1 : IV || cnt     where cnt = 1...n_nblocks+1
    for cnt in 1..=((n_blocks+1) as u32) {
        counter_input.extend_from_slice(&iv);
        let cnt_bytes = cnt.to_be_bytes();
        for cnt_byte in cnt_bytes {
            counter_input.push(party.constant(GF8(cnt_byte)));
        }
    }
    debug_assert_eq!(counter_input.len(), 32 + 16 * n_blocks);
    let counter_input = VectorAesState::from_bytes(counter_input);
    let output_state = aes::aes128_no_keyschedule(party, counter_input, aes_keyschedule, ImplVariant::Simple)?;
    Ok(output_state.to_bytes())
}

fn into_gf128(bytes: Vec<RssShare<GF8>>) -> Result<RssShare<GF128>, TryFromGF128SliceError> {
    debug_assert_eq!(16, bytes.len());
    let (si, sii): (Vec<_>, Vec<_>) = bytes.into_iter().map(|share| (share.si, share.sii)).unzip();
    let si = GF128::try_from(si.as_slice())?;
    let sii = GF128::try_from(sii.as_slice())?;
    Ok(RssShare::from(si, sii))
}

fn from_gf128(e: RssShare<GF128>) -> Vec<RssShare<GF8>> {
    e.si.into_gf8().into_iter().zip(e.sii.into_gf8())
        .map(|(si,sii)| RssShare::from(si, sii))
        .collect()
}

fn ghash<'a, Protocol: MPCProtocol + ComputePhase<GF128>>(party: &mut Protocol, ghash_key: Vec<RssShare<GF8>>, associated_data: &[u8], ciphertext: impl ExactSizeIterator<Item=&'a RssShare<GF8>>) -> MpcResult<Vec<RssShare<GF8>>> {
    let mut ghash_state = party.constant(GF128::zero());
    let ghash_key = into_gf128(ghash_key).unwrap();
    fn ghash_part<T,F, Protocol: MPCProtocol + ComputePhase<GF128>>(party: &mut Protocol, ghash_key: &RssShare<GF128>, ghash_state: &mut RssShare<GF128>, part: impl Iterator<Item = T>, mut map: F) -> MpcResult<()>
    where F: FnMut(&mut Protocol,T)->RssShare<GF8>
     {
        for block in part.chunks(16).into_iter() {
            let mut block_bytes = block.map(|t| map(party, t)).collect_vec();
            if block_bytes.len() != 16 {
                block_bytes.resize(16, party.constant(GF8(0)))
            };
            *ghash_state += into_gf128(block_bytes).unwrap();
            let ghash_state_clone = ghash_state.clone();
            party.mul(slice::from_mut(&mut ghash_state.si), slice::from_mut(&mut ghash_state.sii), slice::from_ref(&ghash_key.si), slice::from_ref(&ghash_key.sii), slice::from_ref(&ghash_state_clone.si), slice::from_ref(&ghash_state_clone.sii))?;
        }
        Ok(())
    }

    let ad_len = 8 * associated_data.len() as u64;
    ghash_part(party, &ghash_key, &mut ghash_state, associated_data.iter(), |p,ad| p.constant(GF8(*ad)))?;
    let ct_len = 8 * ciphertext.len() as u64;

    ghash_part(party, &ghash_key, &mut ghash_state, ciphertext, |_,ct| *ct)?;
    let mut last_block = [0u8; 16];
    for (i,b) in ad_len.to_be_bytes().into_iter().enumerate() {
        last_block[i] = b;
    }
    for (i,b) in ct_len.to_be_bytes().into_iter().enumerate() {
        last_block[8+i] = b;
    }
    ghash_state += party.constant(last_block.as_slice().try_into().unwrap());
    let ghash_state_clone = ghash_state.clone();
    party.mul(slice::from_mut(&mut ghash_state.si), slice::from_mut(&mut ghash_state.sii), &[ghash_key.si], &[ghash_key.sii], &[ghash_state_clone.si], &[ghash_state_clone.sii])?;
    Ok(from_gf128(ghash_state))
}

pub fn semi_honest_tag_check(party: &mut ChidaParty, expected_tag: &[u8], computed_tag: &[RssShare<GF8>]) -> MpcResult<bool> {
    if expected_tag.len() != 16 || computed_tag.len() != 16 { 
        return Err(MpcError::InvalidParameters("Invalid tag length".to_string())); 
    }
    // check the tag by multiplying with a random GF128 element and opening the result
    let rand = party.generate_random(1);
    let check_zero = party.constant(GF128::try_from(expected_tag).unwrap()) - into_gf128(computed_tag.to_vec()).unwrap();
    let mut to_open = RssShare::from(GF128::default(), GF128::default());
    party.mul(slice::from_mut(&mut to_open.si), slice::from_mut(&mut to_open.sii), slice::from_ref(&rand[0].si), slice::from_ref(&rand[0].sii), slice::from_ref(&check_zero.si), slice::from_ref(&check_zero.sii))?;
    let output = party.output_round( slice::from_ref(&to_open.si), slice::from_ref(&to_open.sii))?;
    if output.len() == 1 {
        Ok(output[0].is_zero())
    }else{
        Err(MpcError::IoError(io::Error::new(io::ErrorKind::InvalidData, "Only expected one value to open")))
    }
}

pub fn get_required_mult_for_aes128_gcm(ad_len: usize, m_len: usize) -> (usize, usize) {
    let mul_gf8_ks = aes::get_required_mult_for_keyschedule(ImplVariant::Simple, 1);
    let m_blocks = if m_len % 16 == 0 { m_len/16} else {m_len/16+1};
    let ghash_cnt_gf8 = aes::get_required_mult_for_aes128_no_keyschedule(ImplVariant::Simple, m_blocks+2);
    let ad_blocks = if ad_len % 16 == 0 { ad_len/16 + 1 } else { ad_len/16 + 2 };
    let ghash_gf128 = m_blocks+ad_blocks;
    (mul_gf8_ks+ghash_cnt_gf8, ghash_gf128)
}

pub fn aes128_gcm_encrypt<Protocol: MPCProtocol + ComputePhase<GF8> + ComputeInverse<GF8> + ComputePhase<GF128>>(party: &mut Protocol, iv: &[u8], key: &[RssShare<GF8>], message: &[RssShare<GF8>], associated_data: &[u8]) -> MpcResult<(Vec<RssShare<GF8>>, Vec<RssShare<GF8>>)> {
    // check IV length, key length and message lengths
    if key.len() != 16 { return Err(MpcError::InvalidParameters("Invalid key length, expected 128 bit (16 byte) for AES-GCM-128".to_string())); }
    if iv.len() != 12 { return Err(MpcError::InvalidParameters("Invalid IV length. Supported IV length is 96 bit (12 byte)".to_string())); }
    if (message.len() as u64) >= ((1u64 << 36)-32) { return Err(MpcError::InvalidParameters("Message too large. Maximum message length is < 2^36-32 bytes".to_string())); }
    if (associated_data.len() as u64) >= (1u64 << 61 -1) { return Err(MpcError::InvalidParameters("Associated data too large. Maximum length is < 2^61 - 1 bytes".to_string())); }

    // compute key schedule
    let ks = aes::aes128_keyschedule(party, key.to_vec(), ImplVariant::Simple)?; // Simple works for both Chida and Furukawa
    let n_message_blocks = 
        if message.len() % 16 != 0 {
            message.len() / 16 + 1
        }else {
            message.len() / 16
        };
    let counter_output = ghash_key_and_aes_gcm_cnt(party, iv, n_message_blocks, &ks)?;
    let mut ghash_key = Vec::with_capacity(16);
    ghash_key.extend_from_slice(&counter_output[..16]);
    let mut ghash_mask = Vec::with_capacity(16);
    ghash_mask.extend_from_slice(&counter_output[16..32]);
    let ciphertext: Vec<_> = counter_output.into_iter().skip(32).zip(message) // zip will stop when the (incomplete) last block ends
        .map(|(s,m)| s + *m)
        .collect();
    let mut tag = ghash(party, ghash_key, associated_data, ciphertext.iter())?;
    // compute tag
    for i in 0..16 {
        tag[i] += ghash_mask[i];
    }
    Ok((tag, ciphertext))
}

pub fn aes128_gcm_decrypt<F, Protocol: MPCProtocol + ComputePhase<GF8> + ComputeInverse<GF8> + ComputePhase<GF128>>(party: &mut Protocol, nonce: &[u8], key: &[RssShare<GF8>], ciphertext: &[u8], tag: &[u8], associated_data: &[u8], tag_check: F) -> MpcResult<Vec<RssShare<GF8>>> 
where F: FnOnce(&mut Protocol, &[u8], &[RssShare<GF8>]) -> MpcResult<bool>
{
    // check key length
    if key.len() != 16 { return Err(MpcError::InvalidParameters("Invalid key length, expected 128 bit (16 byte) for AES-GCM-128".to_string())); }
    // compute key schedule
    let ks = aes::aes128_keyschedule(party, key.to_vec(), ImplVariant::Simple)?; // Simple works for both Chida and Furukawa
    aes128_gcm_decrypt_with_ks(party, nonce, &ks, ciphertext, tag, associated_data, tag_check) 
}

fn aes128_gcm_decrypt_with_ks<F, Protocol: MPCProtocol + ComputePhase<GF8> + ComputeInverse<GF8> + ComputePhase<GF128>>(party: &mut Protocol, nonce: &[u8], key_schedule: &Vec<AesKeyState>, ciphertext: &[u8], tag: &[u8], associated_data: &[u8], tag_check: F) -> MpcResult<Vec<RssShare<GF8>>>
where F: FnOnce(&mut Protocol, &[u8], &[RssShare<GF8>]) -> MpcResult<bool>
{
    // check nonce length and message lengths
    if nonce.len() != 12 { return Err(MpcError::InvalidParameters("Invalid IV length. Supported IV length is 96 bit (12 byte)".to_string())); }
    if (ciphertext.len() as u64) >= ((1u64 << 36)-32) { return Err(MpcError::InvalidParameters("Ciphertext too large. Maximum ciphertext length is < 2^36-32 bytes".to_string())); }
    if (associated_data.len() as u64) >= (1u64 << 61 -1) { return Err(MpcError::InvalidParameters("Associated data too large. Maximum length is < 2^61 - 1 bytes".to_string())); }
    
    let n_message_blocks = 
        if ciphertext.len() % 16 != 0 {
            ciphertext.len() / 16 + 1
        }else {
            ciphertext.len() / 16
        };
    let counter_output = ghash_key_and_aes_gcm_cnt(party, nonce, n_message_blocks, &key_schedule)?;
    let mut ghash_key = Vec::with_capacity(16);
    ghash_key.extend_from_slice(&counter_output[..16]);
    let mut ghash_mask = Vec::with_capacity(16);
    ghash_mask.extend_from_slice(&counter_output[16..32]);
    let ciphertext = ciphertext.iter().map(|b| party.constant(GF8(*b))).collect_vec();
    let message: Vec<_> = counter_output.into_iter().skip(32).zip(ciphertext.iter()) // zip will stop when the (incomplete) last block ends
        .map(|(s,ct)| s + *ct)
        .collect();
    let mut computed_tag = ghash(party, ghash_key, associated_data, ciphertext.iter())?;
    // compute tag
    for i in 0..16 {
        computed_tag[i] += ghash_mask[i];
    }

    // check computed and given tag
    match tag_check(party, tag, &computed_tag) {
        Ok(true) => Ok(message),
        Ok(false) => Err(MpcError::OperationFailed("Decryption failed".to_string())),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use rand::thread_rng;

    use crate::{aes::MPCProtocol, chida::{self, online::test::ChidaSetup, ChidaParty}, gcm::gf128::GF128, party::{test::{localhost_setup, TestSetup}, Party}, share::{field::GF8, test::{assert_eq_vector, consistent, consistent_vector, secret_share_vector}, RssShare}};

    use super::{aes128_gcm_decrypt, aes128_gcm_encrypt, semi_honest_tag_check};

    struct AesGcm128Testvector {
        key: &'static str,
        nonce: &'static str,
        ad: &'static str,
        message: &'static str,
        ciphertext: &'static str,
        tag: &'static str
    }

    fn get_test_vectors() -> Vec<AesGcm128Testvector> {
        vec![
            AesGcm128Testvector { key: "67c6697351ff4aec29cdbaabf2fbe346", nonce: "7cc254f81be8e78d765a2e63", ad: "33", message: "", ciphertext: "", tag: "60a09cbb8d4ab9aecfd8d7b59ddefb54" },
            AesGcm128Testvector { key: "9fc99a66320db73158a35a255d051758", nonce: "e95ed4abb2cdc69bb454110e", ad: "827441213ddc8770e93ea141e1fc67", message: "", ciphertext: "", tag: "6d06851093b69f6ba0b56178811dff2d" },
            AesGcm128Testvector { key: "3e017e97eadc6b968f385c2aecb03bfb", nonce: "32af3c54ec18db5c021afe43", ad: "fbfaaa3afb29d1e6053c7c9475d8be61", message: "", ciphertext: "", tag: "afa00954b8f3c9d86e68b1ebcdcaa00d" },
            AesGcm128Testvector { key: "89f95cbba8990f95b1ebf1b305eff700", nonce: "e9a13ae5ca0bcbd0484764bd", ad: "1f231ea81c7b64c514735ac55e4b79633b", message: "", ciphertext: "", tag: "462b140701577af223f4e73b1fe5b934" },
            AesGcm128Testvector { key: "706424119e09dcaad4acf21b10af3b33", nonce: "cde3504847155cbb6f2219ba", ad: "9b7df50be11a1c7f23f829f8a41b13b5ca4ee8983238e0794d3d34bc5f4e77", message: "", ciphertext: "", tag: "314cc4b2e7f8218eb53d9c59f2541bee" },
            AesGcm128Testvector { key: "facb6c05ac86212baa1a55a2be70b573", nonce: "3b045cd33694b3afe2f0e49e", ad: "4f321549fd824ea90870d4b28a2954489a0abcd50e18a844ac5bf38e4cd72d9b", message: "", ciphertext: "", tag: "73feaf67d0edbaeb9d026dddd098e6c6" },
            AesGcm128Testvector { key: "0942e506c433afcda3847f2dadd47647", nonce: "de321cec4ac430f62023856c", ad: "fbb20704f4ec0bb920ba86c33e05f1ecd96733b79950a3e314d3d934f75ea0f210", message: "", ciphertext: "", tag: "7cf36d2e1b4339d7f726775f4e3c2b7f" },
            AesGcm128Testvector { key: "a8f6059401beb4bc4478fa4969e623d0", nonce: "1ada696a7e4c7e5125b34884", ad: "", message: "53", ciphertext: "0f", tag: "1c4163e976bc7a5009d67d0b5fdc4178" },
            AesGcm128Testvector { key: "3a94fb319990325744ee9bbce9e525cf", nonce: "08f5e9e25e5360aad2b2d085", ad: "", message: "fa54d835e8d466826498d9a8877565", ciphertext: "c4a3e75bb2e161c86372536221ba9e", tag: "299f402480bfae50cf56b3918ad02b57" },
            AesGcm128Testvector { key: "705a8a3f62802944de7ca5894e5759d3", nonce: "51adac869580ec17e485f18c", ad: "", message: "0c66f17cc07cbb22fce466da610b63af", ciphertext: "5455de87929f5640268900109d39c2aa", tag: "71082455dfd07d8a7ee2e48114797aa1" },
            AesGcm128Testvector { key: "62bc83b4692f3affaf271693ac071fb8", nonce: "6d11342d8def4f89d4b66335", ad: "", message: "c1c7e4248367d8ed9612ec453902d8e50a", ciphertext: "4d1e4013b3be309ea8f4901f1af690563c", tag: "8532a32e20dc74a938ece2528c2fcac9" },
            AesGcm128Testvector { key: "f89d7709d1a596c1f41f95aa82ca6c49", nonce: "ae90cd1668baac7aa6f2b4a8", ad: "", message: "ca99b2c2372acb08cf61c9c3805e6e0328da4cd76a19edd2d3994c798b0022", ciphertext: "044b9a03ddc189449f4fb3d3d43ce9831f4d0e2b692884db5577510e3d4a39", tag: "334476d1bddf95abb00c8e34eaafe759" },
            AesGcm128Testvector { key: "569ad418d1fee4d9cd45a391c601ffc9", nonce: "2ad91501432fee150287617c", ad: "", message: "13629e69fc7281cd7165a63eab49cf714bce3a75a74f76ea7e64ff81eb61fdfe", ciphertext: "8e6e51ce2405faf80de42f6cd06fac4ca881be92a490f54deaec347916d4ac66", tag: "9edde34ef3e43749b39d0fa816e0b849" },
            AesGcm128Testvector { key: "c39b67bf0de98c7e4e32bdf97c8c6ac7", nonce: "5ba43c02f4b2ed7216ecf301", ad: "", message: "4df000108b67cf99505b179f8ed4980a6103d1bca70dbe9bbfab0ed59801d6e5f2", ciphertext: "ab24883cad514002aea36ab260518c098331c50893d625ebcb965eb4832f549b1a", tag: "6e7a9096669dc78854822596e4656ded" },
            AesGcm128Testvector { key: "d6f67d3ec5168e212e2daf02c6b963c9", nonce: "8a1f7097de0c56891a2b211b", ad: "", message: "", ciphertext: "", tag: "3dd8898125f3e4c151307a88f25c161c" },
            AesGcm128Testvector { key: "01070dd8fd8b16c2a1a4e3cfd292d298", nonce: "4b3561d555d16c33ddc2bcf7", ad: "ed", message: "de", ciphertext: "58", tag: "40aad058bfb61a9216f2b3655a8338ad" },
            AesGcm128Testvector { key: "13efe520c7e2abdda44d81881c531aee", nonce: "eb66244c3b791ea8acfb6a68", ad: "f3584606472b260e0dd2ebb21f6c3a", message: "3bc0542aabba4ef8f6c7169e731108", ciphertext: "b9aa6469c619e1aa88ed0b25020113", tag: "891a65175fbbcbb6f1643ab7dc0c8a7b" },
            AesGcm128Testvector { key: "db0460220aa74d31b55b03a00d220d47", nonce: "5dcd9b877856d5704c9c86ea", ad: "0f98f2eb9c530da7fa5ad8b0b5db50c2fd", message: "5d", ciphertext: "08", tag: "f5f0a775a7aec9acd4ca0dbdcb0b455b" },
            AesGcm128Testvector { key: "095a2aa5e2a3fbb71347549a31633223", nonce: "4ece765b7571b64d216b2871", ad: "2e25cf3780f9dc629cd719b01e6d4a4fd1", message: "7c731f4ae97bc05a310d7b9c36edca5bbc02dbb5de3d52b65702d4c44c2495", ciphertext: "7d1ec648639b19eb371800cb4723481eaf62d6e3b2b84e673ebcc8f2aec575", tag: "8fb84cb2bb4d70c15a89db657e748b5f" },
            AesGcm128Testvector { key: "c897b5128030d2db61e056fd1643c871", nonce: "ffca4db5a88a075ee10933a6", ad: "55573b1deef02f6e20024981e2a07ff8e34769e311b698b9419f1822a84bc8fd", message: "a2041a90f449fe154b48962de81525cb5c8fae6d45462786e53fa98d8a718a2c", ciphertext: "3ac4e3e5e673fefde9f666e3b4c10f8763efe743520d02faf3c8cebe4a4adb77", tag: "d03e2b46889ddea2236b97cfb99bfcab" },
            AesGcm128Testvector { key: "75a4bc6aeeba7f39021567ea2b8cb687", nonce: "1b64f561ab1ce7905b901ee5", ad: "02a811774dcde13b8760748a76db74a1682a28838f1de43a39ccca945ce8795e918ad6de57b719df", message: "188d698e69dd2fd1085754977539d1ae059b4361", ciphertext: "498dbaee28d1fe08eb893027043cabc2680ccb45", tag: "fbbf997f34f293605e440ebf6401f9ab" },
        ]
    }

    fn test_aes_gcm_128_encrypt(keys: &[u8], iv: &[u8], plaintext: &[u8], ad: &[u8], expected_ciphertext: &[u8], expected_tag: &[u8]) {
        let mut rng = thread_rng();
        let (k1,k2,k3) = secret_share_vector(&mut rng, keys.iter().map(|x| GF8(*x)));
        let (pt1, pt2, pt3) = secret_share_vector(&mut rng, plaintext.iter().map(|x| GF8(*x)));

        let program = |key: Vec<RssShare<GF8>>, pt: Vec<RssShare<GF8>>, iv: &[u8], ad: &[u8]| {
            let iv = iv.iter().cloned().collect_vec();
            let ad = ad.iter().cloned().collect_vec();
            move |p: &mut ChidaParty| {
                let (tag, ct) = aes128_gcm_encrypt(p, &iv, &key, &pt, &ad).unwrap();
                (tag, ct)
            }
        };

        let (r1, r2, r3) = ChidaSetup::localhost_setup(program(k1, pt1, iv, ad), program(k2, pt2, iv, ad), program(k3, pt3, iv, ad));
        let ((tag1, ct1), _) = r1.join().unwrap();
        let ((tag2, ct2), _) = r2.join().unwrap();
        let ((tag3, ct3), _) = r3.join().unwrap();

        consistent_vector(&tag1, &tag2, &tag3);
        consistent_vector(&ct1, &ct2, &ct3);
        let expected_ciphertext = expected_ciphertext.iter().map(|x| GF8(*x)).collect_vec();
        let expected_tag = expected_tag.iter().map(|x| GF8(*x)).collect_vec();
        assert_eq_vector(ct1, ct2, ct3, expected_ciphertext);
        assert_eq_vector(tag1, tag2, tag3, expected_tag);
    }

    fn test_aes_gcm_128_decrypt(keys: &[u8], iv: &[u8], expected_plaintext: &[u8], ad: &[u8], ciphertext: &[u8], tag: &[u8]) {
        let mut rng = thread_rng();
        let (k1,k2,k3) = secret_share_vector(&mut rng, keys.iter().map(|x| GF8(*x)));
        // let (ct1, ct2, ct3) = secret_share_vector(&mut rng, ciphertext.iter().map(|x| GF8(*x)));

        let program = |key: Vec<RssShare<GF8>>, ct: &[u8], tag: &[u8], iv: &[u8], ad: &[u8]| {
            let iv = iv.iter().cloned().collect_vec();
            let ad = ad.iter().cloned().collect_vec();
            let ct = ct.iter().cloned().collect_vec();
            let tag = tag.iter().cloned().collect_vec();
            move |p: &mut ChidaParty| {
                aes128_gcm_decrypt(p, &iv, &key, &ct, &tag, &ad, semi_honest_tag_check).unwrap()
            }
        };

        let (r1, r2, r3) = ChidaSetup::localhost_setup(program(k1, ciphertext, tag, iv, ad), program(k2, ciphertext, tag, iv, ad), program(k3, ciphertext, tag, iv, ad));
        let (m1, _) = r1.join().unwrap();
        let (m2, _) = r2.join().unwrap();
        let (m3, _) = r3.join().unwrap();

        consistent_vector(&m1, &m2, &m3);
        let expected_message = expected_plaintext.iter().map(|x| GF8(*x)).collect_vec();
        assert_eq_vector(m1, m2, m3, expected_message);
    }

    #[test]
    fn aes_gcm_128_encrypt_testvectors() {
        let tv = get_test_vectors();
        for tvi in tv {
            let key = hex::decode(tvi.key).unwrap();
            let nonce = hex::decode(tvi.nonce).unwrap();
            let ad = hex::decode(tvi.ad).unwrap();
            let msg = hex::decode(tvi.message).unwrap();
            let ct = hex::decode(tvi.ciphertext).unwrap();
            let tag = hex::decode(tvi.tag).unwrap();
            test_aes_gcm_128_encrypt(&key, &nonce, &msg, &ad, &ct, &tag);
        }
    }

    #[test]
    fn aes_gcm_128_decrypt_testvectors() {
        let tv = get_test_vectors();
        for tvi in tv {
            let key = hex::decode(tvi.key).unwrap();
            let nonce = hex::decode(tvi.nonce).unwrap();
            let ad = hex::decode(tvi.ad).unwrap();
            let msg = hex::decode(tvi.message).unwrap();
            let ct = hex::decode(tvi.ciphertext).unwrap();
            let tag = hex::decode(tvi.tag).unwrap();
            test_aes_gcm_128_decrypt(&key, &nonce, &msg, &ad, &ct, &tag);
        }
    }

    #[test]
    fn consistent_random_gf128() {
        const N: usize = 100;
        let program = |p: &mut ChidaParty| {
            p.generate_random::<GF128>(N)
        };
        let (h1,h2,h3) = ChidaSetup::localhost_setup(program, program, program);
        let (r1, _) = h1.join().unwrap();
        let (r2, _) = h2.join().unwrap();
        let (r3, _) = h3.join().unwrap();

        for (r1, (r2, r3)) in r1.into_iter().zip(r2.into_iter().zip(r3)) {
            consistent(&r1, &r2, &r3);
        }
    }

    #[test]
    fn test_semi_honest_tag_check() {
        let tag = hex::decode("01070dd8fd8b16c2a1a4e3cfd292d298").unwrap();
        let tag2 = hex::decode("01070dd8fd8b16c2a1a4e3cfd292d297").unwrap();
        let tag3 = hex::decode("11070dd8fd8b16c2a1a4e3cfd292d298").unwrap();

        let mut rng = thread_rng();
        let tag1 = secret_share_vector(&mut rng, tag.iter().map(|b| GF8(*b)));
        let tag2 = secret_share_vector(&mut rng, tag2.iter().map(|b| GF8(*b)));
        let tag3 = secret_share_vector(&mut rng, tag3.iter().map(|b| GF8(*b)));

        let program = |expected: &[u8], tag1: Vec<RssShare<GF8>>, tag2: Vec<RssShare<GF8>>, tag3: Vec<RssShare<GF8>>| {
            let expected = expected.iter().cloned().collect_vec();
            move |party: &mut ChidaParty| {
                assert_eq!(semi_honest_tag_check(party, &expected, &tag1).unwrap(), true);
                assert_eq!(semi_honest_tag_check(party, &expected, &tag2).unwrap(), false);
                assert_eq!(semi_honest_tag_check(party, &expected, &tag3).unwrap(), false);
            }
        };

        let (r1, r2, r3) = ChidaSetup::localhost_setup(program(&tag, tag1.0, tag2.0, tag3.0), program(&tag, tag1.1, tag2.1, tag3.1), program(&tag, tag1.2, tag2.2, tag3.2));
        r1.join().unwrap();
        r2.join().unwrap();
        r3.join().unwrap();
    }

    #[test]
    fn output_gf128_to_all() {
        let mut rng = thread_rng();
        let o: Vec<GF128> = vec![GF128::try_from(hex::decode("01070dd8fd8b16c2a1a4e3cfd292d298").unwrap().as_slice()).unwrap()];

        let o_share = secret_share_vector(&mut rng, o.iter().cloned());

        let program = |a: Vec<RssShare<GF128>>| {
            move |p: &mut Party| {
                chida::online::output_round(p, &a, &a, &a).unwrap()
            }
        };

        let (h1, h2, h3) = localhost_setup(program(o_share.0), program(o_share.1), program(o_share.2));
        let (s1, _) = h1.join().unwrap();
        let (s2, _) = h2.join().unwrap();
        let (s3, _) = h3.join().unwrap();
        assert_eq!(o, s1);
        assert_eq!(o, s2);
        assert_eq!(o, s3);
    }
}