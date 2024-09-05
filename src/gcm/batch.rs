use std::{io, iter};

use itertools::{izip, repeat_n, Itertools};

use crate::{aes::{self, AesKeyScheduleBatch, AesKeyState, GF8InvBlackBox, VectorAesState}, gcm::{from_gf128, into_gf128}, rep3_core::{party::{self, error::{MpcError, MpcResult}}, share::{HasZero, RssShare}}, share::{gf8::GF8, Field}, util::ArithmeticBlackBox};

use super::{gf128::GF128, Aes128GcmCiphertext};

/// Describes input parameters for encryption.
/// Use in [batch_aes128_gcm_encrypt_with_ks].
#[derive(Clone)]
pub struct EncParam<'a> {
    /// Nonce value, for AES-128-GCM, 12 byte
    pub iv: &'a[u8],
    /// Key schedule for AES-128, 11 round keys of 16 byte each
    pub key_schedule: &'a Vec<AesKeyState>,
    /// Secret-shared message, can be any length
    pub message: &'a[RssShare<GF8>],
    /// Public associated data, can be any length
    pub associated_data: &'a[u8]
}

/// Describes input parameters for decryption.
/// Use in [batch_aes128_gcm_decrypt_with_ks].
#[derive(Clone)]
pub struct DecParam<'a> {
    /// Nonce value, for AES-128-GCM, 12 byte
    pub iv: &'a[u8],
    /// Key schedule for AES-128, 11 round keys of 16 byte each
    pub key_schedule: &'a Vec<AesKeyState>,
    /// Public ciphertext
    pub ciphertext: &'a [u8],
    /// Public tag
    pub tag: &'a [u8],
    /// Public associated data, can be any length
    pub associated_data: &'a[u8],
}

/// Describes input parameters for encryption.
/// Similar to [EncParam] but with ownership.
#[derive(Clone)]
pub struct EncParamOwned {
    /// Nonce value, for AES-128-GCM, 12 byte
    pub iv: Vec<u8>,
    /// Key schedule for AES-128, 11 round keys of 16 byte each
    pub key_schedule: Vec<AesKeyState>,
    /// Secret-shared message, can be any length
    pub message: Vec<RssShare<GF8>>,
    /// Public associated data, can be any length
    pub associated_data: Vec<u8>
}

/// Describes input parameters for decryption.
/// Similar to [DecParam] but with ownership.
#[derive(Clone)]
pub struct DecParamOwned {
    /// Nonce value, for AES-128-GCM, 12 byte
    iv: Vec<u8>,
    /// Key schedule for AES-128, 11 round keys of 16 byte each
    key_schedule: Vec<AesKeyState>,
    /// Public ciphertext
    ciphertext: Vec<u8>,
    /// Public tag
    tag: Vec<u8>,
    /// Public associated data, can be any length
    associated_data: Vec<u8>
}

type GcmParamEnc<'a> = GcmParam<'a, RssShare<GF8>>;
type GcmParamDec<'a> = GcmParam<'a, u8>;

struct GcmParam<'a, T> {
    pub iv: &'a[u8],
    /// message or ciphertext
    pub message: &'a[T],
    /// empty if message
    pub tag: &'a [u8],
    pub associated_data: &'a[u8],
    pub n_blocks: usize,
    pub key_schedule: &'a[AesKeyState],
}

struct BatchedGcmParams<'a, T> {
    pub batch: Vec<GcmParam<'a, T>>,
}

impl<'a, T> BatchedGcmParams<'a, T> {
    /// Returns the total number of AES blocks that are in this batch
    /// Computed as (2+n_blocks_i) x number of items per batch
    pub fn total_block_length(&self) -> usize {
        2*self.batch.len() + self.batch.iter().map(|batch| batch.n_blocks).sum::<usize>()
    }

    pub fn key_schedule(&self) -> AesKeyScheduleBatch<11> {
        // add 2 to each n_blocks since GCM has two extra AES calls
        let n_nblocks = self.batch.iter().map(|batch| batch.n_blocks+2).collect_vec();
        let key_schedules = self.batch.iter().map(|batch| batch.key_schedule).collect_vec();
        AesKeyScheduleBatch::new(&key_schedules, n_nblocks)
    }

    /// Returns the total number of message/ciphertext bytes
    pub fn total_ct_length(&self) -> usize {
        self.batch.iter().map(|b| b.message.len()).sum()
    }
}

/// Encrypts all (nonce, key, associated data, message) pairs specified in `data` in one batch with AES-128-GCM.
/// Returns the corresponding [Aes128GcmCiphertext] in the order of the the input.
/// 
/// This function returns an error if any encryption failed.
pub fn batch_aes128_gcm_encrypt_with_ks<'a, Protocol: ArithmeticBlackBox<GF8> + ArithmeticBlackBox<GF128> + GF8InvBlackBox>(party: &mut Protocol, party_index: usize, data: impl IntoIterator<Item=EncParam<'a>>) -> MpcResult<Vec<Aes128GcmCiphertext>> {
    let param = data.into_iter().map(|data| {
        // check IV length, key_schedule and message lengths
        if data.iv.len() != 12 { return Err(MpcError::InvalidParameters("Invalid IV length. Supported IV length is 96 bit (12 byte)".to_string())); }
        if data.key_schedule.len() != 11 { return Err(MpcError::InvalidParameters("Invalid Key Schedule length. Expected 11 round keys".to_string())); }
        if (data.message.len() as u64) >= ((1u64 << 36)-32) { return Err(MpcError::InvalidParameters("Message too large. Maximum message length is < 2^36-32 bytes".to_string())); }
        if (data.associated_data.len() as u64) >= (1u64 << 61 -1) { return Err(MpcError::InvalidParameters("Associated data too large. Maximum length is < 2^61 - 1 bytes".to_string())); }

        let n_message_blocks = data.message.len().div_ceil(16);
        Ok(GcmParamEnc {
            iv: data.iv,
            associated_data: data.associated_data,
            key_schedule: data.key_schedule,
            message: data.message,
            tag: &[],
            n_blocks: n_message_blocks,
        })
    })
    .collect::<MpcResult<Vec<_>>>()?;
    let param = BatchedGcmParams { batch: param };
    
    let counter_output = batched_ghash_key_and_aes_gcm_cnt(party, &param)?;

    let mut ciphertexts = Vec::with_capacity(param.batch.len());

    let mut byte_index = 0;
    let mut ghash_keys = Vec::with_capacity(param.batch.len());
    let mut ad_vec = Vec::with_capacity(param.batch.len());

    for batch in param.batch {
        let mut ghash_key = Vec::with_capacity(16);
        ghash_key.extend_from_slice(&counter_output[byte_index..byte_index+16]);
        ghash_keys.push(into_gf128(ghash_key).unwrap()); // unwrap is safe since ghash_key has length 16
        let mut ghash_mask = Vec::with_capacity(16);
        ghash_mask.extend_from_slice(&counter_output[byte_index+16..byte_index+32]);
        let ciphertext: Vec<_> = counter_output.iter().skip(byte_index+32).zip(batch.message) // zip will stop when the (incomplete) last block ends
            .map(|(s,m)| *s + *m)
            .collect();
        ciphertexts.push(Aes128GcmCiphertext { ciphertext, tag: ghash_mask }); // store ghash_mask in tag for now

        ad_vec.push(batch.associated_data);

        byte_index += 32 + 16 * batch.n_blocks;
    }

    let ct_vec = ciphertexts.iter().map(|ct| ct.ciphertext.as_slice()).collect_vec();
    let tags = batched_ghash(party, party_index, ghash_keys, ad_vec, ct_vec)?;
    debug_assert_eq!(tags.len(), ciphertexts.len());
    ciphertexts.iter_mut().zip(tags).for_each(|(ct, block)| {
        // compute tag
        let block = from_gf128(block);
        for i in 0..16 {
            ct.tag[i] += block[i];
        }
    });

    Ok(ciphertexts)
}

/// Computes the AES-128-GCM decryption operation on the (nonce, key, associated data, ciphertext, tag)-pairs given in `data` in one batch.
/// Returns the corresponding result in the order of the inputs.
/// If the decryption was successful, `Some(plaintext)` is returned. Otherwise, `None` is returned.
/// 
/// This function returns an error if an MPC errors occur during any decryption operation. Decryption failure (i.e., invalid tag) is handled per decryption operation and does not return an Error
pub fn batch_aes128_gcm_decrypt_with_ks<'a, Protocol: ArithmeticBlackBox<GF128> + GF8InvBlackBox>(party: &mut Protocol, party_index: usize, data: impl Iterator<Item=DecParam<'a>>) -> MpcResult<Vec<Option<Vec<RssShare<GF8>>>>> {
    let params = data.into_iter().map(|param| {
        // check nonce length, key schedule and message lengths
        if param.iv.len() != 12 { return Err(MpcError::InvalidParameters("Invalid IV length. Supported IV length is 96 bit (12 byte)".to_string())); }
        if param.key_schedule.len() != 11 { return Err(MpcError::InvalidParameters("Invalid Key Schedule length. Expected 11 round keys".to_string())); }
        if (param.ciphertext.len() as u64) >= ((1u64 << 36)-32) { return Err(MpcError::InvalidParameters("Ciphertext too large. Maximum ciphertext length is < 2^36-32 bytes".to_string())); }
        if (param.associated_data.len() as u64) >= (1u64 << 61 -1) { return Err(MpcError::InvalidParameters("Associated data too large. Maximum length is < 2^61 - 1 bytes".to_string())); }
        if param.tag.len() != 16 { return Err(MpcError::InvalidParameters("Invalid tag length: supported length is 128-bit (16 byte)".to_string())); }

        let n_message_blocks = param.ciphertext.len().div_ceil(16);
        Ok(GcmParamDec {
            associated_data: param.associated_data,
            iv: param.iv,
            key_schedule: param.key_schedule,
            message: param.ciphertext,
            tag: param.tag,
            n_blocks: n_message_blocks,
        })
    }).collect::<MpcResult<Vec<_>>>()?;
    let param = BatchedGcmParams { batch: params };
    
    let counter_output = batched_ghash_key_and_aes_gcm_cnt(party, &param)?;
    
    let mut plaintexts = Vec::with_capacity(param.batch.len());
    let mut byte_index = 0;
    let mut ghash_keys = Vec::with_capacity(param.batch.len());
    let mut ad_vec = Vec::with_capacity(param.batch.len());
    let mut ciphertext = Vec::with_capacity(param.total_ct_length());

    let mut tags = Vec::with_capacity(param.batch.len());

    for batch in &param.batch {
        let mut ghash_key = Vec::with_capacity(16);
        ghash_key.extend_from_slice(&counter_output[byte_index..byte_index+16]);
        ghash_keys.push(into_gf128(ghash_key).unwrap()); // unwrap is safe since ghash_key has length 16
        let mut ghash_mask = Vec::with_capacity(16);
        ghash_mask.extend_from_slice(&counter_output[byte_index+16..byte_index+32]);
        let ghash_mask = into_gf128(ghash_mask).unwrap(); // unwrap is safe since ghash_mask has length 16
        let tag = ArithmeticBlackBox::<GF128>::constant(party, GF128::try_from(batch.tag).unwrap());
        tags.push(ghash_mask + tag);

        ciphertext.extend(batch.message.iter().map(|b| GF8InvBlackBox::constant(party, GF8(*b))));

        let current_ct = &ciphertext[ciphertext.len()-batch.message.len()..];
        let message: Vec<_> = counter_output.iter().skip(byte_index+32).zip(current_ct) // zip will stop when the (incomplete) last block ends
            .map(|(s,ct)| *s + *ct)
            .collect();
        plaintexts.push(message);

        ad_vec.push(batch.associated_data);
        byte_index += 32 + 16 * batch.n_blocks;
    }

    let mut ct_index = 0;
    let ct_vec = param.batch.into_iter().map(|batch| {
        let old = ct_index;
        ct_index += batch.message.len();
        &ciphertext[old..ct_index]
    }).collect_vec();
    
    let mut computed_tag = batched_ghash(party, party_index, ghash_keys, ad_vec, ct_vec)?;
    debug_assert_eq!(computed_tag.len(), plaintexts.len());


    // compute tag
    computed_tag.iter_mut().zip(tags).for_each(|(tag, mask)| *tag += mask);

    // check computed and given tag
    let correct = batched_tag_check(party, computed_tag)?;

    // only release the plaintext where the tag checked out
    let output = plaintexts.into_iter().zip(correct).map(|(pt, correct)| {
        if correct {
            Some(pt)
        }else{
            None
        }
    }).collect();

    Ok(output)
}

fn batched_ghash_key_and_aes_gcm_cnt<'a, Protocol: GF8InvBlackBox, T>(party: &mut Protocol, batch_params: &BatchedGcmParams<'a, T>) -> MpcResult<Vec<RssShare<GF8>>> {
    assert!(batch_params.batch.iter().all(|el| el.iv.len() == 12), "The only supported IV length is 96 bits");
    let mut counter_input = Vec::with_capacity(16*batch_params.total_block_length()); // the first block computes the GHASH key H, the second block computes the GHASH output mask
    
    let zero = party.constant(GF8(0));
    for el in &batch_params.batch {
        // first block all 0
        counter_input.extend(repeat_n(zero, 16));
        let iv = el.iv.iter().map(|iv_byte| party.constant(GF8(*iv_byte))).collect_vec();
        // n_blocks+1 : IV || cnt     where cnt = 1...n_nblocks+1
        for cnt in 1..=((el.n_blocks+1) as u32) {
            counter_input.extend_from_slice(&iv);
            let cnt_bytes = cnt.to_be_bytes();
            for cnt_byte in cnt_bytes {
                counter_input.push(party.constant(GF8(cnt_byte)));
            }
        }
    }
    
    debug_assert_eq!(counter_input.len(), 16*batch_params.total_block_length());
    let counter_input = VectorAesState::from_bytes(counter_input);
    let output_state = aes::batched_aes128_no_keyschedule(party, counter_input, &batch_params.key_schedule())?;
    Ok(output_state.to_bytes())
}

fn batched_ghash<'a, Protocol: ArithmeticBlackBox<GF128>>(party: &mut Protocol, party_index: usize, ghash_keys: Vec<RssShare<GF128>>, ad_vec: Vec<&'a [u8]>, ct_vec: Vec<&'a [RssShare<GF8>]>) -> MpcResult<Vec<RssShare<GF128>>> {
    debug_assert_eq!(ghash_keys.len(), ad_vec.len());
    debug_assert_eq!(ghash_keys.len(), ct_vec.len());
    let mut ghash_state = vec![party.constant(GF128::ZERO); ghash_keys.len()];

    let mut batch_iters = ad_vec.into_iter().zip(ct_vec).map(|(ad, ct)| {
        into_ghash_input_iter(party_index, ad, ct)
    }).collect_vec();

    let mut idx = 1; // to get at least on iteration
    let mut current_blocks = Vec::with_capacity(ghash_keys.len());
    let mut current_modified_state_si = Vec::with_capacity(ghash_keys.len());
    let mut current_modified_state_sii = Vec::with_capacity(ghash_keys.len());
    let mut current_key_si = Vec::with_capacity(ghash_keys.len());
    let mut current_key_sii = Vec::with_capacity(ghash_keys.len());
    let mut res_si = vec![GF128::ZERO; ghash_keys.len()];
    let mut res_sii = vec![GF128::ZERO; ghash_keys.len()];
    while idx > 0 {
        idx = 0;
        current_blocks.clear();
        current_modified_state_si.clear();
        current_modified_state_sii.clear();
        current_key_si.clear();
        current_key_sii.clear();

        // advance all iterators and collect the blocks
        batch_iters.iter_mut().for_each(|it| current_blocks.push(it.next()));
        // collect the modified state
        ghash_state.iter().zip(&current_blocks).for_each(|(state, block)| {
            if let Some(block) = block {
                let s = *state + *block;
                current_modified_state_si.push(s.si);
                current_modified_state_sii.push(s.sii);
            }
        });
        // check if at least one block is present
        if current_modified_state_si.len() > 0 {
            // collect the appropriate keys
            ghash_keys.iter().zip(&current_blocks).for_each(|(key, block)| {
                if block.is_some() {
                    current_key_si.push(key.si);
                    current_key_sii.push(key.sii);
                }
            });
        
            // mul
            party.mul(&mut res_si[..current_key_si.len()], &mut res_sii[..current_key_si.len()], &current_modified_state_si, &current_modified_state_sii, &current_key_si, &current_key_sii)?;

            // update the state
            ghash_state.iter_mut().zip(&current_blocks).for_each(|(state, block)| {
                if block.is_some() {
                    state.si = res_si[idx];
                    state.sii = res_sii[idx];
                    idx += 1;
                }
            });
        }
    }

    Ok(ghash_state)
}

fn batched_tag_check<Protocol: ArithmeticBlackBox<GF128>>(party: &mut Protocol, zero: Vec<RssShare<GF128>>) -> MpcResult<Vec<bool>> {
    let len = zero.len();
    let (zero_si, zero_sii): (Vec<_>, Vec<_>) = zero.into_iter().map(|rss| (rss.si, rss.sii)).unzip();
    let (rand_si, rand_sii): (Vec<_>, Vec<_>) = party.generate_random(zero_si.len()).into_iter().map(|rss| (rss.si, rss.sii)).unzip();
    let mut open_si = vec![GF128::ONE; len];
    let mut open_sii = vec![GF128::ONE; len];
    party.mul(&mut open_si, &mut open_sii, &zero_si, &zero_sii, &rand_si, &rand_sii)?;
    let els = party.output_round(&open_si, &open_sii)?;
    if els.len() != len {
        return Err(MpcError::Io(io::Error::new(io::ErrorKind::InvalidData, "Unexpected number of values to open")))
    }
    Ok(els.into_iter().map(|x| x == GF128::ZERO).collect())
}


fn into_ghash_input_iter<'a>(party_index: usize, associated_data: &'a [u8], ciphertext: &'a [RssShare<GF8>]) -> impl Iterator<Item=RssShare<GF128>> + 'a {
    let ad_len = 8 * associated_data.len() as u64;
    let ad_iter = associated_data.chunks(16)
        .map(move |chunk| {
            let mut arr = [0u8; 16];
            arr[..chunk.len()].copy_from_slice(chunk);
            let ad_block = GF128::from(arr);
            party::constant(party_index, ad_block)
        });
    let ct_len = 8 * ciphertext.len() as u64;
    let ct_iter = ciphertext.chunks(16).into_iter()
        .map(|chunk| {
            let mut si = [GF8::ZERO; 16];
            let mut sii = [GF8::ZERO; 16];
            izip!(chunk, si.iter_mut(), sii.iter_mut()).for_each(|(x, si, sii)| {
                *si = x.si;
                *sii = x.sii;
            });
            RssShare::from(GF128::from(si), GF128::from(sii))
        });
    let mut last_block = [0u8; 16];
    last_block[0..8].copy_from_slice(&ad_len.to_be_bytes());
    last_block[8..16].copy_from_slice(&ct_len.to_be_bytes());
    let last_block = party::constant(party_index, GF128::from(last_block));
    ad_iter.chain(ct_iter).chain(iter::once(last_block))
}

#[cfg(test)]
pub mod test {
    use aes_gcm::{aead::{Aead, Payload}, Aes128Gcm, Key, KeyInit, Nonce};
    use itertools::{izip, Itertools};
    use rand::{thread_rng, CryptoRng, Rng};

    use crate::{aes::{self, AesKeyState}, chida::{online::test::ChidaSetupSimple, ChidaBenchmarkParty}, gcm::{batch::{batch_aes128_gcm_decrypt_with_ks, batch_aes128_gcm_encrypt_with_ks, DecParam, DecParamOwned, EncParam, EncParamOwned}, test::{get_test_vectors, AesGcm128Testvector}}, rep3_core::test::TestSetup, share::{gf8::GF8, test::{assert_eq_vector, consistent_vector, secret_share_vector}}};

    #[test]
    fn batch_aes_gcm_128_encrypt_with_ks_test_vectors() {
        batch_aes_gcm_128_encrypt_with_ks_helper(get_test_vectors())
    }

    #[test]
    fn batch_aes_gcm_128_encrypt_with_ks_batch64() {
        // create 5x8 = 40 byte messages
        batch_aes_gcm_128_encrypt_with_ks_helper(get_batchsize_testvectors(64, 40))
    }

    #[test]
    fn batch_aes_gcm_128_encrypt_with_ks_batch128() {
        // create 5x8 = 40 byte messages
        batch_aes_gcm_128_encrypt_with_ks_helper(get_batchsize_testvectors(128, 40))
    }

    fn batch_aes_gcm_128_encrypt_with_ks_helper(test_vectors: Vec<AesGcm128Testvector>) {
        let empty_enc_param = EncParamOwned {
            iv: Vec::new(),
            key_schedule: Vec::new(),
            message: Vec::new(),
            associated_data: Vec::new(),
        };
        let mut enc_params1 = vec![empty_enc_param.clone(); test_vectors.len()];
        let mut enc_params2 = vec![empty_enc_param.clone(); test_vectors.len()];
        let mut enc_params3 = vec![empty_enc_param; test_vectors.len()];

        let mut rng = thread_rng();
        // fill enc params
        test_vectors.iter().enumerate().for_each(|(i, tv)| {
            // secret-share keys into key schedule
            let key = hex::decode(&tv.key).unwrap();
            let key_schedule = aes::test::aes128_keyschedule_plain(key.try_into().unwrap());

            for rk in key_schedule {
                let (k1, k2, k3) = secret_share_vector(&mut rng, rk.iter().map(|x| GF8(*x)));
                enc_params1[i].key_schedule.push(AesKeyState::from_rss_vec(k1));
                enc_params2[i].key_schedule.push(AesKeyState::from_rss_vec(k2));
                enc_params3[i].key_schedule.push(AesKeyState::from_rss_vec(k3));
            }

            // secret-share plaintext
            let pt = hex::decode(&tv.message).unwrap();
            let (pt1, pt2, pt3) = secret_share_vector(&mut rng, pt.iter().map(|x| GF8(*x)));
            enc_params1[i].message = pt1;
            enc_params2[i].message = pt2;
            enc_params3[i].message = pt3;

            // set iv and ad
            let iv = hex::decode(&tv.nonce).unwrap();
            let ad = hex::decode(&tv.ad).unwrap();
            enc_params1[i].iv = iv.clone();
            enc_params1[i].associated_data = ad.clone();
            enc_params2[i].iv = iv.clone();
            enc_params2[i].associated_data = ad.clone();
            enc_params3[i].iv = iv;
            enc_params3[i].associated_data = ad;
        });
        
        let program = |param: Vec<EncParamOwned>| {
            move |p: &mut ChidaBenchmarkParty| {
                let data = param.iter().map(|enc_param| EncParam {
                    iv: &enc_param.iv,
                    key_schedule: &enc_param.key_schedule,
                    associated_data: &enc_param.associated_data,
                    message: &enc_param.message,
                });
                let index = p.party_index();
                batch_aes128_gcm_encrypt_with_ks(p, index, data).unwrap()
            }
        };

        let ((res1, _), (res2, _), (res3, _)) = ChidaSetupSimple::localhost_setup(program(enc_params1), program(enc_params2), program(enc_params3));

        assert_eq!(res1.len(), test_vectors.len());
        assert_eq!(res2.len(), test_vectors.len());
        assert_eq!(res3.len(), test_vectors.len());

        izip!(test_vectors, res1, res2, res3).for_each(|(tv, ct1, ct2, ct3)| {
            consistent_vector(&ct1.tag, &ct2.tag, &ct3.tag);
            consistent_vector(&ct1.ciphertext, &ct2.ciphertext, &ct3.ciphertext);

            let expected_ciphertext = hex::decode(tv.ciphertext).unwrap().into_iter().map(|x| GF8(x)).collect_vec();
            let expected_tag = hex::decode(tv.tag).unwrap().into_iter().map(|x| GF8(x)).collect_vec();
            assert_eq_vector(ct1.ciphertext, ct2.ciphertext, ct3.ciphertext, expected_ciphertext);
            assert_eq_vector(ct1.tag, ct2.tag, ct3.tag, expected_tag);
        });
        
    }

    #[test]
    fn batch_aes_gcm_128_decrypt_with_ks_test_vectors() {
        batch_aes_gcm_128_decrypt_with_ks_helper(get_test_vectors());
    }

    #[test]
    fn batch_aes_gcm_128_decrypt_with_ks_batch64() {
        // generate 187x8 = 1496 byte long messages
        batch_aes_gcm_128_decrypt_with_ks_helper(get_batchsize_testvectors(64, 1496));
    }

    #[test]
    fn batch_aes_gcm_128_decrypt_with_ks_batch128() {
        // generate 187x8 = 1496 byte long messages
        batch_aes_gcm_128_decrypt_with_ks_helper(get_batchsize_testvectors(128, 1496));
    }

    fn batch_aes_gcm_128_decrypt_with_ks_helper(test_vectors: Vec<AesGcm128Testvector>) {
        let empty_dec_param = DecParamOwned {
            iv: Vec::new(),
            key_schedule: Vec::new(),
            ciphertext: Vec::new(),
            tag: Vec::new(),
            associated_data: Vec::new(),
        };
        let mut dec_params1 = vec![empty_dec_param.clone(); test_vectors.len()];
        let mut dec_params2 = vec![empty_dec_param.clone(); test_vectors.len()];
        let mut dec_params3 = vec![empty_dec_param; test_vectors.len()];

        let mut rng = thread_rng();
        // fill dec params
        test_vectors.iter().enumerate().for_each(|(i, tv)| {
            // secret-share keys into key schedule
            let key = hex::decode(&tv.key).unwrap();
            let key_schedule = aes::test::aes128_keyschedule_plain(key.try_into().unwrap());

            for rk in key_schedule {
                let (k1, k2, k3) = secret_share_vector(&mut rng, rk.iter().map(|x| GF8(*x)));
                dec_params1[i].key_schedule.push(AesKeyState::from_rss_vec(k1));
                dec_params2[i].key_schedule.push(AesKeyState::from_rss_vec(k2));
                dec_params3[i].key_schedule.push(AesKeyState::from_rss_vec(k3));
            }

            // set ciphertext, tag, iv and ad
            let ciphertext = hex::decode(&tv.ciphertext).unwrap();
            dec_params1[i].ciphertext = ciphertext.clone();
            dec_params2[i].ciphertext = ciphertext.clone();
            dec_params3[i].ciphertext = ciphertext;
            let tag = hex::decode(&tv.tag).unwrap();
            dec_params1[i].tag = tag.clone();
            dec_params2[i].tag = tag.clone();
            dec_params3[i].tag = tag;
            let iv = hex::decode(&tv.nonce).unwrap();
            dec_params1[i].iv = iv.clone();
            dec_params2[i].iv = iv.clone();
            dec_params3[i].iv = iv;
            let ad = hex::decode(&tv.ad).unwrap();
            dec_params1[i].associated_data = ad.clone();
            dec_params2[i].associated_data = ad.clone();
            dec_params3[i].associated_data = ad;
        });
        
        let program = |param: Vec<DecParamOwned>| {
            move |p: &mut ChidaBenchmarkParty| {
                let data = param.iter().map(|dec_param| DecParam {
                    iv: &dec_param.iv,
                    key_schedule: &dec_param.key_schedule,
                    associated_data: &dec_param.associated_data,
                    ciphertext: &dec_param.ciphertext,
                    tag: &dec_param.tag,
                });
                let index = p.party_index();
                batch_aes128_gcm_decrypt_with_ks(p, index, data).unwrap()
            }
        };

        let ((res1, _), (res2, _), (res3, _)) = ChidaSetupSimple::localhost_setup(program(dec_params1), program(dec_params2), program(dec_params3));

        assert_eq!(res1.len(), test_vectors.len());
        assert_eq!(res2.len(), test_vectors.len());
        assert_eq!(res3.len(), test_vectors.len());

        izip!(test_vectors, res1, res2, res3).for_each(|(tv, pt1, pt2, pt3)| {
            assert!(pt1.is_some());
            assert!(pt2.is_some());
            assert!(pt3.is_some());
            let pt1 = pt1.unwrap();
            let pt2 = pt2.unwrap();
            let pt3 = pt3.unwrap();
            consistent_vector(&pt1, &pt2, &pt3);
            
            let expected_message = hex::decode(tv.message).unwrap();
            let expected_message = expected_message.into_iter().map(|b| GF8(b)).collect_vec();
            assert_eq_vector(pt1, pt2, pt3, expected_message);
        });
        
    }

    /// n_bytes random bytes encoded as hex
    fn random_bytes<R: Rng + CryptoRng>(rng: &mut R, n_bytes: usize) -> String {
        let mut bytes = vec![0u8; n_bytes];
        rng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Returns n many test vectors
    fn get_batchsize_testvectors(n: usize, msg_len: usize) -> Vec<AesGcm128Testvector> {
        let mut rng = thread_rng();
        let keys = (0..n).map(|_| random_bytes(&mut rng, 16)).collect_vec();
        let ivs = (0..n).map(|_| random_bytes(&mut rng, 12)).collect_vec();
        let ads = (0..n).map(|_| random_bytes(&mut rng, 1200)).collect_vec();
        let messages = (0..n).map(|_| random_bytes(&mut rng, msg_len)).collect_vec();
        
        izip!(keys, ivs, ads, messages).map(|(key, iv, ad, msg)| {
            let (ct, tag) = aes128_gcm_enc_plain(&key, &iv, &ad, &msg);
            let ct = hex::encode(ct);
            let tag = hex::encode(tag);
            AesGcm128Testvector {
                ad, key, nonce: iv, message: msg, ciphertext: ct, tag
            }
        }).collect()
    }

    pub fn aes128_gcm_enc_plain(key: &str, iv: &str, ad: &str, msg: &str) -> (Vec<u8>, Vec<u8>) {
        let k = hex::decode(key).unwrap();
        let key = Key::<Aes128Gcm>::from_slice(&k);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::clone_from_slice(hex::decode(iv).unwrap().as_slice());
        let ad = hex::decode(ad).unwrap();
        let msg = hex::decode(msg).unwrap();
        let mut res = cipher.encrypt(&nonce, Payload {msg: &msg, aad: &ad}).unwrap();
        let mut tag = Vec::with_capacity(16);
        tag.extend_from_slice(&res[res.len()-16..]);
        res.truncate(res.len()-16);
        (res, tag)
    }
}