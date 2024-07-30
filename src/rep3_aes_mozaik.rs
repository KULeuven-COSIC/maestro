#![allow(dead_code)]
mod share;
mod party;
mod network;
mod gcm;
mod chida;
mod conversion;
mod aes;
mod furukawa;
mod benchmark;

use core::slice;
use std::{fmt::Display, io, path::PathBuf, str::FromStr, time::Duration};

use aes::{AesKeyState, GF8InvBlackBox};
use chida::{ChidaBenchmarkParty, ImplVariant};
use clap::{Parser, Subcommand};
use conversion::{convert_boolean_to_ring, convert_ring_to_boolean, Z64Bool};
use furukawa::FurukawaGCMParty;
use gcm::{batch::{batch_aes128_gcm_decrypt_with_ks, batch_aes128_gcm_encrypt_with_ks, DecParam, EncParam}, gf128::GF128, Aes128GcmCiphertext, RequiredPrepAesGcm128};
use itertools::{izip, repeat_n, Itertools};
use network::{Config, ConnectedParty};
use party::{error::{MpcError, MpcResult}, ArithmeticBlackBox};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use share::{gf8::GF8, Field, RssShare};

#[derive(Debug)]
enum Rep3AesError {
    ParseError(String),
    MpcError(String),
}

type Result<T> = core::result::Result<T, Rep3AesError>;

#[derive(Parser)]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    #[arg(long, value_name = "TIME_SECONDS", help="If set, the server attempts to connect to the other parties until TIME_SECONDS has passed.")]
    timeout: Option<usize>,
    #[arg(long, action, help="If set, uses actively secure MPC protocols. Default: not set, i.e., uses passively-secure MPC protocol.")]
    active: bool,
    #[arg(long, value_name = "THREADS", help="If set, the number of threads to use.")]
    threads: Option<usize>,
    #[command(subcommand)]
    command: Commands
}

#[derive(Clone)]
pub enum Mode {
    AesGcm128,
}

impl FromStr for Mode {
    type Err = clap::Error;
    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        match s {
            "AES-GCM-128" => Ok(Self::AesGcm128),
            _ => Err(clap::Error::raw(clap::error::ErrorKind::UnknownArgument, format!("Unknown mode argument: {}; Available options are: \"AES-GCM-128\"", s))),
        }
    }
}

impl Display for Rep3AesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParseError(s) => write!(f, "Parse error: {}", s),
            Self::MpcError(s) => write!(f, "MPC error: {}", s),
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long, help="The encryption mode to use.")]
        mode: Mode,
    },
    Decrypt {
        #[arg(short, long, help="The decryption mode to use.")]
        mode: Mode,
    },
}

#[derive(Deserialize)]
enum Key {
    #[serde(rename = "key_share")]
    KeyShare(String),
    #[serde(rename = "key_schedule_share")]
    SharedKeySchedule(String),
}

#[derive(Deserialize)]
struct EncryptArgs {
    #[serde(flatten)]
    key_share: Key,
    nonce: String,
    associated_data: String,
    message_share: Vec<(u64,u64)>,
}

#[derive(Deserialize)]
struct DecryptArgs {
    #[serde(flatten)]
    key_share: Key,
    nonce: String,
    associated_data: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

enum KeyParams<T> {
    KeyShare(Vec<T>),
    SharedKeySchedule(Vec<T>)
}

struct EncryptParams {
    key_share: KeyParams<GF8>,
    nonce: Vec<u8>,
    associated_data: Vec<u8>,
    message_share: Vec<(u64,u64)>,
}

struct DecryptParams {
    key_share: KeyParams<GF8>,
    nonce: Vec<u8>,
    associated_data: Vec<u8>,
    ciphertext: Vec<u8>,
}

trait HasKeyParams {
    fn key_share(&self) -> &KeyParams<GF8>;
    fn message_len(&self) -> usize;
}

#[derive(Serialize, Deserialize)]
struct DecryptResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    message_share: Option<Vec<(u64,u64)>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag_error: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> KeyParams<T> {
    pub fn len(&self) -> usize {
        match self {
            Self::KeyShare(v) | Self::SharedKeySchedule(v) => v.len()
        }
    }
}

fn try_decode_hex(field: &str, arg: String) -> Result<Vec<u8>> {
    hex::decode(arg).map_err(|hex_err| Rep3AesError::ParseError(format!("when reading parameter field '{}': {}", field, hex_err)))
}

fn try_decode_key(key_share: Key) -> Result<KeyParams<GF8>> {
    Ok(match key_share {
        Key::KeyShare(key_share) => {
            let bytes = try_decode_hex("key_share", key_share)?;
            KeyParams::KeyShare(bytes.into_iter().map(|b| GF8(b)).collect())
        },
        Key::SharedKeySchedule(key_schedule) => {
            let bytes = try_decode_hex("key_schedule_share", key_schedule)?;
            KeyParams::SharedKeySchedule(bytes.into_iter().map(|b| GF8(b)).collect())
        },
    })
}

impl TryFrom<EncryptArgs> for EncryptParams {
    type Error = Rep3AesError;
    fn try_from(args: EncryptArgs) -> Result<Self> {
        let key_share = try_decode_key(args.key_share)?;
        let nonce = try_decode_hex("nonce", args.nonce)?;
        let ad = try_decode_hex("associated_data", args.associated_data)?;
    
        Ok(Self {
            key_share,
            nonce,
            associated_data: ad,
            message_share: args.message_share,
        })
    }
}

impl TryFrom<DecryptArgs> for DecryptParams {
    type Error = Rep3AesError;
    fn try_from(args: DecryptArgs) -> Result<Self> {
        let key_share = try_decode_key(args.key_share)?;
        let nonce = try_decode_hex("nonce", args.nonce)?;
        let ad = try_decode_hex("associated_data", args.associated_data)?;
        let ct = try_decode_hex("ciphertext", args.ciphertext)?;

        Ok(Self {
            key_share,
            nonce,
            associated_data: ad,
            ciphertext: ct,
        })
    }
}

impl HasKeyParams for EncryptParams {
    fn key_share(&self) -> &KeyParams<GF8> {
        &self.key_share
    }
    fn message_len(&self) -> usize {
        self.message_share.len()
    }
}

impl HasKeyParams for DecryptParams {
    fn key_share(&self) -> &KeyParams<GF8> {
        &self.key_share
    }

    fn message_len(&self) -> usize {
        self.ciphertext.len()
    }
}

impl EncryptResult {
    pub fn new(ct: Vec<GF8>) -> Self {
        Self {
            ciphertext: Some(hex::encode(ct.into_iter().map(|gf| gf.0).collect_vec())),
            error: None,
        }
    }
}

impl From<Rep3AesError> for Vec<EncryptResult> {
    fn from(value: Rep3AesError) -> Self {
        vec![EncryptResult {
            ciphertext: None,
            error: Some(value.to_string())
        }]
    }
}

impl DecryptResult {
    pub fn new_success(ring_share: Vec<(u64,u64)>) -> Self {
        Self {
            message_share: Some(ring_share),
            tag_error: None,
            error: None,
        }
    }

    pub fn new_tag_error() -> Self {
        Self {
            message_share: None,
            tag_error: Some(true),
            error: None,
        }
    }
}

impl From<Rep3AesError> for Vec<DecryptResult> {
    fn from(value: Rep3AesError) -> Self {
        vec![DecryptResult {
            message_share: None,
            tag_error: None,
            error: Some(value.to_string()),
        }]
    }
}

fn parse_args_from_reader<Args: DeserializeOwned, Params: TryFrom<Args, Error = Rep3AesError>, R: io::Read>(reader: R) -> Result<Vec<Params>> {
    let args: Vec<Args> = serde_json::from_reader(reader).map_err(|serde_err| Rep3AesError::ParseError(format!("When parsing EncryptArgs: {}", serde_err)))?;
    args.into_iter().map(|arg| Params::try_from(arg)).collect()
}

fn return_to_writer<T: Serialize + From<Rep3AesError>, W: io::Write, F: FnOnce()->Result<T>>(compute: F, writer: W) {
    match compute() {
        Ok(msg) => serde_json::to_writer(writer, &msg).unwrap(),
        Err(err) => serde_json::to_writer::<_, T>(writer, &err.into()).unwrap(),
    }
}

fn additive_shares_to_rss<Protocol: ArithmeticBlackBox<GF8>>(party: &mut Protocol, shares: &[impl HasKeyParams]) -> MpcResult<Vec<KeyParams<RssShare<GF8>>>> {
    debug_assert!(shares.len() > 0);

    let key_param_len = shares[0].key_share().len();
    if shares.iter().any(|ks| ks.key_share().len() != key_param_len) {
        return Err(MpcError::InvalidParameters("Key shares and key schedule shares cannot be mixed in batched encryption/decryption".to_string()));
    }
    let total_length = shares.len() * key_param_len;
    let mut add_shares = Vec::with_capacity(total_length);
    shares.iter().for_each(|s| {
        match s.key_share() {
            KeyParams::KeyShare(v) | KeyParams::SharedKeySchedule(v) => add_shares.extend_from_slice(&v),
        }
    });
    
    let (k1, k2, k3) = party.input_round(&add_shares)?;
    let key_share_rss: Vec<_> = izip!(k1, k2, k3)
        .map(|(k1, k2, k3)| k1 + k2 + k3)
        .collect();
    Ok(shares.iter().zip(key_share_rss.chunks_exact(key_param_len))
        .map(|(share, chunk)| {
            let rss = chunk.iter().copied().collect_vec();
            match share.key_share() {
                KeyParams::KeyShare(_) => KeyParams::KeyShare(rss),
                KeyParams::SharedKeySchedule(_) => KeyParams::SharedKeySchedule(rss),
            }
        })
        .collect()
    )
}

impl From<MpcError> for Rep3AesError {
    fn from(value: MpcError) -> Self {
        Self::MpcError(value.to_string())
    }
}

impl From<io::Error> for Rep3AesError {
    fn from(value: io::Error) -> Self {
        Self::MpcError(value.to_string())
    }
}

fn try_unflatten_aes128_gcm_key_schedule(key_schedule: &Vec<RssShare<GF8>>) -> MpcResult<Vec<AesKeyState>> {
    if key_schedule.len() != 176 {
        return Err(MpcError::InvalidParameters("Expected a AES-128 keyschedule (176 byte)".to_string()));
    }
    // un-flatten the key_schedule
    let key_schedule = key_schedule.chunks_exact(16)
        .map(|round_key| AesKeyState::from_bytes(round_key.iter().copied().collect_vec()))
        .collect_vec();
    Ok(key_schedule)
}

fn aes128_gcm_encrypt_key_params<Protocol>(party: &mut Protocol, iv: &[u8], key: &KeyParams<RssShare<GF8>>, message: &[RssShare<GF8>], associated_data: &[u8]) -> MpcResult<Aes128GcmCiphertext>
where Protocol: ArithmeticBlackBox<Z64Bool> + ArithmeticBlackBox<GF8> + ArithmeticBlackBox<GF128> + GF8InvBlackBox
{
    match key {
        KeyParams::KeyShare(key_share) => gcm::aes128_gcm_encrypt(party, iv, &key_share, message, associated_data),
        KeyParams::SharedKeySchedule(key_schedule) => {
            let key_schedule = try_unflatten_aes128_gcm_key_schedule(key_schedule)?;
            gcm::aes128_gcm_encrypt_with_ks(party, iv, &key_schedule, message, associated_data)
        }
    }
}

fn aes_gcm_128_enc<Protocol: ArithmeticBlackBox<Z64Bool> + ArithmeticBlackBox<GF8> + ArithmeticBlackBox<GF128> + GF8InvBlackBox>(party: &mut Protocol, party_index: usize, encrypt_args: EncryptParams) -> Result<EncryptResult> {
    let key_share = additive_shares_to_rss(party, slice::from_ref(&encrypt_args))?;
    debug_assert_eq!(key_share.len(), 1);
    let key_share = &key_share[0];
    let (message_share_si, message_share_sii): (Vec<_>, Vec<_>) = encrypt_args.message_share.into_iter().unzip();
    ArithmeticBlackBox::<Z64Bool>::pre_processing(party, 2*64*message_share_si.len())?;
    let prep_info = gcm::get_required_prep_for_aes_128_gcm(encrypt_args.associated_data.len(), message_share_si.len()*8);
    GF8InvBlackBox::do_preprocessing(party, 1, prep_info.blocks)?;
    ArithmeticBlackBox::<GF128>::pre_processing(party, prep_info.mul_gf128)?;
    let message_share = convert_ring_to_boolean(party, party_index, &message_share_si, &message_share_sii)?;
    let mut ct = aes128_gcm_encrypt_key_params(party, &encrypt_args.nonce, key_share, &message_share, &encrypt_args.associated_data)?;
    ct.ciphertext.append(&mut ct.tag);
    // open ct||tag
    let ct_and_tag = party.output_to(&ct.ciphertext, &ct.ciphertext, &ct.ciphertext)?;
    ArithmeticBlackBox::<Z64Bool>::finalize(party)?;
    ArithmeticBlackBox::<GF128>::finalize(party)?;
    Ok(EncryptResult::new(ct_and_tag))
}

fn batch_aes_gcm_128_enc<Protocol: ArithmeticBlackBox<Z64Bool> + ArithmeticBlackBox<GF8> + ArithmeticBlackBox<GF128> + GF8InvBlackBox>(party: &mut Protocol, party_index: usize, encrypt_args: Vec<EncryptParams>) -> Result<Vec<EncryptResult>> {
    let key_share = additive_shares_to_rss(party, &encrypt_args)?;
    let key_share = key_share.into_iter().map(|ks| {
        match ks {
            KeyParams::SharedKeySchedule(ks) => try_unflatten_aes128_gcm_key_schedule(&ks),
            KeyParams::KeyShare(_) => Err(MpcError::InvalidParameters("key schedule computation not supported in batching mode".to_string())),
        }
    }).collect::<MpcResult<Vec<_>>>()?;

    let total_message_len: usize = encrypt_args.iter().map(|arg| arg.message_share.len()).sum();
    ArithmeticBlackBox::<Z64Bool>::pre_processing(party, 2*64 * total_message_len)?;
    let prep_info = encrypt_args.iter().fold(RequiredPrepAesGcm128 { blocks: 0, mul_gf128: 0 }, |mut acc, arg| {
        let tmp = gcm::get_required_prep_for_aes_128_gcm(arg.associated_data.len(), arg.message_share.len()*8);
        acc.blocks += tmp.blocks;
        acc.mul_gf128 += tmp.mul_gf128;
        acc
    });
    
    GF8InvBlackBox::do_preprocessing(party, 0, prep_info.blocks)?;
    ArithmeticBlackBox::<GF128>::pre_processing(party, prep_info.mul_gf128)?;

    let (message_share_si, message_share_sii): (Vec<_>, Vec<_>) = encrypt_args.iter().flat_map(|arg| arg.message_share.iter().copied()).unzip();
    let message_share = convert_ring_to_boolean(party, party_index, &message_share_si, &message_share_sii)?;

    let mut message_index = 0;
    let data = encrypt_args.iter().zip(&key_share).map(|(arg, key_schedule)| {
        let param = EncParam {
            iv: &arg.nonce,
            associated_data: &arg.associated_data,
            key_schedule,
            message: &message_share[message_index..message_index+8*arg.message_share.len()]
        };
        message_index += 8*arg.message_share.len();
        param
    });
    let ct = batch_aes128_gcm_encrypt_with_ks(party, party_index, data)?;
    drop(key_share);
    drop(message_share);
    drop(encrypt_args);

    // flatten
    let mut ct_lens = Vec::with_capacity(ct.len());
    let flat_ct = ct.into_iter().flat_map(|ct| {
        ct_lens.push(ct.ciphertext.len());
        // append ct||tag
        ct.ciphertext.into_iter().chain(ct.tag.into_iter())
    }).collect_vec();
    // open ct||tag
    let ct_and_tag = party.output_to(&flat_ct, &flat_ct, &flat_ct)?;
    drop(flat_ct);
    ArithmeticBlackBox::<Z64Bool>::finalize(party)?;
    ArithmeticBlackBox::<GF128>::finalize(party)?;

    // undo the flatten on the opened values
    let mut ct_index = 0;
    Ok(
        ct_lens.into_iter().map(|ct_len| {
            let mut res = Vec::with_capacity(ct_len+16); //tag has fixed length 16 byte
            res.extend_from_slice(&ct_and_tag[ct_index..ct_index+ct_len+16]);
            ct_index += ct_len+16;
            EncryptResult::new(res)
        })
        .collect()
    )
}

fn mozaik_decrypt<Protocol: ArithmeticBlackBox<GF8> + ArithmeticBlackBox<GF128> + GF8InvBlackBox + ArithmeticBlackBox<Z64Bool>>(party: &mut Protocol, party_index: usize, decrypt_args: DecryptParams) -> Result<DecryptResult> {
    let key_share = additive_shares_to_rss(party, slice::from_ref(&decrypt_args))?;
    debug_assert_eq!(key_share.len(), 1);
    let key_share = &key_share[0];
    // split ciphertext and tag; tag is the last 16 bytes
    let ctlen = decrypt_args.ciphertext.len();
    if ctlen < 16 {
        return Err(Rep3AesError::MpcError("Invalid ciphertext length".to_string()));
    }
    let (ct, tag) = (&decrypt_args.ciphertext[..ctlen-16], &decrypt_args.ciphertext[ctlen-16..]);
    let res = match key_share {
        KeyParams::KeyShare(key_share) => gcm::aes128_gcm_decrypt(party, &decrypt_args.nonce, key_share, ct, tag, &decrypt_args.associated_data, gcm::semi_honest_tag_check),
        KeyParams::SharedKeySchedule(key_schedule) => {
            if key_schedule.len() != 176 {
                return Err(MpcError::InvalidParameters("Expected a AES-128 keyschedule (176 byte)".to_string()).into());
            }
            // un-flatten the key_schedule
            let key_schedule = key_schedule.chunks_exact(16)
                .map(|round_key| AesKeyState::from_bytes(round_key.iter().copied().collect_vec()))
                .collect_vec();
            gcm::aes128_gcm_decrypt_with_ks(party, &decrypt_args.nonce, &key_schedule, ct, tag, &decrypt_args.associated_data, gcm::semi_honest_tag_check)
        }
    };
    match res {
        Ok(message_share) => {
            // now run b2a conversion
            let (ring_shares_si, ring_shares_sii) = convert_boolean_to_ring(party, party_index, message_share.into_iter())?;
            let ring_shares = ring_shares_si.into_iter().zip(ring_shares_sii).collect();
            Ok(DecryptResult::new_success(ring_shares))
        },
        Err(MpcError::OperationFailed(_)) => Ok(DecryptResult::new_tag_error()),
        Err(err) => Err(err.into()),
    }
}

fn batch_mozaik_decrypt<Protocol: ArithmeticBlackBox<GF8> + ArithmeticBlackBox<GF128> + GF8InvBlackBox + ArithmeticBlackBox<Z64Bool>>(party: &mut Protocol, party_index: usize, decrypt_args: Vec<DecryptParams>) -> Result<Vec<DecryptResult>> {
    let key_share = additive_shares_to_rss(party, &decrypt_args)?;
    let key_share = key_share.into_iter().map(|ks| {
        match ks {
            KeyParams::SharedKeySchedule(ks) => try_unflatten_aes128_gcm_key_schedule(&ks),
            KeyParams::KeyShare(_) => Err(MpcError::InvalidParameters("key schedule computation not supported in batching mode".to_string())),
        }
    }).collect::<MpcResult<Vec<_>>>()?;

    let total_message_len: usize = decrypt_args.iter().map(|arg| arg.ciphertext.len()).sum::<usize>() / 8;
    ArithmeticBlackBox::<Z64Bool>::pre_processing(party, 2*64 * total_message_len)?;
    let prep_info = decrypt_args.iter().fold(RequiredPrepAesGcm128 { blocks: 0, mul_gf128: 0 }, |mut acc, arg| {
        let tmp = gcm::get_required_prep_for_aes_128_gcm(arg.associated_data.len(), arg.ciphertext.len());
        acc.blocks += tmp.blocks;
        acc.mul_gf128 += tmp.mul_gf128;
        acc
    });
    GF8InvBlackBox::do_preprocessing(party, 0, prep_info.blocks)?;
    ArithmeticBlackBox::<GF128>::pre_processing(party, prep_info.mul_gf128)?;

    // check that all ciphertexts have valid length
    if decrypt_args.iter().any(|arg| arg.ciphertext.len() < 16) {
        return Err(Rep3AesError::MpcError("invalid ciphertext length".to_string()));
    }

    let data = decrypt_args.iter().zip(&key_share).map(|(arg, key_schedule)| {
        // split ciphertext and tag; tag is the last 16 bytes
        DecParam {
            iv: &arg.nonce,
            associated_data: &arg.associated_data,
            key_schedule,
            ciphertext: &arg.ciphertext[..arg.ciphertext.len()-16],
            tag: &arg.ciphertext[arg.ciphertext.len()-16..],
        }
    });

    let plaintexts = batch_aes128_gcm_decrypt_with_ks(party, party_index, data)?;

    drop(decrypt_args);
    drop(key_share);

    let mut pt_lens = Vec::with_capacity(plaintexts.len());
    let zero = RssShare::constant(party_index, GF8::ZERO);
    let pt_flat = plaintexts.into_iter().flat_map(|decrypt_res| {
        match decrypt_res {
            Some(pt) => {
                pt_lens.push(pt.len().div_ceil(8));
                let pad = if pt.len() % 8 == 0 { 0 } else { 8 - (pt.len() % 8) };
                pt.into_iter().chain(repeat_n(zero, pad))
            },
            None => {
                pt_lens.push(0);
                // we have to return the same type in the two match arms
                Vec::new().into_iter().chain(repeat_n(zero, 0))
            }
        }
    });

    // now run b2a conversion
    let (ring_shares_si, ring_shares_sii) = convert_boolean_to_ring(party, party_index, pt_flat)?;
    
    ArithmeticBlackBox::<Z64Bool>::finalize(party)?;
    ArithmeticBlackBox::<GF128>::finalize(party)?;
    let mut pt_index = 0;
    Ok(
        pt_lens.into_iter().map(|len| {
            if len > 0 {
                let ring_shares = ring_shares_si.iter().copied().zip(ring_shares_sii.iter().copied())
                    .skip(pt_index).take(len).collect();
                pt_index += len;
                DecryptResult::new_success(ring_shares)
            }else{
                DecryptResult::new_tag_error()
            }
        }).collect()
    )
}

fn execute_command<R: io::Read, W: io::Write>(cli: Cli, input_arg_reader: R, output_writer: W) {
    let (party_index, config) = Config::from_file(&cli.config).unwrap();
    let timeout = cli.timeout.map(|secs| Duration::from_secs(secs as u64));
    match cli.command {
        Commands::Encrypt { mode } => {
            let encrypt_args = parse_args_from_reader::<EncryptArgs,EncryptParams, _>(input_arg_reader).unwrap();
            match mode {
                Mode::AesGcm128 => {
                    return_to_writer(|| {
                        let connected = ConnectedParty::bind_and_connect(party_index, config, timeout)?;
                        let party_index = connected.i;
                        if cli.active {
                            let mut party = FurukawaGCMParty::setup(connected, cli.threads)?;
                            if encrypt_args.len() == 1 {
                                let encrypt_args = encrypt_args.into_iter().next().unwrap();
                                let res = aes_gcm_128_enc(&mut party, party_index, encrypt_args);
                                // pack res into a list of size 1
                                res.map(|encrypt_res| vec![encrypt_res])
                            }else{
                                batch_aes_gcm_128_enc(&mut party, party_index, encrypt_args)
                            }
                        }else{
                            let mut party = ChidaBenchmarkParty::setup(connected, chida::ImplVariant::Simple, cli.threads)?;
                            if encrypt_args.len() == 1 {
                                let encrypt_args = encrypt_args.into_iter().next().unwrap();
                                let res = aes_gcm_128_enc(&mut party, party_index, encrypt_args);
                                // pack res into a list of size 1
                                res.map(|encrypt_res| vec![encrypt_res])
                            }else{
                                batch_aes_gcm_128_enc(&mut party, party_index, encrypt_args)
                            }
                        }
                    }, output_writer);
                }
            }  
        },
        Commands::Decrypt { mode } => {
            let decrypt_args = parse_args_from_reader::<DecryptArgs, DecryptParams, _>(input_arg_reader).unwrap();
            match mode {
                Mode::AesGcm128 => {
                    return_to_writer(|| {
                        let connected = ConnectedParty::bind_and_connect(party_index, config, timeout)?;
                        let party_index = connected.i;
                        if cli.active {
                            let mut party = FurukawaGCMParty::setup(connected, cli.threads)?;
                            if decrypt_args.len() == 1 {
                                let decrypt_args = decrypt_args.into_iter().next().unwrap();
                                let res = mozaik_decrypt(&mut party, party_index, decrypt_args);
                                // pack res into a list of size 1
                                res.map(|decrypt_res| vec![decrypt_res])
                            }else{
                                batch_mozaik_decrypt(&mut party, party_index, decrypt_args)
                            }
                        }else{
                            let mut party = ChidaBenchmarkParty::setup(connected, ImplVariant::Optimized, cli.threads)?;
                            if decrypt_args.len() == 1 {
                                let decrypt_args = decrypt_args.into_iter().next().unwrap();
                                let res = mozaik_decrypt(&mut party, party_index, decrypt_args);
                                // pack res into a list of size 1
                                res.map(|decrypt_res| vec![decrypt_res])
                            }else{
                                batch_mozaik_decrypt(&mut party, party_index, decrypt_args)
                            }
                        }
                    }, output_writer);
                }
            }
        }
    }
}


fn main() {
    let cli = Cli::parse();
    execute_command(cli, io::stdin(), io::stdout());
}

#[cfg(test)]
mod rep3_aes_main_test {
    use std::{io::BufWriter, path::PathBuf, sync::Mutex, thread};
    use aes_gcm::{aead::{Aead, Payload}, Aes128Gcm, Key, KeyInit, Nonce};
    use rand::Rng;

    use itertools::{izip, Itertools};
    use rand::thread_rng;

    use crate::{aes, conversion::test::secret_share_vector_ring, execute_command, gcm, share::{gf8::GF8, test::secret_share_vector, RssShare}, Cli, Commands, DecryptResult, EncryptResult, Mode};


    const KEY_SHARE_1: &str = "76c2488bd101fd2999a922d351707fcf";
    const KEY_SHARE_2: &str = "014a3b40b4e7b77f600e6bdacd1c50af";
    const KEY_SHARE_3: &str = "022ccfa18b5c356ffbb22ee3b7e099e7";
    const NONCE: &str = "18a04c8f66bdec6a74513af6";
    const AD: &str = "34643134373530652d323335332d346433302d616332622d65383933383138303736643230820122300d06092a864886f70d01010105000382010f003082010a0282010100a78746c19361dbff7c3c7a3d1b9cdb76dfad38e69bf456184af575244fdb0c7770358dbf637bdeea05fc50d310b5ed1a61859f66a38aa1ede42c5fb2891b640aba34a6a9ba906e414337f8e81573fc6923f3fa6c1b7538ea041d109864d4183f237f882e5ee4af214311d7db298e9da2a00bbb04c44539a0fd86468c60c30a699bc8d41bbbef75ed63a4d523776af621f9b3b00c27c36aca23a290e293688351fdfb919c907b3758acc9b9e34368972759863aa90f76c04fc522d731d6cf1779069e4e07254bafd9c5f79c249a7c5fbad43f3ddc4d3d5429260d91d5ed4506f6aa380e74ee56a636f7a6157992497f18b25d963fe2364162ac08f685df5a5709020301000130820122300d06092a864886f70d01010105000382010f003082010a0282010100cccb626ab39b644ab7c9bb6785616f1689e3999bdfcb64f5575a77d1af8ad8e371e4f43bdb8d99174fce4f6cf0cb54738362b64f4e9089adaec2557294a7c906c8549b2c91db6c1a569a29c61d03a196887e3bf40bb07302aa05561befa7b3ffd2c295fb538944381943f1b03e046eeb10e9e5b67c1773185a85f06aa9d558cd61f407f2084174cefd2ae8e50a89b97ca069f201bd4662f7715d83fbdcb9d02590512355a0e0a67f6a991a77ad715936fa80bc60111727ecb56e735e9c2caf90247d74b8aba82cb0222cfed640fde34a46d507da98b9ee40987347fa7d56f94f3474cb7b3fe780b4dfe925587e96d5606d1fe4dccb4b8054d532bdaee93bb9bf020301000130820122300d06092a864886f70d01010105000382010f003082010a0282010100d8ae66dded6a8d8e7daa8ed8fe4e03b6e107db3b23d81b789a885b804def98a38fd826f93489438dcc694400e5132600a9d8ba16df6662e609eeac10ad803fbc31982d408118dc5478802cd968e61787489c9f2d85bd2d1c24a5c3883226b61d9b0ea74ca89a7d46b363b635e349711bf15c375ee18dc50fd3efac3f231564b4ea06071fabdd1c183eb02540bc9f7eadf61753f2538fbbd6b00dc85a627d5d971649c8014b12a3903c2ad739084fceee2b244cc2eb10414ec4ef402243ff36d3bc663ae14e18d446a851ba38a8aedac539a2f89cfd0b2e98f74e924b2f9d4d96d26cce499133b95e2151f4194f50d1701ac76750041a4de7125bad7a80fd91a7020301000132383334316630372d323836612d343736312d386664652d3232306237626533643463634865617274626561742d44656d6f2d31";
    const MESSAGE_RING: [u64;5] = [6149648890722733960, 3187258121416518661, 3371553381890320898, 1292927509834657361, 1216049165532225112];
    const CT: &str = "df9776ec3ce5fbace5b8d3602d0177aabd10527c5e5157a4f68ae4a12bdaf9387ffa60b78fd805b0";
    const TAG: &str = "26f800262da61ee3320ba0834ada6b9d";

    const KEY_SCHEDULE_SHARE_1: &str = "a1af1c27bdb5e523a4315fd2ff2af347d46b06e1565cd41039405a5a736e4544caa92b2f843cfa9d572dee94ac96085709473e314ebf5d139016159644f59e536c533ffb8585081c0610e3b3cd5f10a1b75c70fccaa67fa0104d746c2151423716b1929d7ff33896c39bd552ed9e2455eb884d77782033edc50bfcc5caa2ecdf9e5878e233c11ee2068caab62e54c51cf34c84db8f98c19d529792da4e3a9fd3dd0856fc86297d3e87a9726c23836ca1";
    const KEY_SCHEDULE_SHARE_2: &str = "4cd755f877594026205d836c25300fd301223cb6f3208542b378a9026b0c59e29fc1b879b1505fd8ebd47b46c9f71828f00f38860bdd471a4f479f5f65bddb9727f8453c0d2f073d0960d1d174e2fbf7d90fae66a2850302e31edd1b5cad3a481654916bb4039f8de426606cb4f10b27f05bb5a05e429a8a0306794f659aadee68ee7b58e1f9f002f21014909e1e0ae11d82710d96d7e6c83e34de0fe502b7e78453c2528319f4af18fb3db98db7a720";
    const KEY_SCHEDULE_SHARE_3: &str = "98dcf5b52456da3c8679bb54f1964a13c5a391cc5b2c85f0767d4010cfab19699ae9b2c304bd5072716dd3ad7f3c53cf7ed3c080f3282909a48fffb640cb730b2835361f5d7e70f9a17a38c57634d73eba26d7c869820a285cf8d55a1dde383a67996474ad2db613eecbd81bf03b02121c774f86471b0f3e6e024ef6ae63a72d489c28970d6b639483c0f82ec64d6fe98e0424c3a6d67b34a46656bc15fa92492a65ba15c997fb4b9b3027661494194f";

    static PORT_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn encrypt_aes_gcm_128() {
        // before running this test, make sure that the ports in p1/p2/p3.toml are free
        let guard = PORT_LOCK.lock().unwrap();

        let mut rng = thread_rng();
        let (r1, r2, r3) = secret_share_vector_ring(&mut rng, &MESSAGE_RING);

        let party_f = |i: usize, key_share: &'static str, message_share: (Vec<u64>, Vec<u64>)| {
            move || {
                let path = match i {
                    0 => "p1.toml",
                    1 => "p2.toml",
                    2 => "p3.toml",
                    _ => panic!()
                };
                let cli = Cli {
                    config: PathBuf::from(path),
                    active: false,
                    timeout: None,
                    threads: None,
                    command: Commands::Encrypt { mode: Mode::AesGcm128 }
                };

                let list_of_numbers = message_share.0.into_iter().zip(message_share.1).map(|(vi, vii)| format!("[{}, {}]", vi, vii)).join(", ");

                // prepare input arg
                let input_arg = format!("[{{\"key_share\": \"{}\", \"nonce\": \"{}\", \"associated_data\": \"{}\", \"message_share\": [{}]}}]", key_share, NONCE, AD, list_of_numbers);
                let mut output = BufWriter::new(Vec::new());
                execute_command(cli, input_arg.as_bytes(), &mut output);

                // check what is written to the output
                let buf = output.into_inner().unwrap();
                let res: Vec<EncryptResult> = serde_json::from_slice(&buf).unwrap();
                assert_eq!(res.len(), 1);

                assert!(res[0].ciphertext.is_some());
                assert!(res[0].error.is_none());
                let ciphertext = res.into_iter().next().unwrap().ciphertext.unwrap();
                
                assert_eq!(ciphertext.len(), CT.len() + TAG.len());
                assert_eq!(&ciphertext[..CT.len()], CT);
                assert_eq!(&ciphertext[CT.len()..], TAG);
            }
        };

        let h1 = thread::spawn(party_f(0, KEY_SHARE_1, (r1.clone(), r2.clone())));
        let h2 = thread::spawn(party_f(1, KEY_SHARE_2, (r2, r3.clone())));
        let h3 = thread::spawn(party_f(2, KEY_SHARE_3, (r3, r1)));

        h1.join().unwrap();
        h2.join().unwrap();
        h3.join().unwrap();

        drop(guard);        
    }

    #[test]
    fn encrypt_aes_gcm_128_ks() {
        // before running this test, make sure that the ports in p1/p2/p3.toml are free
        let guard = PORT_LOCK.lock().unwrap();

        let mut rng = thread_rng();
        let (r1, r2, r3) = secret_share_vector_ring(&mut rng, &MESSAGE_RING);

        let party_f = |i: usize, key_schedule_share: &'static str, message_share: (Vec<u64>, Vec<u64>)| {
            move || {
                let path = match i {
                    0 => "p1.toml",
                    1 => "p2.toml",
                    2 => "p3.toml",
                    _ => panic!()
                };
                let cli = Cli {
                    config: PathBuf::from(path),
                    active: false,
                    timeout: None,
                    threads: None,
                    command: Commands::Encrypt { mode: Mode::AesGcm128 }
                };

                let list_of_numbers = message_share.0.into_iter().zip(message_share.1).map(|(vi, vii)| format!("[{}, {}]", vi, vii)).join(", ");

                // prepare input arg
                let input_arg = format!("[{{\"key_schedule_share\": \"{}\", \"nonce\": \"{}\", \"associated_data\": \"{}\", \"message_share\": [{}]}}]", key_schedule_share, NONCE, AD, list_of_numbers);
                let mut output = BufWriter::new(Vec::new());
                execute_command(cli, input_arg.as_bytes(), &mut output);

                // check what is written to the output
                let buf = output.into_inner().unwrap();
                let res: Vec<EncryptResult> = serde_json::from_slice(&buf).unwrap();
                assert_eq!(res.len(), 1);

                assert!(res[0].ciphertext.is_some());
                assert!(res[0].error.is_none());
                let ciphertext = res.into_iter().next().unwrap().ciphertext.unwrap();
                
                assert_eq!(ciphertext.len(), CT.len() + TAG.len());
                assert_eq!(&ciphertext[..CT.len()], CT);
                assert_eq!(&ciphertext[CT.len()..], TAG);
            }
        };

        let h1 = thread::spawn(party_f(0, KEY_SCHEDULE_SHARE_1, (r1.clone(), r2.clone())));
        let h2 = thread::spawn(party_f(1, KEY_SCHEDULE_SHARE_2, (r2, r3.clone())));
        let h3 = thread::spawn(party_f(2, KEY_SCHEDULE_SHARE_3, (r3, r1)));

        h1.join().unwrap();
        h2.join().unwrap();
        h3.join().unwrap();

        drop(guard);        
    }

    fn additive_share_to_string(v: Vec<RssShare<GF8>>) -> String {
        let x = v.into_iter().map(|rss| rss.si.0).collect_vec();
        hex::encode(x)
    }

    #[test]
    fn encrypt_aes_gcm_128_ks_batched() {
        const BATCH_SIZE: usize = 64;

        // before running this test, make sure that the ports in p1/p2/p3.toml are free
        let guard = PORT_LOCK.lock().unwrap();

        let mut rng = thread_rng();
        let plaintexts = (0..BATCH_SIZE).map(|_| rng.gen::<[u64; 5]>() ).collect_vec();
        let mut r1 = Vec::new();
        let mut r2 = Vec::new();
        let mut r3 = Vec::new();
        for i in 0..BATCH_SIZE {
            let (ri1, ri2, ri3) = secret_share_vector_ring(&mut rng, &plaintexts[i]);
            r1.push((ri1.clone(), ri2.clone()));
            r2.push((ri2, ri3.clone()));
            r3.push((ri3, ri1));
        }

        let nonces = (0..BATCH_SIZE).map(|_| rng.gen::<[u8; 12]>() ).collect_vec();
        let keys = (0..BATCH_SIZE).map(|_| rng.gen::<[u8; 16]>() ).collect_vec();
        let mut ks1 = Vec::new();
        let mut ks2 = Vec::new();
        let mut ks3 = Vec::new();
        keys.iter().for_each(|key| {
            let ks = aes::test::aes128_keyschedule_plain(key.clone()).into_iter()
                // transpose the round key because `aes128_keyschedule_plain` returns column-first
                // but we expect row-first
                .map(|k| transpose(k))
                .collect_vec();
            let flat_ks = ks.into_iter().flatten().map(|x| GF8(x)).collect_vec();
            let (ksi1, ksi2, ksi3) = secret_share_vector(&mut rng, flat_ks);
            ks1.push(additive_share_to_string(ksi1));
            ks2.push(additive_share_to_string(ksi2));
            ks3.push(additive_share_to_string(ksi3));
        });
        

        let party_f = |i: usize, key_schedule_shares: Vec<String>, message_shares: Vec<(Vec<u64>, Vec<u64>)>, nonces: Vec<[u8; 12]>| {
            move || {
                let path = match i {
                    0 => "p1.toml",
                    1 => "p2.toml",
                    2 => "p3.toml",
                    _ => panic!()
                };
                let cli = Cli {
                    config: PathBuf::from(path),
                    active: false,
                    timeout: None,
                    threads: None,
                    command: Commands::Encrypt { mode: Mode::AesGcm128 }
                };
                assert_eq!(key_schedule_shares.len(), message_shares.len());
                assert_eq!(key_schedule_shares.len(), nonces.len());

                let args = izip!(key_schedule_shares, message_shares, nonces).map(|(ks, msg, nonce)| {
                    let list_of_numbers = msg.0.into_iter().zip(msg.1).map(|(vi, vii)| format!("[{}, {}]", vi, vii)).join(", ");
                    let nonce = hex::encode(nonce);
                    format!("{{\"key_schedule_share\": \"{}\", \"nonce\": \"{}\", \"associated_data\": \"{}\", \"message_share\": [{}]}}", ks, nonce, AD, list_of_numbers)
                }).join(", ");

                // prepare input arg
                let input_arg = format!("[{}]", args);
                let mut output = BufWriter::new(Vec::new());
                execute_command(cli, input_arg.as_bytes(), &mut output);

                // check what is written to the output
                let buf = output.into_inner().unwrap();
                let res: Vec<EncryptResult> = serde_json::from_slice(&buf).unwrap();
                assert_eq!(res.len(), BATCH_SIZE);

                for i in 0..BATCH_SIZE {
                    assert!(res[i].ciphertext.is_some());
                    assert!(res[i].error.is_none());
                }
                res.into_iter().map(|r| r.ciphertext.unwrap()).collect_vec()
                
            }
        };

        let h1 = thread::spawn(party_f(0, ks1, r1, nonces.clone()));
        let h2 = thread::spawn(party_f(1, ks2, r2, nonces.clone()));
        let h3 = thread::spawn(party_f(2, ks3, r3, nonces.clone()));

        let res1 = h1.join().unwrap();
        let res2 = h2.join().unwrap();
        let res3 = h3.join().unwrap();

        drop(guard);        

        // check if the returned ciphertexts are the same and decrypt correctly to the desired plaintext
        assert_eq!(&res1, &res2);
        assert_eq!(&res2, &res3);

        for (key, nonce, ct, expected_pt) in izip!(keys, nonces, res1, plaintexts) {
            let ct = hex::decode(ct).unwrap();
            let ad = hex::decode(AD).unwrap();
            let decrypted = aes128_gcm_dec_plain(&key, &nonce, &ad, &ct);
            assert!(decrypted.is_some());
            let plaintext = decrypted.unwrap();
            assert_eq!(plaintext.len(), 8*5);
            let plaintext = plaintext.chunks_exact(8).map(|chunk| {
                let arr: [u8; 8] = chunk.try_into().unwrap();
                u64::from_le_bytes(arr)
            }).collect_vec();
            assert_eq!(plaintext, expected_pt);
        }
    }

    fn aes128_gcm_dec_plain(key: &[u8], iv: &[u8], ad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        let key = Key::<Aes128Gcm>::from_slice(key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::clone_from_slice(iv);
        let res = cipher.decrypt(&nonce, Payload {msg: ct, aad: &ad});
        res.ok()
    }

    fn transpose(k: [u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for i in 0..4 {
            for j in 0..4 {
                out[4*j+i] = k[4*i + j];
            }
        }
        out
    }

    //#[test] todo: implement malicius cut-and-choose for bool, then retry
    fn encrypt_aes_gcm_128_malicious() {
        // before running this test, make sure that the ports in p1/p2/p3.toml are free
        let guard = PORT_LOCK.lock().unwrap();

        let mut rng = thread_rng();
        let (r1, r2, r3) = secret_share_vector_ring(&mut rng, &MESSAGE_RING);

        let party_f = |i: usize, key_share: &'static str, message_share: (Vec<u64>, Vec<u64>)| {
            move || {
                let path = match i {
                    0 => "p1.toml",
                    1 => "p2.toml",
                    2 => "p3.toml",
                    _ => panic!()
                };
                let cli = Cli {
                    config: PathBuf::from(path),
                    active: true,
                    timeout: None,
                    threads: None,
                    command: Commands::Encrypt { mode: Mode::AesGcm128 }
                };

                let list_of_numbers = message_share.0.into_iter().zip(message_share.1).map(|(vi, vii)| format!("[{}, {}]", vi, vii)).join(", ");

                // prepare input arg
                let input_arg = format!("{{\"key_share\": \"{}\", \"nonce\": \"{}\", \"associated_data\": \"{}\", \"message_share\": [{}]}}", key_share, NONCE, AD, list_of_numbers);
                let mut output = BufWriter::new(Vec::new());
                execute_command(cli, input_arg.as_bytes(), &mut output);

                // check what is written to the output
                let buf = output.into_inner().unwrap();
                let res: EncryptResult = serde_json::from_slice(&buf).unwrap();

                assert!(res.ciphertext.is_some());
                assert!(res.error.is_none());
                let ciphertext = res.ciphertext.unwrap();
                
                assert_eq!(ciphertext.len(), CT.len() + TAG.len());
                assert_eq!(&ciphertext[..CT.len()], CT);
                assert_eq!(&ciphertext[CT.len()..], TAG);
            }
        };

        let h1 = thread::spawn(party_f(0, KEY_SHARE_1, (r1.clone(), r2.clone())));
        let h2 = thread::spawn(party_f(1, KEY_SHARE_2, (r2, r3.clone())));
        let h3 = thread::spawn(party_f(2, KEY_SHARE_3, (r3, r1)));

        h1.join().unwrap();
        h2.join().unwrap();
        h3.join().unwrap();

        drop(guard);        
    }

    #[test]
    fn decrypt_aes_gcm_128() {
        // before running this test, make sure that the ports in p1/p2/p3.toml are free
        let guard = PORT_LOCK.lock().unwrap();

        let party_f = |i: usize, key_share: &'static str| {
            move || {
                let path = match i {
                    0 => "p1.toml",
                    1 => "p2.toml",
                    2 => "p3.toml",
                    _ => panic!()
                };
                let cli = Cli {
                    config: PathBuf::from(path),
                    active: false,
                    timeout: None,
                    threads: None,
                    command: Commands::Decrypt { mode: Mode::AesGcm128 }
                };
                // prepare input arg
                let input_arg = format!("[{{\"key_share\": \"{}\", \"nonce\": \"{}\", \"associated_data\": \"{}\", \"ciphertext\": \"{}{}\"}}]", key_share, NONCE, AD, CT, TAG);
                let mut output = BufWriter::new(Vec::new());
                execute_command(cli, input_arg.as_bytes(), &mut output);
                // check what is written to the output
                let buf = output.into_inner().unwrap();
                let res: Vec<DecryptResult> = serde_json::from_slice(&buf).unwrap();
                assert_eq!(res.len(), 1);
                assert_eq!(None, res[0].tag_error);
                assert_eq!(None, res[0].error);
                assert!(res[0].message_share.is_some());
                res[0].message_share.clone().unwrap()
            }
        };
        let h1 = thread::spawn(party_f(0, KEY_SHARE_1));
        let h2 = thread::spawn(party_f(1, KEY_SHARE_2));
        let h3 = thread::spawn(party_f(2, KEY_SHARE_3));

        let share_1 = h1.join().unwrap();
        let share_2 = h2.join().unwrap();
        let share_3 = h3.join().unwrap();

        drop(guard);

        assert_eq!(MESSAGE_RING.len(), share_1.len());
        assert_eq!(MESSAGE_RING.len(), share_2.len());
        assert_eq!(MESSAGE_RING.len(), share_3.len());
        for (m, s1, s2, s3) in izip!(MESSAGE_RING, share_1, share_2, share_3) {
            // check consistent
            assert_eq!(s1.0, s3.1);
            assert_eq!(s1.1, s2.0);
            assert_eq!(s2.1, s3.0);
            assert_eq!(m, s1.0.overflowing_add(s2.0).0.overflowing_add(s3.0).0);
        }
    }

    #[test]
    fn decrypt_aes_gcm_128_ks() {
        // before running this test, make sure that the ports in p1/p2/p3.toml are free
        let guard = PORT_LOCK.lock().unwrap();

        let party_f = |i: usize, key_schedule_share: &'static str| {
            move || {
                let path = match i {
                    0 => "p1.toml",
                    1 => "p2.toml",
                    2 => "p3.toml",
                    _ => panic!()
                };
                let cli = Cli {
                    config: PathBuf::from(path),
                    active: false,
                    timeout: None,
                    threads: None,
                    command: Commands::Decrypt { mode: Mode::AesGcm128 }
                };
                // prepare input arg
                let input_arg = format!("[{{\"key_schedule_share\": \"{}\", \"nonce\": \"{}\", \"associated_data\": \"{}\", \"ciphertext\": \"{}{}\"}}]", key_schedule_share, NONCE, AD, CT, TAG);
                let mut output = BufWriter::new(Vec::new());
                execute_command(cli, input_arg.as_bytes(), &mut output);
                // check what is written to the output
                let buf = output.into_inner().unwrap();
                let res: Vec<DecryptResult> = serde_json::from_slice(&buf).unwrap();
                assert_eq!(res.len(), 1);
                assert_eq!(None, res[0].tag_error);
                assert_eq!(None, res[0].error);
                assert!(res[0].message_share.is_some());
                res[0].message_share.clone().unwrap()
            }
        };
        let h1 = thread::spawn(party_f(0, &KEY_SCHEDULE_SHARE_1));
        let h2 = thread::spawn(party_f(1, KEY_SCHEDULE_SHARE_2));
        let h3 = thread::spawn(party_f(2, KEY_SCHEDULE_SHARE_3));

        let share_1 = h1.join().unwrap();
        let share_2 = h2.join().unwrap();
        let share_3 = h3.join().unwrap();

        drop(guard);

        assert_eq!(MESSAGE_RING.len(), share_1.len());
        assert_eq!(MESSAGE_RING.len(), share_2.len());
        assert_eq!(MESSAGE_RING.len(), share_3.len());
        for (m, s1, s2, s3) in izip!(MESSAGE_RING, share_1, share_2, share_3) {
            // check consistent
            assert_eq!(s1.0, s3.1);
            assert_eq!(s1.1, s2.0);
            assert_eq!(s2.1, s3.0);
            assert_eq!(m, s1.0.overflowing_add(s2.0).0.overflowing_add(s3.0).0);
        }
    }

    #[test]
    fn decrypt_aes_gcm_128_ks_batched() {
        const BATCH_SIZE: usize = 64;

        // before running this test, make sure that the ports in p1/p2/p3.toml are free
        let guard = PORT_LOCK.lock().unwrap();

        let mut rng = thread_rng();
        let plaintexts = (0..BATCH_SIZE).map(|_| {
            let mut arr = [0u64; 187];
            (0..arr.len()).for_each(|i| arr[i] = rng.gen());
            arr
        } ).collect_vec();

        let nonces = (0..BATCH_SIZE).map(|_| rng.gen::<[u8; 12]>() ).collect_vec();
        let keys = (0..BATCH_SIZE).map(|_| rng.gen::<[u8; 16]>() ).collect_vec();
        let mut ks1 = Vec::new();
        let mut ks2 = Vec::new();
        let mut ks3 = Vec::new();
        keys.iter().for_each(|key| {
            let ks = aes::test::aes128_keyschedule_plain(key.clone()).into_iter()
                // transpose the round key because `aes128_keyschedule_plain` returns column-first
                // but we expect row-first
                .map(|k| transpose(k))
                .collect_vec();
            let flat_ks = ks.into_iter().flatten().map(|x| GF8(x)).collect_vec();
            let (ksi1, ksi2, ksi3) = secret_share_vector(&mut rng, flat_ks);
            ks1.push(additive_share_to_string(ksi1));
            ks2.push(additive_share_to_string(ksi2));
            ks3.push(additive_share_to_string(ksi3));
        });

        let ciphertexts = izip!(&plaintexts, &nonces, &keys).map(|(pt, nonce, key)| {
            let msg = pt.iter().flat_map(|ring_el| ring_el.to_le_bytes()).collect_vec();
            let (ct, tag)  = gcm::batch::test::aes128_gcm_enc_plain(&hex::encode(key), &hex::encode(nonce), AD, &hex::encode(msg));
            (ct, tag)
        }).collect_vec();
        

        let party_f = |i: usize, key_schedule_shares: Vec<String>, ciphertexts: Vec<(Vec<u8>, Vec<u8>)>, nonces: Vec<[u8; 12]>| {
            move || {
                let path = match i {
                    0 => "p1.toml",
                    1 => "p2.toml",
                    2 => "p3.toml",
                    _ => panic!()
                };
                let cli = Cli {
                    config: PathBuf::from(path),
                    active: false,
                    timeout: None,
                    threads: None,
                    command: Commands::Decrypt { mode: Mode::AesGcm128 }
                };
                assert_eq!(key_schedule_shares.len(), ciphertexts.len());
                assert_eq!(key_schedule_shares.len(), nonces.len());

                let args = izip!(key_schedule_shares, ciphertexts, nonces).map(|(ks, (ct, tag), nonce)| {
                    let nonce = hex::encode(nonce);
                    let ct = hex::encode(ct);
                    let tag = hex::encode(tag);
                    format!("{{\"key_schedule_share\": \"{}\", \"nonce\": \"{}\", \"associated_data\": \"{}\", \"ciphertext\": \"{}{}\"}}", ks, nonce, AD, ct, tag)
                }).join(", ");

                // prepare input arg
                let input_arg = format!("[{}]", args);
                let mut output = BufWriter::new(Vec::new());
                execute_command(cli, input_arg.as_bytes(), &mut output);

                // check what is written to the output
                let buf = output.into_inner().unwrap();
                let res: Vec<DecryptResult> = serde_json::from_slice(&buf).unwrap();
                assert_eq!(res.len(), BATCH_SIZE);

                for i in 0..BATCH_SIZE {
                    assert!(res[i].tag_error.is_none());
                    assert!(res[i].error.is_none());
                    assert!(res[i].message_share.is_some());
                }
                res.into_iter().map(|r| r.message_share.unwrap()).collect_vec()
                
            }
        };

        let h1 = thread::spawn(party_f(0, ks1, ciphertexts.clone(), nonces.clone()));
        let h2 = thread::spawn(party_f(1, ks2, ciphertexts.clone(), nonces.clone()));
        let h3 = thread::spawn(party_f(2, ks3, ciphertexts, nonces.clone()));

        let share1 = h1.join().unwrap();
        let share2 = h2.join().unwrap();
        let share3 = h3.join().unwrap();

        drop(guard);

        for (expected, share_1, share_2, share_3) in izip!(plaintexts, share1, share2, share3) {
            assert_eq!(expected.len(), share_1.len());
            assert_eq!(expected.len(), share_2.len());
            assert_eq!(expected.len(), share_3.len());

            for (m, s1, s2, s3) in izip!(expected, share_1, share_2, share_3) {
                // check consistent
                assert_eq!(s1.0, s3.1);
                assert_eq!(s1.1, s2.0);
                assert_eq!(s2.1, s3.0);
                assert_eq!(m, s1.0.overflowing_add(s2.0).0.overflowing_add(s3.0).0);
            }
        }
    }
}
