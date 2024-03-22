#![allow(dead_code)]
mod share;
mod party;
mod network;
mod gcm;
mod chida;
mod conversion;
mod aes;
mod furukawa;

use std::{fmt::Display, io, path::PathBuf, str::FromStr, time::Duration};

use aes::{ComputeInverse, ComputePhase, InputPhase, MPCProtocol, OutputPhase, PreProcessing};
use chida::ChidaParty;
use clap::{Parser, Subcommand};
use conversion::{convert_boolean_to_ring, convert_ring_to_boolean, Z64Bool};
use furukawa::FurukawaGCMParty;
use gcm::gf128::GF128;
use itertools::{izip, Itertools};
use network::{Config, ConnectedParty};
use party::{error::{MpcError, MpcResult}, Party};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use share::{field::GF8, RssShare};

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
struct EncryptArgs {
    key_share: String,
    nonce: String,
    associated_data: String,
    message_share: Vec<(u64,u64)>,
}

#[derive(Deserialize)]
struct DecryptArgs {
    key_share: String,
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

struct EncryptParams {
    key_share: Vec<GF8>,
    nonce: Vec<u8>,
    associated_data: Vec<u8>,
    message_share: Vec<(u64,u64)>,
}

struct DecryptParams {
    key_share: Vec<GF8>,
    nonce: Vec<u8>,
    associated_data: Vec<u8>,
    ciphertext: Vec<u8>,
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

fn try_decode_hex(field: &str, arg: String) -> Result<Vec<u8>> {
    hex::decode(arg).map_err(|hex_err| Rep3AesError::ParseError(format!("when reading parameter field '{}': {}", field, hex_err)))
}

impl TryFrom<EncryptArgs> for EncryptParams {
    type Error = Rep3AesError;
    fn try_from(args: EncryptArgs) -> Result<Self> {
        let key_share = try_decode_hex("key_share", args.key_share)?;
        let nonce = try_decode_hex("nonce", args.nonce)?;
        let ad = try_decode_hex("associated_data", args.associated_data)?;
    
        Ok(Self {
            key_share: key_share.into_iter().map(|b| GF8(b)).collect(),
            nonce,
            associated_data: ad,
            message_share: args.message_share,
        })
    }
}

impl TryFrom<DecryptArgs> for DecryptParams {
    type Error = Rep3AesError;
    fn try_from(args: DecryptArgs) -> Result<Self> {
        let key_share = try_decode_hex("key_share", args.key_share)?;
        let nonce = try_decode_hex("nonce", args.nonce)?;
        let ad = try_decode_hex("associated_data", args.associated_data)?;
        let ct = try_decode_hex("ciphertext", args.ciphertext)?;

        Ok(Self {
            key_share: key_share.into_iter().map(|b| GF8(b)).collect(),
            nonce,
            associated_data: ad,
            ciphertext: ct,
        })
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

impl From<Rep3AesError> for EncryptResult {
    fn from(value: Rep3AesError) -> Self {
        Self {
            ciphertext: None,
            error: Some(value.to_string())
        }
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

impl From<Rep3AesError> for DecryptResult {
    fn from(value: Rep3AesError) -> Self {
        Self {
            message_share: None,
            tag_error: None,
            error: Some(value.to_string()),
        }
    }
}

fn parse_args_from_reader<Args: DeserializeOwned, Params: TryFrom<Args, Error = Rep3AesError>, R: io::Read>(reader: R) -> Result<Params> {
    let args: Args = serde_json::from_reader(reader).map_err(|serde_err| Rep3AesError::ParseError(format!("When parsing EncryptArgs: {}", serde_err)))?;
    Params::try_from(args)
}

fn return_to_writer<T: Serialize + From<Rep3AesError>, W: io::Write, F: FnOnce()->Result<T>>(compute: F, writer: W) {
    match compute() {
        Ok(msg) => serde_json::to_writer(writer, &msg).unwrap(),
        Err(err) => serde_json::to_writer::<_, T>(writer, &err.into()).unwrap(),
    }
}

fn additive_shares_to_rss<Protocol: InputPhase<GF8>>(party: &mut Protocol, shares: Vec<GF8>) -> MpcResult<Vec<RssShare<GF8>>> {
    let (k1, k2, k3) = party.input_round(&shares)?;
    let key_share_rss: Vec<_> = izip!(k1, k2, k3)
        .map(|(k1, k2, k3)| k1 + k2 + k3)
        .collect();
    Ok(key_share_rss)
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

fn aes_gcm_128_enc<Protocol: PreProcessing<Z64Bool> + PreProcessing<GF8> + PreProcessing<GF128> + InputPhase<GF8> + ComputePhase<Z64Bool> + MPCProtocol + ComputePhase<GF8> + ComputeInverse<GF8> + ComputePhase<GF128> + OutputPhase<GF8>>(party: &mut Protocol, party_index: usize, encrypt_args: EncryptParams) -> Result<EncryptResult> {
    let key_share = additive_shares_to_rss(party, encrypt_args.key_share)?;
    let (message_share_si, message_share_sii): (Vec<_>, Vec<_>) = encrypt_args.message_share.into_iter().unzip();
    PreProcessing::<Z64Bool>::pre_processing(party, 2*64*message_share_si.len())?;
    let (mul_gf8, mul_gf128) = gcm::get_required_mult_for_aes128_gcm(encrypt_args.associated_data.len(), message_share_si.len()*8);
    PreProcessing::<GF8>::pre_processing(party, mul_gf8)?;
    PreProcessing::<GF128>::pre_processing(party, mul_gf128)?;
    let message_share = convert_ring_to_boolean(party, party_index, &message_share_si, &message_share_sii)?;
    let (mut tag, mut ct) = gcm::aes128_gcm_encrypt(party, &encrypt_args.nonce, &key_share, &message_share, &encrypt_args.associated_data)?;
    ct.append(&mut tag);
    // open ct||tag
    let ct_and_tag = party.output_to(&ct, &ct, &ct)?;
    party.finalize()?;
    Ok(EncryptResult::new(ct_and_tag))
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
                        if cli.active {
                            let mut party = FurukawaGCMParty::setup(connected)?;
                            let party_index = party.inner_mut().i;
                            aes_gcm_128_enc(&mut party, party_index, encrypt_args)
                        }else{
                            let mut party = ChidaParty::setup(connected)?;
                            let party_index = party.inner_mut().i;
                            aes_gcm_128_enc(&mut party, party_index, encrypt_args)
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
                        let mut party = ChidaParty::setup(connected)?;
                        let key_share = additive_shares_to_rss(&mut party, decrypt_args.key_share)?;
                        // split ciphertext and tag; tag is the last 16 bytes
                        let ctlen = decrypt_args.ciphertext.len();
                        let (ct, tag) = (&decrypt_args.ciphertext[..ctlen-16], &decrypt_args.ciphertext[ctlen-16..]);
                        let res = gcm::aes128_gcm_decrypt(&mut party, &decrypt_args.nonce, &key_share, ct, tag, &decrypt_args.associated_data, gcm::semi_honest_tag_check);
                        match res {
                            Ok(message_share) => {
                                // now run b2a conversion
                                let (ring_shares_si, ring_shares_sii) = convert_boolean_to_ring(&mut party, party_index, message_share.into_iter())?;
                                let ring_shares = ring_shares_si.into_iter().zip(ring_shares_sii).collect();
                                Ok(DecryptResult::new_success(ring_shares))
                            },
                            Err(MpcError::OperationFailed(_)) => Ok(DecryptResult::new_tag_error()),
                            Err(err) => Err(err.into()),
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

    use itertools::{izip, Itertools};
    use rand::thread_rng;

    use crate::{conversion::test::secret_share_vector_ring, execute_command, Cli, Commands, DecryptResult, EncryptResult, Mode};


    const KEY_SHARE_1: &str = "76c2488bd101fd2999a922d351707fcf";
    const KEY_SHARE_2: &str = "014a3b40b4e7b77f600e6bdacd1c50af";
    const KEY_SHARE_3: &str = "022ccfa18b5c356ffbb22ee3b7e099e7";
    const NONCE: &str = "18a04c8f66bdec6a74513af6";
    const AD: &str = "34643134373530652d323335332d346433302d616332622d65383933383138303736643230820122300d06092a864886f70d01010105000382010f003082010a0282010100a78746c19361dbff7c3c7a3d1b9cdb76dfad38e69bf456184af575244fdb0c7770358dbf637bdeea05fc50d310b5ed1a61859f66a38aa1ede42c5fb2891b640aba34a6a9ba906e414337f8e81573fc6923f3fa6c1b7538ea041d109864d4183f237f882e5ee4af214311d7db298e9da2a00bbb04c44539a0fd86468c60c30a699bc8d41bbbef75ed63a4d523776af621f9b3b00c27c36aca23a290e293688351fdfb919c907b3758acc9b9e34368972759863aa90f76c04fc522d731d6cf1779069e4e07254bafd9c5f79c249a7c5fbad43f3ddc4d3d5429260d91d5ed4506f6aa380e74ee56a636f7a6157992497f18b25d963fe2364162ac08f685df5a5709020301000130820122300d06092a864886f70d01010105000382010f003082010a0282010100cccb626ab39b644ab7c9bb6785616f1689e3999bdfcb64f5575a77d1af8ad8e371e4f43bdb8d99174fce4f6cf0cb54738362b64f4e9089adaec2557294a7c906c8549b2c91db6c1a569a29c61d03a196887e3bf40bb07302aa05561befa7b3ffd2c295fb538944381943f1b03e046eeb10e9e5b67c1773185a85f06aa9d558cd61f407f2084174cefd2ae8e50a89b97ca069f201bd4662f7715d83fbdcb9d02590512355a0e0a67f6a991a77ad715936fa80bc60111727ecb56e735e9c2caf90247d74b8aba82cb0222cfed640fde34a46d507da98b9ee40987347fa7d56f94f3474cb7b3fe780b4dfe925587e96d5606d1fe4dccb4b8054d532bdaee93bb9bf020301000130820122300d06092a864886f70d01010105000382010f003082010a0282010100d8ae66dded6a8d8e7daa8ed8fe4e03b6e107db3b23d81b789a885b804def98a38fd826f93489438dcc694400e5132600a9d8ba16df6662e609eeac10ad803fbc31982d408118dc5478802cd968e61787489c9f2d85bd2d1c24a5c3883226b61d9b0ea74ca89a7d46b363b635e349711bf15c375ee18dc50fd3efac3f231564b4ea06071fabdd1c183eb02540bc9f7eadf61753f2538fbbd6b00dc85a627d5d971649c8014b12a3903c2ad739084fceee2b244cc2eb10414ec4ef402243ff36d3bc663ae14e18d446a851ba38a8aedac539a2f89cfd0b2e98f74e924b2f9d4d96d26cce499133b95e2151f4194f50d1701ac76750041a4de7125bad7a80fd91a7020301000132383334316630372d323836612d343736312d386664652d3232306237626533643463634865617274626561742d44656d6f2d31";
    const MESSAGE_RING: [u64;5] = [6149648890722733960, 3187258121416518661, 3371553381890320898, 1292927509834657361, 1216049165532225112];
    const CT: &str = "df9776ec3ce5fbace5b8d3602d0177aabd10527c5e5157a4f68ae4a12bdaf9387ffa60b78fd805b0";
    const TAG: &str = "26f800262da61ee3320ba0834ada6b9d";

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
                    command: Commands::Decrypt { mode: Mode::AesGcm128 }
                };
                // prepare input arg
                let input_arg = format!("{{\"key_share\": \"{}\", \"nonce\": \"{}\", \"associated_data\": \"{}\", \"ciphertext\": \"{}{}\"}}", key_share, NONCE, AD, CT, TAG);
                let mut output = BufWriter::new(Vec::new());
                execute_command(cli, input_arg.as_bytes(), &mut output);
                // check what is written to the output
                let buf = output.into_inner().unwrap();
                let res: DecryptResult = serde_json::from_slice(&buf).unwrap();
                assert_eq!(None, res.tag_error);
                assert_eq!(None, res.error);
                assert!(res.message_share.is_some());
                res.message_share.unwrap()
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
}