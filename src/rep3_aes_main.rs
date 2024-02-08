mod share;
mod party;
mod network;
mod gcm;
mod chida;

use std::{fmt::Display, io, path::PathBuf, str::FromStr, time::Duration};

use chida::ChidaParty;
use clap::{Parser, Subcommand};
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
    message_share: String,
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
    ciphertext: Option<String>,
    error: Option<String>,
}

struct EncryptParams {
    key_share: Vec<GF8>,
    nonce: Vec<u8>,
    associated_data: Vec<u8>,
    message_share: Vec<GF8>,
}

struct DecryptParams {
    key_share: Vec<GF8>,
    nonce: Vec<u8>,
    associated_data: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct DecryptResult {
    message_share: Option<String>,
    tag_error: Option<bool>,
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
        let message = try_decode_hex("message_share", args.message_share)?;
    
        Ok(Self {
            key_share: key_share.into_iter().map(|b| GF8(b)).collect(),
            nonce,
            associated_data: ad,
            message_share: message.into_iter().map(|b| GF8(b)).collect(),
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
    pub fn new_success(message: Vec<RssShare<GF8>>) -> Self {
        Self {
            message_share: Some(hex::encode(message.into_iter().map(|rss| rss.si.0).collect_vec())),
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

fn additive_shares_to_rss(party: &mut Party, shares: Vec<GF8>) -> MpcResult<Vec<RssShare<GF8>>> {
    let (k1, k2, k3) = chida::online::input_round(party, shares)?;
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

fn execute_command<R: io::Read, W: io::Write>(cli: Cli, input_arg_reader: R, output_writer: W) {
    let (party_index, config) = Config::from_file(&cli.config).unwrap();

    match cli.command {
        Commands::Encrypt { mode } => {
            let encrypt_args = parse_args_from_reader::<EncryptArgs,EncryptParams, _>(input_arg_reader).unwrap();
            match mode {
                Mode::AesGcm128 => {
                    return_to_writer(|| {
                        let connected = ConnectedParty::bind_and_connect(party_index, config, Some(Duration::from_secs_f32(1.0)))?;
                        let mut party = ChidaParty::setup(connected);
                        
                        let key_share = additive_shares_to_rss(party.inner_mut(), encrypt_args.key_share)?;
                        let message_share = additive_shares_to_rss(party.inner_mut(), encrypt_args.message_share)?;
                        let (mut tag, mut ct) = gcm::aes128_gcm_encrypt(party.inner_mut(), &encrypt_args.nonce, &key_share, &message_share, &encrypt_args.associated_data)?;
                        ct.append(&mut tag);
                        // open ct||tag
                        let ct_and_tag = chida::online::output_round(party.inner_mut(), &ct, &ct, &ct)?;
                        Ok(EncryptResult::new(ct_and_tag))
                    }, output_writer);
                }
            }  
        },
        Commands::Decrypt { mode } => {
            let decrypt_args = parse_args_from_reader::<DecryptArgs, DecryptParams, _>(input_arg_reader).unwrap();
            match mode {
                Mode::AesGcm128 => {
                    return_to_writer(|| {
                        let connected = ConnectedParty::bind_and_connect(party_index, config, Some(Duration::from_secs_f32(1.0)))?;
                        let mut party = ChidaParty::setup(connected);
                        let key_share = additive_shares_to_rss(party.inner_mut(), decrypt_args.key_share)?;
                        // split ciphertext and tag; tag is the last 16 bytes
                        let ctlen = decrypt_args.ciphertext.len();
                        let (ct, tag) = (&decrypt_args.ciphertext[..ctlen-16], &decrypt_args.ciphertext[ctlen-16..]);
                        let res = gcm::aes128_gcm_decrypt(party.inner_mut(), &decrypt_args.nonce, &key_share, ct, tag, &decrypt_args.associated_data, gcm::semi_honest_tag_check);
                        match res {
                            Ok(message_share) => Ok(DecryptResult::new_success(message_share)),
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

    use crate::{execute_command, Cli, Commands, DecryptResult, EncryptResult, Mode};


    const KEY_SHARE_1: &str = "76c2488bd101fd2999a922d351707fcf";
    const KEY_SHARE_2: &str = "014a3b40b4e7b77f600e6bdacd1c50af";
    const KEY_SHARE_3: &str = "022ccfa18b5c356ffbb22ee3b7e099e7";
    const NONCE: &str = "1b64f561ab1ce7905b901ee5";
    const AD: &str = "02a811774dcde13b8760748a76db74a1682a28838f1de43a39ccca945ce8795e918ad6de57b719df";
    const MESSAGE: &str = "188d698e69dd2fd1085754977539d1ae059b4361";
    const MESSAGE_SHARE_1: &str = "a3c559badbea203a918f93c2584f8f1f80374841";
    const MESSAGE_SHARE_2: &str = "66ec85c67bf2bc55380fe9f0bd49e2d5c504760f";
    const MESSAGE_SHARE_3: &str = "dda4b5f2c9c5b3bea1d72ea5903fbc6440a87d2f";
    const CT: &str = "498dbaee28d1fe08eb893027043cabc2680ccb45";
    const TAG: &str = "fbbf997f34f293605e440ebf6401f9ab";

    static PORT_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn encrypt_aes_gcm_128() {
        // before running this test, make sure that the ports in p1/p2/p3.toml are free
        let guard = PORT_LOCK.lock().unwrap();

        let party_f = |i: usize, key_share: &'static str, message_share: &'static str| {
            move || {
                let path = match i {
                    0 => "p1.toml",
                    1 => "p2.toml",
                    2 => "p3.toml",
                    _ => panic!()
                };
                let cli = Cli {
                    config: PathBuf::from(path),
                    command: Commands::Encrypt { mode: Mode::AesGcm128 }
                };

                // prepare input arg
                let input_arg = format!("{{\"key_share\": \"{}\", \"nonce\": \"{}\", \"associated_data\": \"{}\", \"message_share\": \"{}\"}}", key_share, NONCE, AD, message_share);
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

        let h1 = thread::spawn(party_f(0, KEY_SHARE_1, MESSAGE_SHARE_1));
        let h2 = thread::spawn(party_f(1, KEY_SHARE_2, MESSAGE_SHARE_2));
        let h3 = thread::spawn(party_f(2, KEY_SHARE_3, MESSAGE_SHARE_3));


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

        let v1 = hex::decode(share_1).unwrap();
        let v2 = hex::decode(share_2).unwrap();
        let v3 = hex::decode(share_3).unwrap();
        assert_eq!(v1.len(), v2.len());
        assert_eq!(v1.len(), v3.len());
        let message = izip!(v1, v2, v3).map(|(b1, b2, b3)| b1 ^ b2 ^ b3).collect_vec();
        assert_eq!(hex::decode(MESSAGE).unwrap(), message);
    }
}