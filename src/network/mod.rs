use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::time::{Duration, Instant};
use std::{io, fs, thread};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig, ClientConnection, ServerConnection, StreamOwned};
use serde::Deserialize;

mod non_blocking;
mod receiver;
pub mod task;

pub struct Config {
    player_addr: Vec<Ipv4Addr>,
    player_ports: Vec<u16>,
    my_cert: CertificateDer<'static>,
    my_key: PrivateKeyDer<'static>,
    player_certs: Vec<CertificateDer<'static>>,
}

impl Config {
    pub fn new(player_addr: Vec<Ipv4Addr>, player_ports: Vec<u16>, player_certs: Vec<CertificateDer<'static>>, my_cert: CertificateDer<'static>, my_key: PrivateKeyDer<'static>) -> Self {
        Self {
            player_addr,
            player_ports,
            my_cert,
            my_key,
            player_certs
        }
    }

    fn load_certificate_from_file(config_path: &Path, cert_path: &Path) -> io::Result<CertificateDer<'static>> {
        let mut path = PathBuf::from(config_path);
        path.push(cert_path);
        let mut reader = BufReader::new(File::open(&path)?);
        let cert: io::Result<Vec<_>> = rustls_pemfile::certs(&mut reader).collect();
        let cert = cert?;
        if cert.len() != 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Found {} certificates in {}, expected 1", cert.len(), path.display())));
        }
        return Ok(cert[0].clone());
    }

    fn load_private_key_from_file(config_path: &Path, key_path: &Path) -> io::Result<PrivateKeyDer<'static>> {
        let mut path = PathBuf::from(config_path);
        path.push(key_path);
        let mut reader = BufReader::new(File::open(&path)?);
        let key = rustls_pemfile::private_key(&mut reader)?;
        return key.ok_or(io::Error::new(io::ErrorKind::InvalidData, format!("Invalid private key in {}", path.display())));
    }

    // returns party index and config
    pub fn from_file(path: &Path) -> Result<(usize, Self), io::Error> {
        let file_content = fs::read_to_string(path)?;
        let parsed_config: SerializedConfig = toml::from_str(&file_content)
            .map_err(|ser| io::Error::new(io::ErrorKind::InvalidData, format!("{}", ser)))?;
        // check party index is valid 1 <= party_index <= 3
        if parsed_config.party_index < 1 || parsed_config.party_index > 3 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Invalid party_index: {}; must be 1 <= party_index <= 3", parsed_config.party_index)));
        }
        let player_addr = vec![parsed_config.p1.address, parsed_config.p2.address, parsed_config.p3.address];
        let player_ports = vec![parsed_config.p1.port, parsed_config.p2.port, parsed_config.p3.port];

        let default_parent_dir = PathBuf::from("./");
        let parent_dir = path.parent().unwrap_or(&default_parent_dir);
        // load all certificates
        let player_certs = vec![
            Self::load_certificate_from_file(parent_dir, &PathBuf::from(parsed_config.p1.certificate))?,
            Self::load_certificate_from_file(parent_dir, &PathBuf::from(parsed_config.p2.certificate))?,
            Self::load_certificate_from_file(parent_dir, &PathBuf::from(parsed_config.p3.certificate))?,
        ];
        let key_path = match parsed_config.party_index {
            1 => parsed_config.p1.private_key,
            2 => parsed_config.p2.private_key,
            3 => parsed_config.p3.private_key,
            _ => unreachable!()
        }.ok_or(io::Error::new(io::ErrorKind::InvalidData, format!("No \"private_key\" field found in section [p{}]", parsed_config.party_index)))?;
        let key = Self::load_private_key_from_file(parent_dir, &PathBuf::from(key_path))?;
        let my_cert = player_certs[parsed_config.party_index-1].clone();
        Ok((parsed_config.party_index-1, Self::new(player_addr, player_ports, player_certs, my_cert, key)))
    }
}

#[derive(Deserialize)]
struct SerializedPartyConfig {
    pub address: Ipv4Addr,
    pub port: u16,
    pub certificate: String,
    pub private_key: Option<String>,
}
#[derive(Deserialize)]
struct SerializedConfig {
    pub party_index: usize,
    pub p1: SerializedPartyConfig,
    pub p2: SerializedPartyConfig,
    pub p3: SerializedPartyConfig
}

pub struct CommChannel {
    /// to which player (0,1,2)
    pub to: usize,
    stream: Option<Stream>,
    bytes_sent: u64,
    bytes_received: u64,
    rounds: usize,
}

pub enum Stream {
    Client(rustls::StreamOwned<ClientConnection, TcpStream>),
    Server(rustls::StreamOwned<ServerConnection, TcpStream>),
}

impl Stream {
    pub fn as_mut_write(&mut self) -> &mut dyn io::Write {
        match self {
            Stream::Client(stream) => stream,
            Stream::Server(stream) => stream,
        }
    }

    pub fn as_mut_read(&mut self) -> &mut dyn io::Read {
        match self {
            Stream::Client(stream) => stream,
            Stream::Server(stream)=> stream,
        }
    }

    pub fn complete_handshake_blocking(&mut self) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.conn.complete_io(&mut stream.sock).map(|_|()),
            Self::Server(stream) => stream.conn.complete_io(&mut stream.sock).map(|_|()),
        }
    }
}

pub struct CreatedParty {
    i: usize,
    server_socket: TcpListener,
}

pub struct ConnectedParty {
    pub i: usize,
    pub config: Config,
    /// Channel to player i+1
    pub comm_next: CommChannel,
    /// Channel to player i-1
    pub comm_prev: CommChannel,
}

impl ConnectedParty {
    pub fn bind_and_connect(i: usize, config: Config, timeout: Option<Duration>) -> io::Result<Self> {
        let party = CreatedParty::bind(i, std::net::IpAddr::V4(config.player_addr[i]), config.player_ports[i])?;
        CreatedParty::connect(party, config, timeout)
    }
}

impl CreatedParty {
    pub fn bind(i: usize, addr: IpAddr, port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind((addr, port))?;
        Ok(Self {
            i,
            server_socket: listener,
        })
    }

    #[cfg(test)]
    pub fn port(&self) -> io::Result<u16> {
        self.server_socket
            .local_addr()
            .map(|socket_addr| socket_addr.port())
    }

    pub fn connect(self, config: Config, timeout: Option<Duration>) -> io::Result<ConnectedParty> {
        let (next, prev) = match self.i {
            0 => {
                // (1)
                let mut server01 = CommChannel::new_server(&config, self.server_socket, 1).unwrap();
                server01.stream.as_mut().unwrap().complete_handshake_blocking()?;
                // println!("P1-P2 connected");
                // (2)
                // println!("P1 connecting to P3");
                let mut client02 = CommChannel::new_client(&config, 2, timeout).unwrap();
                client02.stream.as_mut().unwrap().complete_handshake_blocking()?;
                // println!("P1-P3 connected");
                (server01, client02)
            }
            1 => {
                // (1)
                // println!("P2 connecting to P1");
                let mut client01 = CommChannel::new_client(&config, 0, timeout).unwrap();
                client01.stream.as_mut().unwrap().complete_handshake_blocking()?;
                // println!("P2-P1 connected");
                // (3)
                // println!("P2 waiting for P3 to connect");
                let mut server12 = CommChannel::new_server(&config, self.server_socket, 2).unwrap();
                server12.stream.as_mut().unwrap().complete_handshake_blocking()?;
                // println!("P2-P3 connected");
                (server12, client01)
            }
            2 => {
                // (2)
                // println!("P3 waiting for P1 to connect");
                let mut server02 = CommChannel::new_server(&config, self.server_socket, 0).unwrap();
                server02.stream.as_mut().unwrap().complete_handshake_blocking()?;
                // println!("P3-P1 connected");
                // (3)
                // println!("P3 connecting to P2");
                let mut client12 = CommChannel::new_client(&config, 1, timeout).unwrap();
                client12.stream.as_mut().unwrap().complete_handshake_blocking()?;
                // println!("P3-P2 connected");
                (server02, client12)
            }
            _ => unreachable!(),
        };

        let comm_next = next;
        let comm_prev = prev;
        Ok(ConnectedParty {
            i: self.i,
            config,
            comm_next,
            comm_prev,
        })
    }
}

impl CommChannel {
    fn new_server_config(client_cert: &CertificateDer, my_cert: &CertificateDer<'static>, my_key: PrivateKeyDer<'static>) -> ServerConfig {
        let mut root_store = RootCertStore::empty();
        root_store.add(client_cert.clone()).unwrap();
        let client_verifier = WebPkiClientVerifier::builder(root_store.into())
        .build().unwrap();
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![my_cert.clone()], my_key)
        .unwrap()
    }

    fn new_client_config(server_cert: &CertificateDer, my_cert: &CertificateDer<'static>, my_key: PrivateKeyDer<'static>) -> ClientConfig {
        let mut root_store = RootCertStore::empty();
        root_store.add(server_cert.clone()).unwrap();
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(root_store)
        .with_client_auth_cert(vec![my_cert.clone()], my_key)
        .unwrap()
        .into()
    }

    fn new(to: usize, stream: Stream) -> Self {
        Self {
            to,
            stream: Some(stream),
            bytes_sent: 0,
            bytes_received: 0,
            rounds: 0,
        }
    }

    pub fn new_server(config: &Config, server_socket: TcpListener, to: usize) -> io::Result<Self> {
        // println!("Accepting connections from port {}", server_socket.local_addr().unwrap().port());
        let (sock, _) = server_socket.accept()?;
        let conn = ServerConnection::new(Self::new_server_config(&config.player_certs[to], &config.my_cert, config.my_key.clone_key()).into())
        .expect("Cannot create ServerConnection");
        // println!("Accepting connections from port {} done", server_socket.local_addr().unwrap().port());
        Ok(Self::new(to, Stream::Server(StreamOwned::new(conn, sock))))
    }

    pub fn new_client(config: &Config, to: usize, timeout: Option<Duration>) -> io::Result<Self> {
        // println!("Connecting to {}", config.player_ports[to]);
        let addr: std::net::Ipv4Addr = config.player_addr[to];
        let port = config.player_ports[to];
        // try to connect in a loop until timeout is reached (if timeout is None, try forever)
        let start_time = Instant::now();
        let sock = {
            loop {
                match TcpStream::connect((addr, port)) {
                    Ok(sock) => break Ok(sock),
                    Err(io_err) => if io_err.kind() == ErrorKind::ConnectionRefused {
                        // try again
                    }else{
                        break Err(io_err)
                    }
                }
                // check time
                if let Some(timeout) = timeout {
                    if start_time.elapsed() >= timeout {
                        break Err(io::Error::new(ErrorKind::NotConnected, format!("Cannot connect to {}:{} after {}s", addr, port, timeout.as_secs_f32())));
                    }
                }
                // sleep a bit
                thread::sleep(Duration::from_millis(100));
            }
        }?;
        let conn = ClientConnection::new(
            Self::new_client_config(&config.player_certs[to], &config.my_cert, config.my_key.clone_key()).into(), 
            ServerName::IpAddress(rustls::pki_types::IpAddr::V4(addr.into()))
        )
        .expect("Cannot create ClientConnection");
        // println!("Connecting to {} done", config.player_ports[to]);
        Ok(Self::new(to, Stream::Client(StreamOwned::new(conn, sock))))
    }

    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.bytes_sent += bytes.len() as u64;
        self.rounds += 1;
        self.stream.as_mut().expect("Cannot write anymore. Connection was closed").as_mut_write().write_all(bytes)
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        self.bytes_received += buffer.len() as u64;
        self.rounds += 1;
        self.stream.as_mut().expect("Cannot read anymore. Connection was closed").as_mut_read().read_exact(buffer)
    }

    pub fn get_bytes_sent(&self) -> u64 {
        return self.bytes_sent;
    }

    pub fn get_bytes_received(&self) -> u64 {
        return self.bytes_received;
    }

    pub fn get_rounds(&self) -> usize {
        return self.rounds;
    }

    pub fn teardown(&mut self) {
        self.stream = None // drop the connection; this will close the socket
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, net::{TcpListener, TcpStream}, io::{Read, Write}, time::Instant};


    // #[test]
    fn tcp_single_thread_throughput() {
        const BUF_SIZES: [usize; 4] = [1024, 2048, 4096, 8192];
        const DATA: usize = 1_000_000_000;
        let server = thread::spawn(|| {
            let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            for buf_size in BUF_SIZES {
                let start = Instant::now();
                let mut buf = vec![0; buf_size];
                let mut remaining = DATA as i64;
                while remaining > 0 {
                    stream.read_exact(&mut buf).unwrap();
                    remaining -= buf_size as i64;
                }
                let time = start.elapsed();
                let s = time.as_secs_f64();
                println!("Server: [{}] {} byte/sec", buf_size, (DATA as f64)/s);
            }
        });

        let client = thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
            for buf_size in BUF_SIZES {
                let start = Instant::now();
                let buf = vec![0; buf_size];
                let mut remaining = DATA as i64;
                while remaining > 0 {
                    stream.write_all(&buf).unwrap();
                    remaining -= buf_size as i64;
                }
                let time = start.elapsed();
                let s = time.as_secs_f64();
                println!("Client: [{}] {} byte/sec", buf_size, (DATA as f64)/s);
            }
        });

        server.join().unwrap();
        client.join().unwrap();
    }
}