//! This module provides the networking functionality.
//! 
//! That is the module essentially provides pair-wise TLS connections between all parties.
//! 
//! TODO: Check the doc strings in this file
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde::Deserialize;
use std::borrow::Borrow;
use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{fs, io, thread};

mod non_blocking;
mod receiver;
pub mod task;

pub use receiver::{NetSliceReceiver, NetVectorReceiver};

pub trait NetSerializable: Sized {
    /// The field size in byte
    // const NBYTES: usize;

    /// Returns the size in byte of a serialization of n_elements many elements
    fn serialized_size(n_elements: usize) -> usize;

    /// The field size in bits
    // const NBITS: usize = 8 * Self::NBYTES;

    // /// Returns if the value is zero
    // fn is_zero(&self) -> bool;

    /// Serializes the elements
    fn as_byte_vec(it: impl IntoIterator<Item = impl Borrow<Self>>, len: usize) -> Vec<u8>;

    /// Serializes the elements
    fn as_byte_vec_slice(elements: &[Self]) -> Vec<u8>;

    /// Deserializes elements from a byte vector
    fn from_byte_vec(v: Vec<u8>, len: usize) -> Vec<Self>;

    /// Deserializes elements from a byte vector into a slice
    fn from_byte_slice(v: Vec<u8>, dest: &mut [Self]);
}

/// The network configuration of a party.
pub struct Config {
    player_addr: Vec<Ipv4Addr>,
    player_ports: Vec<u16>,
    player_certs: Vec<CertificateDer<'static>>,
    my_cert: CertificateDer<'static>,
    my_key: PrivateKeyDer<'static>,
}

impl Config {
    
    /// Creates a new network configuration for a party
    /// 
    /// The inputs are
    /// - `player_addr` - the IP addresses of all parties
    /// - `player_ports` - the ports of all parties
    /// - `player_certs` - the TLS certificates of all parties
    /// - `my_cert` - the TLS certificate of the local party
    /// - `my_key` - the TLS private key of the local party
    pub fn new(
        player_addr: Vec<Ipv4Addr>,
        player_ports: Vec<u16>,
        player_certs: Vec<CertificateDer<'static>>,
        my_cert: CertificateDer<'static>,
        my_key: PrivateKeyDer<'static>,
    ) -> Self {
        Self {
            player_addr,
            player_ports,
            my_cert,
            my_key,
            player_certs,
        }
    }

    fn load_certificate_from_file(
        config_path: &Path,
        cert_path: &Path,
    ) -> io::Result<CertificateDer<'static>> {
        let mut path = PathBuf::from(config_path);
        path.push(cert_path);
        let mut reader = BufReader::new(File::open(&path)?);
        let cert: io::Result<Vec<_>> = rustls_pemfile::certs(&mut reader).collect();
        let cert = cert?;
        if cert.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Found {} certificates in {}, expected 1",
                    cert.len(),
                    path.display()
                ),
            ));
        }
        Ok(cert[0].clone())
    }

    fn load_private_key_from_file(
        config_path: &Path,
        key_path: &Path,
    ) -> io::Result<PrivateKeyDer<'static>> {
        let mut path = PathBuf::from(config_path);
        path.push(key_path);
        let mut reader = BufReader::new(File::open(&path)?);
        let key = rustls_pemfile::private_key(&mut reader)?;
        key.ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid private key in {}", path.display()),
        ))
    }

    /// Loads the [Config]uration from a file and returns the index of the local party.
    pub fn from_file(path: &Path) -> Result<(usize, Self), io::Error> {
        let file_content = fs::read_to_string(path)?;
        let parsed_config: SerializedConfig = toml::from_str(&file_content)
            .map_err(|ser| io::Error::new(io::ErrorKind::InvalidData, format!("{}", ser)))?;
        // check party index is valid 1 <= party_index <= 3
        if parsed_config.party_index < 1 || parsed_config.party_index > 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid party_index: {}; must be 1 <= party_index <= 3",
                    parsed_config.party_index
                ),
            ));
        }
        let player_addr = vec![
            parsed_config.p1.address,
            parsed_config.p2.address,
            parsed_config.p3.address,
        ];
        let player_ports = vec![
            parsed_config.p1.port,
            parsed_config.p2.port,
            parsed_config.p3.port,
        ];

        let default_parent_dir = PathBuf::from("./");
        let parent_dir = path.parent().unwrap_or(&default_parent_dir);
        // load all certificates
        let player_certs = vec![
            Self::load_certificate_from_file(
                parent_dir,
                &PathBuf::from(parsed_config.p1.certificate),
            )?,
            Self::load_certificate_from_file(
                parent_dir,
                &PathBuf::from(parsed_config.p2.certificate),
            )?,
            Self::load_certificate_from_file(
                parent_dir,
                &PathBuf::from(parsed_config.p3.certificate),
            )?,
        ];
        let key_path = match parsed_config.party_index {
            1 => parsed_config.p1.private_key,
            2 => parsed_config.p2.private_key,
            3 => parsed_config.p3.private_key,
            _ => unreachable!(),
        }
        .ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "No \"private_key\" field found in section [p{}]",
                parsed_config.party_index
            ),
        ))?;
        let key = Self::load_private_key_from_file(parent_dir, &PathBuf::from(key_path))?;
        let my_cert = player_certs[parsed_config.party_index - 1].clone();
        Ok((
            parsed_config.party_index - 1,
            Self::new(player_addr, player_ports, player_certs, my_cert, key),
        ))
    }
}

/// The serialized network information for one party.
#[derive(Deserialize)]
struct SerializedPartyConfig {
    pub address: Ipv4Addr,
    pub port: u16,
    pub certificate: String,
    pub private_key: Option<String>,
}
/// The serialized network configuration.
#[derive(Deserialize)]
struct SerializedConfig {
    pub party_index: usize,
    pub p1: SerializedPartyConfig,
    pub p2: SerializedPartyConfig,
    pub p3: SerializedPartyConfig,
}

/// A communication channel between the local party and another party.
pub struct CommChannel {
    /// Defines the party on the other end.
    /// 
    /// Permissible are `0,1,2`
    pub to: usize,
    stream: Option<Stream>,
    bytes_sent: u64,
    bytes_received: u64,
    rounds: usize,
}

/// A TLS connection used as part of a [CommChannel].
pub enum Stream {
    /// TLS connection as a client.
    Client(rustls::StreamOwned<ClientConnection, TcpStream>),
    /// TLS connection as a server.
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
            Stream::Server(stream) => stream,
        }
    }

    /// TODO: add description
    pub fn complete_handshake_blocking(&mut self) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.conn.complete_io(&mut stream.sock).map(|_| ()),
            Self::Server(stream) => stream.conn.complete_io(&mut stream.sock).map(|_| ()),
        }
    }

    /// Closes the TLS connection.
    pub fn teardown(self) -> io::Result<()> {
        match self {
            Self::Client(mut stream) => {
                stream.conn.send_close_notify();
                while stream.conn.wants_write() {
                    stream.conn.write_tls(&mut stream.sock).unwrap();
                }
                drop(stream.conn);
                drop(stream.sock);
            }
            Self::Server(mut stream) => {
                stream.conn.send_close_notify();
                while stream.conn.wants_write() {
                    stream.conn.write_tls(&mut stream.sock).unwrap();
                }
                drop(stream.conn);
                drop(stream.sock);
            }
        }
        Ok(())
    }
}


/// The communication interface of a party.
pub struct ConnectedParty {
    /// The party's index `i`.
    pub i: usize,
    /// The network configuration.
    pub config: Config,
    /// Channel to party `i+1`.
    pub comm_next: CommChannel,
    /// Channel to party `i-1`.
    pub comm_prev: CommChannel,
}

impl ConnectedParty {

    /// Establishes the basic network interface and connects to the other parties.
    /// 
    /// The inputs are
    /// - `i` - the party's index
    /// - `config` - the network configuration
    /// - `timeout` - an optional timeout value
    pub fn bind_and_connect(
        i: usize,
        config: Config,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        let party = CreatedParty::bind(
            i,
            std::net::IpAddr::V4(config.player_addr[i]),
            config.player_ports[i],
        )?;
        CreatedParty::connect(party, config, timeout)
    }
}

/// The basic network interface of a party
pub struct CreatedParty {
    i: usize,
    server_socket: TcpListener,
}

impl CreatedParty {

    /// Binds the interface of party to the given address and port.
    /// 
    /// This function also defines the index of the party.
    pub fn bind(i: usize, addr: IpAddr, port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind((addr, port))?;
        Ok(Self {
            i,
            server_socket: listener,
        })
    }

    /// Returns the port of the [CreatedParty].
    pub fn port(&self) -> io::Result<u16> {
        self.server_socket
            .local_addr()
            .map(|socket_addr| socket_addr.port())
    }

    /// Establishes a connection with the other parties
    /// 
    /// The idea is that party `i` acts as server for party `i-1`.
    /// 
    /// The inputs are
    /// - `self` - the basic network interface
    /// - `config` - the network configuration
    /// - `timeout` - an optional timeout value
    /// 
    /// If successful returns a [ConnectedParty].
    pub fn connect(self, config: Config, timeout: Option<Duration>) -> io::Result<ConnectedParty> {
        let (next, prev) = match self.i {
            0 => {
                // (1)
                let mut server01 = CommChannel::new_server(&config, self.server_socket, 1).unwrap();
                server01
                    .stream
                    .as_mut()
                    .unwrap()
                    .complete_handshake_blocking()?;
                // println!("P1-P2 connected");
                // (2)
                // println!("P1 connecting to P3");
                let mut client02 = CommChannel::new_client(&config, 2, timeout).unwrap();
                client02
                    .stream
                    .as_mut()
                    .unwrap()
                    .complete_handshake_blocking()?;
                // println!("P1-P3 connected");
                (server01, client02)
            }
            1 => {
                // (1)
                // println!("P2 connecting to P1");
                let mut client01 = CommChannel::new_client(&config, 0, timeout).unwrap();
                client01
                    .stream
                    .as_mut()
                    .unwrap()
                    .complete_handshake_blocking()?;
                // println!("P2-P1 connected");
                // (3)
                // println!("P2 waiting for P3 to connect");
                let mut server12 = CommChannel::new_server(&config, self.server_socket, 2).unwrap();
                server12
                    .stream
                    .as_mut()
                    .unwrap()
                    .complete_handshake_blocking()?;
                // println!("P2-P3 connected");
                (server12, client01)
            }
            2 => {
                // (2)
                // println!("P3 waiting for P1 to connect");
                let mut server02 = CommChannel::new_server(&config, self.server_socket, 0).unwrap();
                server02
                    .stream
                    .as_mut()
                    .unwrap()
                    .complete_handshake_blocking()?;
                // println!("P3-P1 connected");
                // (3)
                // println!("P3 connecting to P2");
                let mut client12 = CommChannel::new_client(&config, 1, timeout).unwrap();
                client12
                    .stream
                    .as_mut()
                    .unwrap()
                    .complete_handshake_blocking()?;
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
    fn new_server_config(
        client_cert: &CertificateDer,
        my_cert: &CertificateDer<'static>,
        my_key: PrivateKeyDer<'static>,
    ) -> ServerConfig {
        let mut root_store = RootCertStore::empty();
        root_store.add(client_cert.clone()).unwrap();
        let client_verifier = WebPkiClientVerifier::builder(root_store.into())
            .build()
            .unwrap();
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![my_cert.clone()], my_key)
            .unwrap()
    }

    fn new_client_config(
        server_cert: &CertificateDer,
        my_cert: &CertificateDer<'static>,
        my_key: PrivateKeyDer<'static>,
    ) -> ClientConfig {
        let mut root_store = RootCertStore::empty();
        root_store.add(server_cert.clone()).unwrap();
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_client_auth_cert(vec![my_cert.clone()], my_key)
            .unwrap()
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

    /// Establishes a new communication channel where the local party acts as server.
    pub fn new_server(config: &Config, server_socket: TcpListener, to: usize) -> io::Result<Self> {
        // println!("Accepting connections from port {}", server_socket.local_addr().unwrap().port());
        let (sock, _) = server_socket.accept()?;
        let conn = ServerConnection::new(
            Self::new_server_config(
                &config.player_certs[to],
                &config.my_cert,
                config.my_key.clone_key(),
            )
            .into(),
        )
        .expect("Cannot create ServerConnection");
        // println!("Accepting connections from port {} done", server_socket.local_addr().unwrap().port());
        Ok(Self::new(to, Stream::Server(StreamOwned::new(conn, sock))))
    }

    /// Establishes a new communication channel where the local party acts as client.
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
                    Err(io_err) => {
                        if io_err.kind() == ErrorKind::ConnectionRefused {
                            // try again
                        } else {
                            break Err(io_err);
                        }
                    }
                }
                // check time
                if let Some(timeout) = timeout {
                    if start_time.elapsed() >= timeout {
                        break Err(io::Error::new(
                            ErrorKind::NotConnected,
                            format!(
                                "Cannot connect to {}:{} after {}s",
                                addr,
                                port,
                                timeout.as_secs_f32()
                            ),
                        ));
                    }
                }
                // sleep a bit
                thread::sleep(Duration::from_millis(100));
            }
        }?;
        let conn = ClientConnection::new(
            Self::new_client_config(
                &config.player_certs[to],
                &config.my_cert,
                config.my_key.clone_key(),
            )
            .into(),
            ServerName::IpAddress(rustls::pki_types::IpAddr::V4(addr.into())),
        )
        .expect("Cannot create ClientConnection");
        // println!("Connecting to {} done", config.player_ports[to]);
        Ok(Self::new(to, Stream::Client(StreamOwned::new(conn, sock))))
    }

    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.bytes_sent += bytes.len() as u64;
        self.rounds += 1;
        self.stream
            .as_mut()
            .expect("Cannot write anymore. Connection was closed")
            .as_mut_write()
            .write_all(bytes)
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        self.bytes_received += buffer.len() as u64;
        self.rounds += 1;
        self.stream
            .as_mut()
            .expect("Cannot read anymore. Connection was closed")
            .as_mut_read()
            .read_exact(buffer)
    }

    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received
    }

    pub fn get_rounds(&self) -> usize {
        self.rounds
    }

    /// Closes the communication channel properly. This may block if data needs to be written
    pub fn teardown(&mut self) -> io::Result<()> {
        match self.stream.take() {
            Some(stream) => stream.teardown(),
            None => Ok(()),
        }
    }
}

impl Clone for Config {
    fn clone(&self) -> Self {
        Self {
            player_addr: self.player_addr.clone(),
            player_ports: self.player_ports.clone(),
            my_cert: self.my_cert.clone(),
            my_key: self.my_key.clone_key(),
            player_certs: self.player_certs.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{ErrorKind, Read, Write},
        net::{TcpListener, TcpStream},
        thread,
        time::{Duration, Instant},
    };

    use crate::rep3_core::{network::non_blocking::NonBlockingCommChannel, party::test_export::localhost_connect};

    use super::non_blocking::NonBlockingStream;

    // #[test]
    #[allow(unused)]
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
                println!("Server: [{}] {} byte/sec", buf_size, (DATA as f64) / s);
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
                println!("Client: [{}] {} byte/sec", buf_size, (DATA as f64) / s);
            }
        });

        server.join().unwrap();
        client.join().unwrap();
    }

    fn write_until_block(s: &mut NonBlockingStream, buf: &[u8]) -> usize {
        let mut total = 0;
        loop {
            match s.write(buf) {
                Ok(n) => total += n,
                Err(io_err) => {
                    if io_err.kind() == ErrorKind::WouldBlock {
                        return total;
                    } else {
                        panic!("other error: {}", io_err);
                    }
                }
            }
        }
    }

    #[test]
    fn channel_close_properly() {
        const WRITE_SIZE: usize = 1_000_000;
        let (p1, p2, p3) = localhost_connect(|p| p, |p| p, |p| p);
        // we return channel p1 to p2
        let mut comm_next = NonBlockingCommChannel::from_channel(p1.comm_next).unwrap();
        let mut comm_next_receiver = NonBlockingCommChannel::from_channel(p2.comm_prev).unwrap();
        // close others
        drop(p1.comm_prev);
        drop(p2.comm_next);
        drop(p3.comm_prev);
        drop(p3.comm_next);

        let (send, receive) = oneshot::channel::<()>();

        let buf = vec![0x11; WRITE_SIZE];
        let mut rcv_buf = vec![0; WRITE_SIZE];

        // write until block
        let total_sent = write_until_block(&mut comm_next.stream, &buf);

        // close the connection
        let mut comm_next = comm_next.into_channel().unwrap();

        let writer = thread::spawn(move || {
            send.send(()).unwrap();
            comm_next.teardown().unwrap();
            drop(comm_next);
        });

        // now read
        receive.recv().unwrap();
        // wait a tiny bit more to make sure writer called teardown()
        thread::sleep(Duration::from_millis(10));

        let mut bytes_left = total_sent;
        while bytes_left > 0 {
            let bytes_to_read = usize::min(bytes_left, WRITE_SIZE);
            match comm_next_receiver
                .stream
                .read(&mut rcv_buf[..bytes_to_read])
            {
                Ok(n) => bytes_left -= n,
                Err(io_err) => {
                    if io_err.kind() == ErrorKind::WouldBlock {
                        () // retry
                    } else {
                        panic!("unexpected error: {}", io_err);
                    }
                }
            }
        }

        let mut comm_next_receiver = comm_next_receiver.into_channel().unwrap();
        comm_next_receiver.teardown().unwrap();
        drop(comm_next_receiver);
        writer.join().unwrap();
    }
}
