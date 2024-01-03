use std::io;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig, ClientConnection, ServerConnection, StreamOwned};

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
}

pub struct CommChannel {
    /// to which player (0,1,2)
    pub to: usize,
    stream: Stream,
}

impl CommChannel {
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.as_mut_write().write_all(bytes)?;
        self.stream.as_mut_write().flush()
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        self.stream.as_mut_read().read_exact(buffer)
    }
}

enum Stream {
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

impl CreatedParty {
    pub fn bind(i: usize, addr: IpAddr, port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind((addr, port))?;
        Ok(Self {
            i,
            server_socket: listener,
        })
    }

    pub fn port(&self) -> io::Result<u16> {
        self.server_socket
            .local_addr()
            .map(|socket_addr| socket_addr.port())
    }

    pub fn connect(self, config: Config) -> io::Result<ConnectedParty> {
        let (next, prev) = match self.i {
            0 => {
                // (1)
                let mut server01 = CommChannel::new_server(&config, self.server_socket, 1).unwrap();
                server01.stream.complete_handshake_blocking()?;
                // println!("P1-P2 connected");
                // (2)
                // println!("P1 connecting to P3");
                let mut client02 = CommChannel::new_client(&config, 2).unwrap();
                client02.stream.complete_handshake_blocking()?;
                // println!("P1-P3 connected");
                (server01, client02)
            }
            1 => {
                // (1)
                // println!("P2 connecting to P1");
                let mut client01 = CommChannel::new_client(&config, 0).unwrap();
                client01.stream.complete_handshake_blocking()?;
                // println!("P2-P1 connected");
                // (3)
                // println!("P2 waiting for P3 to connect");
                let mut server12 = CommChannel::new_server(&config, self.server_socket, 2).unwrap();
                server12.stream.complete_handshake_blocking()?;
                // println!("P2-P3 connected");
                (server12, client01)
            }
            2 => {
                // (2)
                // println!("P3 waiting for P1 to connect");
                let mut server02 = CommChannel::new_server(&config, self.server_socket, 0).unwrap();
                server02.stream.complete_handshake_blocking()?;
                // println!("P3-P1 connected");
                // (3)
                // println!("P3 connecting to P2");
                let mut client12 = CommChannel::new_client(&config, 1).unwrap();
                client12.stream.complete_handshake_blocking()?;
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

    pub fn new_server(config: &Config, server_socket: TcpListener, to: usize) -> io::Result<Self> {
        // println!("Accepting connections from port {}", server_socket.local_addr().unwrap().port());
        let (sock, _) = server_socket.accept()?;
        let conn = ServerConnection::new(Self::new_server_config(&config.player_certs[to], &config.my_cert, config.my_key.clone_key()).into())
        .expect("Cannot create ServerConnection");
        // println!("Accepting connections from port {} done", server_socket.local_addr().unwrap().port());
        Ok(Self {
            to,
            stream: Stream::Server(StreamOwned::new(conn, sock)),
        })
    }

    pub fn new_client(config: &Config, to: usize) -> io::Result<Self> {
        // println!("Connecting to {}", config.player_ports[to]);
        let addr: std::net::Ipv4Addr = config.player_addr[to];
        let port = config.player_ports[to];
        let sock = TcpStream::connect((addr, port))?;
        let conn = ClientConnection::new(
            Self::new_client_config(&config.player_certs[to], &config.my_cert, config.my_key.clone_key()).into(), 
            ServerName::IpAddress(rustls::pki_types::IpAddr::V4(addr.into()))
        )
        .expect("Cannot create ClientConnection");
        // println!("Connecting to {} done", config.player_ports[to]);
        Ok(Self {
            to,
            stream: Stream::Client(StreamOwned::new(conn, sock)),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, net::{TcpListener, TcpStream}, io::{Read, Write}, time::Instant};


    // #[test]
    fn tcp_single_thread_throughput() {
        const buf_sizes: [usize; 4] = [1024, 2048, 4096, 8192];
        const data: usize = 1_000_000_000;
        let server = thread::spawn(|| {
            let mut listener = TcpListener::bind("127.0.0.1:8080").unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            for buf_size in buf_sizes {
                let start = Instant::now();
                let mut buf = vec![0; buf_size];
                let mut remaining = data as i64;
                while remaining > 0 {
                    stream.read_exact(&mut buf).unwrap();
                    remaining -= buf_size as i64;
                }
                let time = start.elapsed();
                let s = time.as_secs_f64();
                println!("Server: [{}] {} byte/sec", buf_size, (data as f64)/s);
            }
        });

        let client = thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
            for buf_size in buf_sizes {
                let start = Instant::now();
                let buf = vec![0; buf_size];
                let mut remaining = data as i64;
                while remaining > 0 {
                    stream.write_all(&buf).unwrap();
                    remaining -= buf_size as i64;
                }
                let time = start.elapsed();
                let s = time.as_secs_f64();
                println!("Client: [{}] {} byte/sec", buf_size, (data as f64)/s);
            }
        });

        server.join().unwrap();
        client.join().unwrap();
    }
}