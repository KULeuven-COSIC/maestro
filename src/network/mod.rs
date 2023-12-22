use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
// use rustls::cipher_suite::TLS13_AES_128_GCM_SHA256;
// use rustls::{ClientConfig, Stream, SupportedCipherSuite};

pub struct Config {
    player_addr: Vec<Ipv4Addr>,
    player_ports: Vec<u16>,
    // my_cert: C
}

impl Config {
    pub fn new(player_addr: Vec<Ipv4Addr>, player_ports: Vec<u16>) -> Self {
        Self {
            player_addr,
            player_ports
        }
    }
}

pub struct CommChannel {
    /// to which player (0,1,2)
    pub to: usize,
    stream: Stream
}

impl CommChannel {
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        match &mut self.stream {
            Stream::Client {ref mut stream} | Stream::Server { ref mut stream, ..} => stream.write_all(bytes)
        }
    }

    pub fn read(&mut self, buffer: &mut [u8])  -> io::Result<()>{
        match &mut self.stream {
            Stream::Client {ref mut stream} | Stream::Server { ref mut stream, ..} => stream.read_exact(buffer)
        }
    }
}

enum Stream {
    Client {stream: TcpStream}, Server{stream: TcpStream, _listener: TcpListener}
}

pub struct CreatedParty {
    i: usize,
    server_socket: TcpListener
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
            server_socket:listener
        })
    }

    pub fn port(&self) -> io::Result<u16> {
        self.server_socket.local_addr().map(|socket_addr| socket_addr.port())
    }

    pub fn connect(self, config: Config) -> io::Result<ConnectedParty> {
        let (next, prev) = match self.i {
            0 => {
                // (1)
                let server01 = CommChannel::new_server(self.server_socket, 1).unwrap();
                // println!("P1-P2 connected");
                // (2)
                // println!("P1 connecting to P3");
                let client02 = CommChannel::new_client(&config, 2).unwrap();
                // println!("P1-P3 connected");
                (server01, client02)
            },
            1 => {
                // (1)
                // println!("P2 connecting to P1");
                let client01 = CommChannel::new_client(&config, 0).unwrap();
                // println!("P2-P1 connected");
                // (3)
                // println!("P2 waiting for P3 to connect");
                let server12 = CommChannel::new_server(self.server_socket, 2).unwrap();
                // println!("P2-P3 connected");
                (server12, client01)
            },
            2 => {
                // (2)
                // println!("P3 waiting for P1 to connect");
                let server02 = CommChannel::new_server(self.server_socket, 0).unwrap();
                // println!("P3-P1 connected");
                // (3)
                // println!("P3 connecting to P2");
                let client12 = CommChannel::new_client(&config, 1).unwrap();
                // println!("P3-P2 connected");
                (server02, client12)
            }
            _ => unreachable!()
        };

        let comm_next = next;
        let comm_prev = prev;
        Ok(ConnectedParty {
            i: self.i,
            config,
            comm_next,
            comm_prev
        })
    }
}

impl CommChannel {
    pub fn new_server(server_socket: TcpListener, to: usize) -> io::Result<Self> {
        // println!("Accepting connections from port {}", server_socket.local_addr().unwrap().port());
        let (stream, _) = server_socket.accept()?;
        // println!("Accepting connections from port {} done", server_socket.local_addr().unwrap().port());
        Ok(Self {
            to,
            stream: Stream::Server {stream, _listener: server_socket}
        })
    }

    pub fn new_client(config: &Config, to: usize) -> io::Result<Self> {
        // println!("Connecting to {}", config.player_ports[to]);
        let stream = TcpStream::connect((config.player_addr[to], config.player_ports[to]))?;
        // println!("Connecting to {} done", config.player_ports[to]);
        Ok(Self {
            to,
            stream: Stream::Client {stream}
        })
        // let mut client_config = ClientConfig::builder()
        //     .with_cipher_suites(&[TLS13_AES_128_GCM_SHA256])
    }
}