use std::{io::{self, Read, Write}, os::fd::{FromRawFd, IntoRawFd, OwnedFd}};

use mio::net::TcpStream;
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use super::{CommChannel, Stream};


pub struct NonBlockingCommChannel {
    /// to which player (0,1,2)
    pub to: usize,
    pub stream: NonBlockingStream,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub rounds: usize,
}

pub enum NonBlockingStream {
    Client(rustls::StreamOwned<ClientConnection, TcpStream>),
    Server(rustls::StreamOwned<ServerConnection, TcpStream>),
}

fn mio_to_net(stream: TcpStream) -> std::net::TcpStream {
    unsafe { std::net::TcpStream::from_raw_fd(stream.into_raw_fd()) }
}

impl NonBlockingStream {
    pub fn from_stream(stream: Stream) -> io::Result<Self> {
        match &stream {
            Stream::Client(stream) => stream.sock.set_nonblocking(true)?,
            Stream::Server(stream) => stream.sock.set_nonblocking(true)?,
        };
        match stream {
            Stream::Client(stream) => {
                let (conn, sock) = stream.into_parts();
                Ok(Self::Client(StreamOwned::new(conn, TcpStream::from_std(sock))))
            },
            Stream::Server(stream) => {
                let (conn, sock) = stream.into_parts();
                Ok(Self::Server(StreamOwned::new(conn, TcpStream::from_std(sock))))
            }
        }
    }

    pub fn into_stream(self) -> io::Result<Stream> {
        match self {
            Self::Client(stream) => {
                let (conn, sock) = stream.into_parts();
                let std_stream = mio_to_net(sock);
                std_stream.set_nonblocking(false)?;
                Ok(Stream::Client(StreamOwned::new(conn, std_stream)))
            },
            Self::Server(stream) => {
                let (conn, sock) = stream.into_parts();
                let std_stream = mio_to_net(sock);
                std_stream.set_nonblocking(false)?;
                Ok(Stream::Server(StreamOwned::new(conn, std_stream)))
            }
        }
    }

    // pub fn as_mut_write(&mut self) -> &mut dyn io::Write {
    //     match self {
    //         Self::Client(stream) => stream,
    //         Self::Server(stream) => stream,
    //     }
    // }

    // pub fn as_mut_read(&mut self) -> &mut dyn io::Read {
    //     match self {
    //         Self::Client(stream) => stream,
    //         Self::Server(stream)=> stream,
    //     }
    // }

    pub fn tcp_stream_mut(&mut self) -> &mut TcpStream {
        match self {
            Self::Client(stream) => &mut stream.sock,
            Self::Server(stream)=> &mut stream.sock,
        }
    }
}

impl NonBlockingCommChannel {
    pub fn from_channel(channel: CommChannel) -> io::Result<Self> {
        let nb_stream = NonBlockingStream::from_stream(channel.stream.expect("Stream already closed"))?;
        Ok(Self {
            to: channel.to,
            stream: nb_stream,
            bytes_sent: channel.bytes_sent,
            bytes_received: channel.bytes_received,
            rounds: channel.rounds
        })
    }

    pub fn into_channel(self) -> io::Result<CommChannel> {
        Ok(CommChannel { 
            to: self.to, 
            stream: Some(self.stream.into_stream()?), 
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            rounds: self.rounds 
        })
    }
}

impl Read for NonBlockingStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read(buf),
            Self::Server(stream)=> stream.read(buf),
        }
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.read_exact(buf),
            Self::Server(stream)=> stream.read_exact(buf),
        }
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read_to_end(buf),
            Self::Server(stream)=> stream.read_to_end(buf),
        }
    }
    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read_to_string(buf),
            Self::Server(stream)=> stream.read_to_string(buf),
        }
    }
    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read_vectored(bufs),
            Self::Server(stream)=> stream.read_vectored(bufs),
        }
    }
}

impl Write for NonBlockingStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.write(buf),
            Self::Server(stream)=> stream.write(buf),
        }
    }
    fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.write_all(buf),
            Self::Server(stream)=> stream.write_all(buf),
        }
    }
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.write_vectored(bufs),
            Self::Server(stream)=> stream.write_vectored(bufs),
        }
    }
    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.write_fmt(fmt),
            Self::Server(stream)=> stream.write_fmt(fmt),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.flush(),
            Self::Server(stream)=> stream.flush(),
        }
    }
}