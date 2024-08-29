use rustls::{ClientConnection, ServerConnection};
use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use crate::rep3_core::party::CommStats;

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

impl NonBlockingStream {
    pub fn from_stream(stream: Stream) -> io::Result<Self> {
        match &stream {
            Stream::Client(stream) => stream.sock.set_nonblocking(true)?,
            Stream::Server(stream) => stream.sock.set_nonblocking(true)?,
        };
        match stream {
            Stream::Client(stream) => Ok(Self::Client(stream)),
            Stream::Server(stream) => Ok(Self::Server(stream)),
        }
    }

    pub fn into_stream(self) -> io::Result<Stream> {
        match self {
            Self::Client(stream) => {
                stream.sock.set_nonblocking(false)?;
                Ok(Stream::Client(stream))
            }
            Self::Server(stream) => {
                stream.sock.set_nonblocking(false)?;
                Ok(Stream::Server(stream))
            }
        }
    }

    pub fn wants_write(&self) -> bool {
        match self {
            Self::Client(stream) => stream.conn.wants_write(),
            Self::Server(stream) => stream.conn.wants_write(),
        }
    }

    pub fn write_tls(&mut self) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.conn.write_tls(&mut stream.sock),
            Self::Server(stream) => stream.conn.write_tls(&mut stream.sock),
        }
    }
}

impl NonBlockingCommChannel {
    pub fn from_channel(channel: CommChannel) -> io::Result<Self> {
        let nb_stream =
            NonBlockingStream::from_stream(channel.stream.expect("Stream already closed"))?;
        Ok(Self {
            to: channel.to,
            stream: nb_stream,
            bytes_sent: channel.bytes_sent,
            bytes_received: channel.bytes_received,
            rounds: channel.rounds,
        })
    }

    pub fn into_channel(self) -> io::Result<CommChannel> {
        Ok(CommChannel {
            to: self.to,
            stream: Some(self.stream.into_stream()?),
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            rounds: self.rounds,
        })
    }

    pub fn get_comm_stats(&self) -> CommStats {
        CommStats::new(self.bytes_received, self.bytes_sent, self.rounds)
    }

    pub fn reset_comm_stats(&mut self) {
        self.bytes_received = 0;
        self.bytes_sent = 0;
        self.rounds = 0;
    }
}

impl Read for NonBlockingStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read(buf),
            Self::Server(stream) => stream.read(buf),
        }
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.read_exact(buf),
            Self::Server(stream) => stream.read_exact(buf),
        }
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read_to_end(buf),
            Self::Server(stream) => stream.read_to_end(buf),
        }
    }
    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read_to_string(buf),
            Self::Server(stream) => stream.read_to_string(buf),
        }
    }
    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read_vectored(bufs),
            Self::Server(stream) => stream.read_vectored(bufs),
        }
    }
}

impl Write for NonBlockingStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.write(buf),
            Self::Server(stream) => stream.write(buf),
        }
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.write_all(buf),
            Self::Server(stream) => stream.write_all(buf),
        }
    }
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.write_vectored(bufs),
            Self::Server(stream) => stream.write_vectored(bufs),
        }
    }
    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.write_fmt(fmt),
            Self::Server(stream) => stream.write_fmt(fmt),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.flush(),
            Self::Server(stream) => stream.flush(),
        }
    }
}
