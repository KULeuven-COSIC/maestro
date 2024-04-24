use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;

pub type MpcResult<T> = Result<T, MpcError>;

#[derive(Debug)]
pub enum MpcError {
    Commitment,
    Broadcast,
    Sacrifice,
    Io(io::Error),
    Receive,
}

impl Display for MpcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MpcError::Commitment => f.write_str("CommitmentError"),
            MpcError::Broadcast => f.write_str("BroadcastError"),
            MpcError::Sacrifice => f.write_str("SacrificeError"),
            MpcError::Io(io_err) => write!(f, "IoError({})", io_err),
            MpcError::Receive => f.write_str("RecvError"),
        }
    }
}

impl Error for MpcError {}

impl From<io::Error> for MpcError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<oneshot::RecvError> for MpcError {
    fn from(_err: oneshot::RecvError) -> Self {
        Self::Receive
    }
}
