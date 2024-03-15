use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;

pub type MpcResult<T> = Result<T, MpcError>;

#[derive(Debug)]
pub enum MpcError {
    CommitmentError,
    BroadcastError,
    SacrificeError,
    IoError(io::Error),
    RecvError,
    InvalidParameters(String),
    OperationFailed(String),
}


impl Display for MpcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MpcError::CommitmentError => f.write_str("CommitmentError"),
            MpcError::BroadcastError => f.write_str("BroadcastError"),
            MpcError::SacrificeError => f.write_str("SacrificeError"),
            MpcError::IoError(io_err) => write!(f, "IoError({})", io_err),
            MpcError::RecvError => f.write_str("RecvError"),
            MpcError::InvalidParameters(msg) => write!(f, "InvalidParameters({})", msg),
            MpcError::OperationFailed(msg) => write!(f, "OperationFailed({})", msg),
        }
    }
}

impl Error for MpcError {}

impl From<io::Error> for MpcError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<oneshot::RecvError> for MpcError {
    fn from(_err: oneshot::RecvError) -> Self {
        Self::RecvError
    }
}
