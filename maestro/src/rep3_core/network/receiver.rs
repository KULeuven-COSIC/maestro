use std::marker::PhantomData;

use super::NetSerializable;

#[cfg(feature = "verbose-timing")]
use {crate::network::task::IO_TIMER, std::time::Instant};

#[must_use]
pub struct NetVectorReceiver<T: NetSerializable> {
    inner: oneshot::Receiver<Vec<u8>>,
    expected_len: usize,
    phantom: PhantomData<T>,
}

impl<T: NetSerializable> NetVectorReceiver<T> {
    pub fn new(inner: oneshot::Receiver<Vec<u8>>, expected_len: usize) -> Self {
        Self {
            inner,
            expected_len,
            phantom: PhantomData,
        }
    }

    pub fn rcv(self) -> Result<Vec<T>, oneshot::RecvError> {
        #[cfg(feature = "verbose-timing")]
        let start = Instant::now();
        match self.inner.recv() {
            Ok(bytes) => {
                #[cfg(feature = "verbose-timing")]
                {
                    let io_end = start.elapsed();
                    IO_TIMER.lock().unwrap().report_time("io", io_end);
                    let serialization_start = Instant::now();
                    let res = T::from_byte_vec(bytes, self.expected_len);
                    let ser_end = serialization_start.elapsed();
                    IO_TIMER.lock().unwrap().report_time("ser", ser_end);
                    Ok(res)
                }
                #[cfg(not(feature = "verbose-timing"))]
                Ok(T::from_byte_vec(bytes, self.expected_len))
            }
            Err(err) => Err(err),
        }
    }
}

#[must_use]
pub struct NetSliceReceiver<'a, T: NetSerializable> {
    inner: oneshot::Receiver<Vec<u8>>,
    slice: &'a mut [T],
}

impl<'a, T: NetSerializable> NetSliceReceiver<'a, T> {
    pub fn new(inner: oneshot::Receiver<Vec<u8>>, slice: &'a mut [T]) -> Self {
        Self { inner, slice }
    }

    pub fn rcv(self) -> Result<(), oneshot::RecvError> {
        #[cfg(feature = "verbose-timing")]
        let start = Instant::now();
        match self.inner.recv() {
            Ok(bytes) => {
                #[cfg(feature = "verbose-timing")]
                {
                    let io_end = start.elapsed();
                    IO_TIMER.lock().unwrap().report_time("io", io_end);
                    let serialization_start = Instant::now();
                    T::from_byte_slice(bytes, self.slice);
                    let ser_end = serialization_start.elapsed();
                    IO_TIMER.lock().unwrap().report_time("ser", ser_end);
                }
                #[cfg(not(feature = "verbose-timing"))]
                T::from_byte_slice(bytes, self.slice);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

#[must_use]
pub struct SliceReceiver<'a> {
    inner: oneshot::Receiver<Vec<u8>>,
    slice: &'a mut [u8],
}

impl<'a> SliceReceiver<'a> {
    pub fn new(inner: oneshot::Receiver<Vec<u8>>, slice: &'a mut [u8]) -> Self {
        Self { inner, slice }
    }

    pub fn rcv(self) -> Result<(), oneshot::RecvError> {
        #[cfg(feature = "verbose-timing")]
        let start = Instant::now();
        match self.inner.recv() {
            Ok(bytes) => {
                #[cfg(feature = "verbose-timing")]
                {
                    let io_end = start.elapsed();
                    IO_TIMER.lock().unwrap().report_time("io", io_end);
                }
                self.slice.copy_from_slice(&bytes);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

#[must_use]
pub struct VecReceiver {
    inner: oneshot::Receiver<Vec<u8>>,
}

impl VecReceiver {
    pub fn new(inner: oneshot::Receiver<Vec<u8>>) -> Self {
        Self { inner }
    }

    pub fn recv(self) -> Result<Vec<u8>, oneshot::RecvError> {
        #[cfg(feature = "verbose-timing")]
        let start = Instant::now();
        match self.inner.recv() {
            Ok(bytes) => {
                #[cfg(feature = "verbose-timing")]
                {
                    let io_end = start.elapsed();
                    IO_TIMER.lock().unwrap().report_time("io", io_end);
                }
                Ok(bytes)
            }
            Err(err) => Err(err),
        }
    }
}
