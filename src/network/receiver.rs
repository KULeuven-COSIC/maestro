use std::marker::PhantomData;

use crate::share::Field;

#[must_use]
pub struct FieldVectorReceiver<F: Field>{
    inner: oneshot::Receiver<Vec<u8>>,
    phantom: PhantomData<F>,
}

impl<F: Field> FieldVectorReceiver<F> {
    pub fn new(inner: oneshot::Receiver<Vec<u8>>) -> Self {
        Self {inner, phantom: PhantomData}
    }

    pub fn rcv(self) -> Result<Vec<F>, oneshot::RecvError> {
        self.inner.recv().map(|bytes| F::from_byte_vec(bytes))
    }
}

#[must_use]
pub struct FieldSliceReceiver<'a, F: Field>{
    inner: oneshot::Receiver<Vec<u8>>,
    slice: &'a mut [F],
}

impl<'a, F: Field> FieldSliceReceiver<'a, F> {
    pub fn new(inner: oneshot::Receiver<Vec<u8>>, slice: &'a mut [F]) -> Self {
        Self {inner, slice}
    }

    pub fn rcv(mut self) -> Result<(), oneshot::RecvError> {
        self.inner.recv().map(|bytes| F::from_byte_slice(bytes, &mut self.slice))
    }
}

#[must_use]
pub struct SliceReceiver<'a> {
    inner: oneshot::Receiver<Vec<u8>>,
    slice: &'a mut [u8]
}

impl<'a> SliceReceiver<'a> {
    pub fn new(inner: oneshot::Receiver<Vec<u8>>, slice: &'a mut [u8]) -> Self {
        Self {inner, slice}
    }

    pub fn rcv(self) -> Result<(), oneshot::RecvError> {
        self.inner.recv().map(|bytes| self.slice.copy_from_slice(&bytes))
    }
}