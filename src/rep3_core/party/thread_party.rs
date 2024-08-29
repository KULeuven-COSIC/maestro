use std::{borrow::Borrow, cell::OnceCell, ops::Sub};

use rand_chacha::ChaCha20Rng;

use crate::rep3_core::{network::{
        task::{Direction, IoLayer}, NetSerializable, NetSliceReceiver, NetVectorReceiver
    }, share::{HasZero, RssShare, RssShareVec}};

use super::{correlated_randomness::SharedRng, Party, RngExt};

pub struct ThreadParty<T> {
    /// Party index 0, 1 or 2
    i: usize,
    range_start: usize,
    /// exclusive
    range_end: usize,
    random_next: SharedRng,
    random_prev: SharedRng,
    #[allow(dead_code)]
    random_local: ChaCha20Rng,
    io_layer: OnceCell<IoLayer>,
    pub additional_data: T,
}

impl<T> ThreadParty<T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        i: usize,
        range_start: usize,
        range_end: usize,
        random_next: SharedRng,
        random_prev: SharedRng,
        random_local: ChaCha20Rng,
        io_layer: OnceCell<IoLayer>,
        additional_data: T,
    ) -> Self {
        Self {
            i,
            range_start,
            range_end,
            random_next,
            random_prev,
            random_local,
            io_layer,
            additional_data,
        }
    }

    pub fn task_size(&self) -> usize {
        self.range_end - self.range_start
    }

    pub fn range_start(&self) -> usize {
        self.range_start
    }

    pub fn range_end(&self) -> usize {
        self.range_end
    }
}

impl<T> Party for ThreadParty<T> {
    fn generate_alpha<E: RngExt + Sub<Output=E>>(&mut self, n: usize) -> impl Iterator<Item=E> {
        super::generate_alpha(self.random_next.as_mut(), self.random_prev.as_mut(), n)
    }

    fn generate_random<E: RngExt>(&mut self, n: usize) -> RssShareVec<E> {
        super::generate_random(self.random_next.as_mut(), self.random_prev.as_mut(), n)
    }

    #[inline]
    fn constant<F: HasZero>(&self, value: F) -> RssShare<F> {
        super::constant(self.i, value)
    }

    fn send_field<'a, N: NetSerializable + 'a>(
        &self,
        direction: Direction,
        elements: impl IntoIterator<Item = impl Borrow<N>>,
        len: usize,
    ) {
        self.io_layer
            .get()
            .unwrap()
            .send_field_thread(direction, self.range_start, elements, len)
    }

    fn send_field_slice<N: NetSerializable>(
            &self,
            direction: Direction,
            elements: &[N],
        ) {
            self.io_layer
            .get()
            .unwrap()
            .send_field_slice_thread(direction, self.range_start, elements)
    }

    fn receive_field<N: NetSerializable>(
        &self,
        direction: Direction,
        num_elements: usize,
    ) -> NetVectorReceiver<N> {
        self.io_layer
            .get()
            .unwrap()
            .receive_field_thread(direction, self.range_start, num_elements)
    }

    fn receive_field_slice<'a, N: NetSerializable>(
        &self,
        direction: Direction,
        dst: &'a mut [N],
    ) -> NetSliceReceiver<'a, N> {
        self.io_layer
            .get()
            .unwrap()
            .receive_field_slice_thread(direction, self.range_start, dst)
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use itertools::{izip, Itertools};
    use rand::RngCore;

    use crate::rep3_core::{network::NetSerializable, party::{
            test::DummyNumber, test_export::{PartySetup, TestSetup}, MainParty, Party
        }, share::{HasZero, RssShare}};

    #[test]
    fn thread_parties_correlated_randomness_bytes() {
        struct RngOutput {
            shared_prev: Vec<u8>,
            shared_next: Vec<u8>,
            local: Vec<u8>,
        }

        const THREADS: usize = 3;
        const N_OUTPUT: usize = 1000;
        let program = |p: &mut MainParty| {
            let threads = p.create_thread_parties(p.split_range_equally(100));
            threads
                .into_iter()
                .map(|mut thread| {
                    let mut output = RngOutput {
                        shared_next: vec![0u8; N_OUTPUT],
                        shared_prev: vec![0u8; N_OUTPUT],
                        local: vec![0u8; N_OUTPUT],
                    };
                    thread
                        .random_prev
                        .as_mut()
                        .fill_bytes(&mut output.shared_prev);
                    thread
                        .random_next
                        .as_mut()
                        .fill_bytes(&mut output.shared_next);
                    thread.random_local.fill_bytes(&mut output.local);
                    ((thread.range_start, thread.range_end), output)
                })
                .collect_vec()
        };

        let ((o1, _), (o2, _), (o3, _)) =
            PartySetup::localhost_setup_multithreads(THREADS, program, program, program);
        assert_eq!(o1.len(), THREADS);
        assert_eq!(o2.len(), THREADS);
        assert_eq!(o3.len(), THREADS);

        // check that randomness is correlated for threads with the same range
        for (((start1, end1), o1), ((start2, end2), o2), ((start3, end3), o3)) in
            izip!(o1.iter(), o2.iter(), o3.iter())
        {
            // same range
            assert_eq!(start1, start2);
            assert_eq!(start1, start3);
            assert_eq!(end1, end2);
            assert_eq!(end1, end3);

            // correlated
            assert_eq!(o1.shared_next, o2.shared_prev);
            assert_eq!(o2.shared_next, o3.shared_prev);
            assert_eq!(o3.shared_next, o1.shared_prev);
        }

        // local randomness and other randomness is unique
        let mut set = BTreeSet::new();
        for (_, o) in o1.into_iter().chain(o2).chain(o3) {
            set.insert(o.local);
            set.insert(o.shared_next);
        }
        assert_eq!(set.len(), 3 * THREADS * 2);
    }

    #[test]
    fn thread_parties_correlated_randomness() {
        struct RngOutput {
            alpha: Vec<DummyNumber>,
            random: Vec<RssShare<DummyNumber>>,
        }

        const THREADS: usize = 3;
        const N_OUTPUT: usize = 1000;
        let program = |p: &mut MainParty| {
            let threads = p.create_thread_parties(p.split_range_equally(100));
            threads
                .into_iter()
                .map(|mut thread| {
                    let output = RngOutput {
                        alpha: thread.generate_alpha(N_OUTPUT).collect(),
                        random: thread.generate_random(N_OUTPUT),
                    };
                    ((thread.range_start, thread.range_end), output)
                })
                .collect_vec()
        };

        let ((o1, _), (o2, _), (o3, _)) =
            PartySetup::localhost_setup_multithreads(THREADS, program, program, program);
        assert_eq!(o1.len(), THREADS);
        assert_eq!(o2.len(), THREADS);
        assert_eq!(o3.len(), THREADS);

        let mut random_elements = BTreeSet::new();

        // check that randomness is correct for threads with the same range
        for (((start1, end1), o1), ((start2, end2), o2), ((start3, end3), o3)) in izip!(o1, o2, o3)
        {
            // same range
            assert_eq!(start1, start2);
            assert_eq!(start1, start3);
            assert_eq!(end1, end2);
            assert_eq!(end1, end3);

            assert_eq!(o1.alpha.len(), o2.alpha.len());
            assert_eq!(o2.alpha.len(), o3.alpha.len());
            for (alpha1, alpha2, alpha3) in izip!(o1.alpha, o2.alpha, o3.alpha) {
                assert_eq!(DummyNumber::ZERO, alpha1 + alpha2 + alpha3);
            }

            assert_eq!(o1.random.len(), o2.random.len());
            assert_eq!(o1.random.len(), o3.random.len());
            let n = o1.random.len();
            // reconstruct random elements
            let rand = izip!(o1.random, o2.random, o3.random).map(|(r1, r2, r3)| {
                // check consistent
                assert_eq!(r1.sii, r2.si);
                assert_eq!(r2.sii, r3.si);
                assert_eq!(r3.sii, r1.si);
                r1.si + r2.si + r3.si
            });
            // we serialize rand as bytes to workaround that DummyNumber does not implement Ord, Eq or Hash
            random_elements.insert(DummyNumber::as_byte_vec(rand, n));
        }

        assert_eq!(random_elements.len(), THREADS);
    }
}
