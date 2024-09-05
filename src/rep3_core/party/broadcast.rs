use crate::rep3_core::network::task::Direction;
use crate::rep3_core::network::NetSerializable;
use crate::rep3_core::party::error::{MpcError, MpcResult};
use crate::rep3_core::party::MainParty;
use crate::rep3_core::share::RssShare;
use sha2::digest::FixedOutput;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Add;
use std::slice;

use super::DigestExt;

pub struct BroadcastContext {
    view_next: Sha256,
    view_prev: Sha256,
}

pub trait Broadcast {
    fn broadcast_round_bytes(
        &mut self,
        context: &mut BroadcastContext,
        buffer_next: &mut [u8],
        buffer_prev: &mut [u8],
        message: &[u8],
    ) -> MpcResult<()>;

    fn broadcast_round<T: NetSerializable + DigestExt>(
        &mut self,
        context: &mut BroadcastContext,
        buffer_next: &mut [T],
        buffer_prev: &mut [T],
        message: &[T],
    ) -> MpcResult<()>;

    fn open_rss<T: NetSerializable + Add<Output=T> + Clone + DigestExt>(
        &mut self,
        context: &mut BroadcastContext,
        share_i: &[T],
        share_ii: &[T],
    ) -> MpcResult<Vec<T>>;

    fn compare_view(&mut self, context: BroadcastContext) -> MpcResult<()>;

    fn open_rss_to<T: NetSerializable + Add<Output=T> + Clone + DigestExt>(
        &mut self,
        context: &mut BroadcastContext,
        shares: &[RssShare<T>],
        to: usize,
    ) -> MpcResult<Option<Vec<T>>>;

    fn open_rss_to_multiple<T: NetSerializable + Add<Output=T> + Clone + DigestExt>(&mut self, context: &mut BroadcastContext, to_p1: &[RssShare<T>], to_p2: &[RssShare<T>], to_p3: &[RssShare<T>]) -> MpcResult<Vec<T>>;
}

impl Default for BroadcastContext {
    fn default() -> Self {
        BroadcastContext::new()
    }
}

impl BroadcastContext {
    pub fn new() -> Self {
        Self {
            view_next: Sha256::new(),
            view_prev: Sha256::new(),
        }
    }

    pub fn add_to_next_view<T: DigestExt>(&mut self, el: &T)
    {
        DigestExt::update(&mut self.view_next, slice::from_ref(el));
    }

    pub fn add_to_prev_view<T: DigestExt>(&mut self, el: &T)
    {
        DigestExt::update(&mut self.view_prev, slice::from_ref(el));
    }

    pub fn join(contexts: Vec<Self>) -> Self {
        let mut res = BroadcastContext::new();
        contexts.into_iter().for_each(|context| {
            let final_next = context.view_next.finalize();
            let final_prev = context.view_prev.finalize();
            Digest::update(&mut res.view_next, final_next);
            Digest::update(&mut res.view_prev, final_prev);
        });
        res
    }
}

impl Broadcast for MainParty {
    fn broadcast_round_bytes(
        &mut self,
        context: &mut BroadcastContext,
        buffer_next: &mut [u8],
        buffer_prev: &mut [u8],
        message: &[u8],
    ) -> MpcResult<()> {
        // first send to P+1
        self.io().send(Direction::Next, message.to_vec());
        // then send to P-1
        self.io().send(Direction::Previous, message.to_vec());
        // receive from P-1
        let receive_prev = self.io().receive(Direction::Previous, buffer_prev.len());
        // receive from P+1
        let receive_next = self.io().receive(Direction::Next, buffer_next.len());

        buffer_prev.copy_from_slice(&receive_prev.recv()?);
        Digest::update(&mut context.view_prev, buffer_prev);

        buffer_next.copy_from_slice(&receive_next.recv()?);
        Digest::update(&mut context.view_next, buffer_next);
        self.io().wait_for_completion();
        Ok(())
    }

    fn broadcast_round<T: NetSerializable + DigestExt>(
        &mut self,
        context: &mut BroadcastContext,
        buffer_next: &mut [T],
        buffer_prev: &mut [T],
        message: &[T],
    ) -> MpcResult<()>
    {
        // first send to P+1
        self.io()
            .send_field::<T>(Direction::Next, message, message.len());
        // then send to P-1
        self.io()
            .send_field::<T>(Direction::Previous, message, message.len());

        // receive from P-1
        let receive_prev = self
            .io()
            .receive_field_slice(Direction::Previous, buffer_prev);
        // receive from P+1
        let receive_next = self.io().receive_field_slice(Direction::Next, buffer_next);

        receive_prev.rcv()?;
        DigestExt::update(&mut context.view_prev, buffer_prev);

        receive_next.rcv()?;
        DigestExt::update(&mut context.view_next, buffer_next);
        self.io().wait_for_completion();
        Ok(())
    }

    fn open_rss<T: NetSerializable + Add<Output=T> + Clone + DigestExt>(
        &mut self,
        context: &mut BroadcastContext,
        share_i: &[T],
        share_ii: &[T],
    ) -> MpcResult<Vec<T>>
    {
        // send share_i to P+1
        self.io()
            .send_field::<T>(Direction::Next, share_i, share_i.len());
        // receive share_iii from P-1
        let rcv_share_iii = self.io().receive_field(Direction::Previous, share_i.len());

        // also update view_next as we would have received share_ii from P+1 (but due to RSS we know it already)
        DigestExt::update(&mut context.view_next, share_ii);

        let share_iii = rcv_share_iii.rcv()?;
        DigestExt::update(&mut context.view_prev, &share_iii);

        // reconstruct
        let mut value = Vec::with_capacity(share_i.len());
        for (i, siii) in share_iii.into_iter().enumerate() {
            value.push(share_i[i].clone() + share_ii[i].clone() + siii);
        }
        self.io().wait_for_completion();
        Ok(value)
    }

    fn open_rss_to<T: NetSerializable + Add<Output=T> + Clone + DigestExt>(
        &mut self,
        context: &mut BroadcastContext,
        shares: &[RssShare<T>],
        to: usize,
    ) -> MpcResult<Option<Vec<T>>>
    {
        match (self.i, to) {
            (0, 0) | (1, 1) | (2, 2) => {
                // receive share from P-1
                let siii = self
                    .io()
                    .receive_field(Direction::Previous, shares.len())
                    .rcv()?;
                DigestExt::update(&mut context.view_prev, &siii);
                self.io().wait_for_completion();
                // reconstruct
                Ok(Some(
                    shares
                        .iter()
                        .zip(siii)
                        .map(|(s, siii)| s.si.clone() + s.sii.clone() + siii)
                        .collect(),
                ))
            }
            (0, 1) | (1, 2) | (2, 0) => {
                //send my share to P+1
                self.io().send_field::<T>(
                    Direction::Next,
                    shares.iter().map(|s| &s.si),
                    shares.len(),
                );
                self.io().wait_for_completion();
                Ok(None)
            }
            (2, 1) | (0, 2) | (1, 0) => {
                // update my view of P+1 (who virtually sent sii)
                DigestExt::update(
                    &mut context.view_next,
                    &shares.iter().map(|s| s.sii.clone()).collect::<Vec<_>>(),
                );
                Ok(None)
            }
            _ => unreachable!(),
        }
    }

    fn open_rss_to_multiple<T: NetSerializable + Add<Output=T> + Clone + DigestExt>(&mut self, context: &mut BroadcastContext, to_p1: &[RssShare<T>], to_p2: &[RssShare<T>], to_p3: &[RssShare<T>]) -> MpcResult<Vec<T>>
    {
        let res1 = self.open_rss_to(context, to_p1, 0)?;
        let res2 = self.open_rss_to(context, to_p2, 1)?;
        let res3 = self.open_rss_to(context, to_p3, 2)?;
        match self.i {
            0 => {
                debug_assert!(res2.is_none());
                debug_assert!(res3.is_none());
                res1.ok_or(MpcError::Receive)
            },
            1 => {
                debug_assert!(res1.is_none());
                debug_assert!(res3.is_none());
                res2.ok_or(MpcError::Receive)
            },
            2 => {
                debug_assert!(res1.is_none());
                debug_assert!(res2.is_none());
                res3.ok_or(MpcError::Receive)
            },
            _ => unreachable!()
        }    
    }

    fn compare_view(&mut self, context: BroadcastContext) -> MpcResult<()> {
        // send my view of P-1 to P+1
        let view = context.view_prev.finalize_fixed();
        self.io().send(Direction::Next, view.to_vec());
        // receive P-1's view of P+1
        let mut view_next = [0u8; 256 / 8];
        let rcv_view_next = self.io().receive_slice(Direction::Previous, &mut view_next);

        let check_next = context.view_next.finalize_fixed();
        rcv_view_next.rcv()?;
        for i in 0..(256 / 8) {
            if view_next[i] != check_next[i] {
                return Err(MpcError::Broadcast);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BroadcastError;

impl Display for BroadcastError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("BroadcastError")
    }
}

impl Error for BroadcastError {}

#[cfg(test)]
mod test {
    use std::ops::Sub;

    use crate::rep3_core::network::task::Direction;
    use crate::rep3_core::party::broadcast::{Broadcast, BroadcastContext};
    use crate::rep3_core::party::error::MpcError;
    use crate::rep3_core::party::test::DummyNumber;
    use crate::rep3_core::party::test_export::{PartySetup, TestSetup};
    use crate::rep3_core::party::{DigestExt, MainParty, RngExt};
    use crate::rep3_core::share::{HasZero, RssShare};
    use rand::{thread_rng, CryptoRng, Rng};
    use sha2::digest::FixedOutput;
    use sha2::{Digest, Sha256};

    fn secret_share<F: Copy + Sub<Output=F> + RngExt, R: Rng + CryptoRng>(
        rng: &mut R,
        x: &F,
    ) -> (RssShare<F>, RssShare<F>, RssShare<F>) {
        let r = F::generate(rng, 2);
        let x1 = RssShare::from(*x - r[0] - r[1], r[0]);
        let x2 = RssShare::from(r[0], r[1]);
        let x3 = RssShare::from(r[1], *x - r[0] - r[1]);
        (x1, x2, x3)
    }

    #[test]
    fn broadcast_round() {
        let mut rng = thread_rng();
        const N: usize = 100;
        let x1 = DummyNumber::generate(&mut rng, N);
        let x2 = DummyNumber::generate(&mut rng, N);
        let x3 = DummyNumber::generate(&mut rng, N);

        let program = |msg: Vec<DummyNumber>| {
            move |p: &mut MainParty| {
                let mut context = BroadcastContext::new();
                let mut prev_buf = vec![DummyNumber::ZERO; N];
                let mut next_buf = vec![DummyNumber::ZERO; N];
                p.broadcast_round(&mut context, &mut next_buf, &mut prev_buf, &msg)
                    .unwrap();
                (context, prev_buf, next_buf)
            }
        };

        let (((c1, x13, x12), _), ((c2, x21, x23), _), ((c3, x32, x31), _)) = PartySetup::localhost_setup(
            program(x1.clone()),
            program(x2.clone()),
            program(x3.clone()),
        );

        assert_eq!(&x3, &x13);
        assert_eq!(&x2, &x12);
        assert_eq!(&x1, &x21);
        assert_eq!(&x3, &x23);
        assert_eq!(&x2, &x32);
        assert_eq!(&x1, &x31);

        fn expected_hash(v: &[DummyNumber]) -> Vec<u8> {
            let mut instance = Sha256::new();
            DigestExt::update(&mut instance, v);
            instance.finalize_fixed().to_vec()
        }
        let expected_x1 = expected_hash(&x1);
        let expected_x2 = expected_hash(&x2);
        let expected_x3 = expected_hash(&x3);
        fn check(expected: Vec<u8>, actual1: Sha256, actual2: Sha256) {
            assert_eq!(&expected, &actual1.finalize_fixed().to_vec());
            assert_eq!(&expected, &actual2.finalize_fixed().to_vec());
        }

        check(expected_x1, c2.view_prev, c3.view_next);
        check(expected_x2, c1.view_next, c3.view_prev);
        check(expected_x3, c2.view_next, c1.view_prev);
    }

    #[test]
    fn compare_view_ok() {
        let mut rng = thread_rng();
        const N: usize = 100;
        let x1 = DummyNumber::generate(&mut rng, N);
        let x2 = DummyNumber::generate(&mut rng, N);
        let x3 = DummyNumber::generate(&mut rng, N);
        let program = |msg: Vec<DummyNumber>| {
            move |p: &mut MainParty| {
                let mut context = BroadcastContext::new();
                let mut prev_buf = vec![DummyNumber::ZERO; N];
                let mut next_buf = vec![DummyNumber::ZERO; N];
                p.broadcast_round(&mut context, &mut next_buf, &mut prev_buf, &msg)
                    .unwrap();
                p.compare_view(context).unwrap();
            }
        };
        PartySetup::localhost_setup(
            program(x1.clone()),
            program(x2.clone()),
            program(x3.clone()),
        );
    }

    #[test]
    fn compare_view_fail() {
        fn cheating_setup(cheater: usize) {
            let mut rng = thread_rng();
            const N: usize = 100;
            let x1 = DummyNumber::generate(&mut rng, N);
            let x2 = DummyNumber::generate(&mut rng, N);
            let x3 = DummyNumber::generate(&mut rng, N);
            let program = |msg: Vec<DummyNumber>| {
                move |p: &mut MainParty| {
                    if p.i == cheater {
                        let mut context = BroadcastContext::new();
                        let mut prev_buf = vec![DummyNumber::ZERO; N];
                        let mut next_buf = vec![DummyNumber::ZERO; N];
                        p.io().send_field::<DummyNumber>(Direction::Next, &msg, msg.len());
                        // send the same message except for element N-1 that is different
                        p.io().send_field::<DummyNumber>(
                            Direction::Previous,
                            msg.iter().take(N - 1).chain(&vec![DummyNumber(msg[N - 1].0 ^ 0x1)]),
                            msg.len(),
                        );
                        let rcv_next = p.io().receive_field_slice(Direction::Next, &mut next_buf);
                        let rcv_prev = p
                            .io()
                            .receive_field_slice(Direction::Previous, &mut prev_buf);
                        rcv_next.rcv().unwrap();
                        rcv_prev.rcv().unwrap();
                        p.io().wait_for_completion();
                        DigestExt::update(&mut context.view_next, &next_buf);
                        DigestExt::update(&mut context.view_prev, &prev_buf);
                        p.compare_view(context).unwrap()
                    } else {
                        let mut context = BroadcastContext::new();
                        let mut prev_buf = vec![DummyNumber::ZERO; N];
                        let mut next_buf = vec![DummyNumber::ZERO; N];
                        p.broadcast_round(&mut context, &mut next_buf, &mut prev_buf, &msg)
                            .unwrap();
                        match p.compare_view(context) {
                            Ok(()) if (p.i + 1) % 3 != cheater => (), // ok! we only check the correctness of broadcast for the P+1
                            Err(MpcError::Broadcast) if (p.i + 1) % 3 == cheater => (), // ok!
                            _ => panic!("Expected broadcast error"),
                        }
                    }
                }
            };
            PartySetup::localhost_setup(
                program(x1.clone()),
                program(x2.clone()),
                program(x3.clone()),
            );
        }

        cheating_setup(0);
        // cheating_setup(1);
        // cheating_setup(2);
    }

    #[test]
    fn open_rss() {
        let mut rng = thread_rng();
        const N: usize = 100;
        let x = DummyNumber::generate(&mut rng, N);
        let mut x1 = Vec::new();
        let mut x2 = Vec::new();
        let mut x3 = Vec::new();
        for i in 0..N {
            let (s1, s2, s3) = secret_share(&mut rng, &x[i]);
            x1.push(s1);
            x2.push(s2);
            x3.push(s3);
        }

        let compute = |share: Vec<RssShare<DummyNumber>>| {
            move |p: &mut MainParty| {
                let mut context = BroadcastContext::new();
                let xi: Vec<_> = share.iter().map(|s| s.si.clone()).collect();
                let xii: Vec<_> = share.iter().map(|s| s.sii.clone()).collect();
                let res = p.open_rss(&mut context, &xi, &xii).unwrap();
                p.compare_view(context).unwrap();
                res
            }
        };

        let ((o1, _), (o2, _), (o3, _)) = PartySetup::localhost_setup(compute(x1), compute(x2), compute(x3));

        assert_eq!(&o1, &x);
        assert_eq!(&o2, &x);
        assert_eq!(&o3, &x);
    }

    #[test]
    fn open_rss_to() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let x = DummyNumber::generate(&mut rng, 3*N);
        let mut x1 = Vec::new();
        let mut x2 = Vec::new();
        let mut x3 = Vec::new();
        for i in 0..3 * N {
            let (s1, s2, s3) = secret_share(&mut rng, &x[i]);
            x1.push(s1);
            x2.push(s2);
            x3.push(s3);
        }

        let program = |x: Vec<RssShare<DummyNumber>>| {
            move |p: &mut MainParty| {
                let mut context = BroadcastContext::new();
                let open1 = p.open_rss_to(&mut context, &x[0..N], 0).unwrap();
                let open2 = p.open_rss_to(&mut context, &x[N..2 * N], 1).unwrap();
                let open3 = p.open_rss_to(&mut context, &x[2 * N..3 * N], 2).unwrap();
                p.compare_view(context).unwrap();
                match p.i {
                    0 => {
                        assert_eq!(open2, None);
                        assert_eq!(open3, None);
                        open1
                    }
                    1 => {
                        assert_eq!(open1, None);
                        assert_eq!(open3, None);
                        open2
                    }
                    2 => {
                        assert_eq!(open1, None);
                        assert_eq!(open2, None);
                        open3
                    }
                    _ => unreachable!(),
                }
            }
        };

        let ((open1, _), (open2, _), (open3, _)) = PartySetup::localhost_setup(program(x1), program(x2), program(x3));

        let open1 = open1.unwrap();
        let open2 = open2.unwrap();
        let open3 = open3.unwrap();

        assert_eq!(&open1, &x[0..N]);
        assert_eq!(&open2, &x[N..2 * N]);
        assert_eq!(&open3, &x[2 * N..3 * N]);
    }
}
