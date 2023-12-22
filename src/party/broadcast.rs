use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use sha2::{Sha256, Digest};
use sha2::digest::FixedOutput;
use crate::network::CommChannel;
use crate::party::error::{MpcError, MpcResult};
use crate::party::Party;
use crate::share::{Field, FieldDigestExt, FieldVectorCommChannel, RssShare};

pub struct BroadcastContext{
    view_next: Sha256,
    view_prev: Sha256
}

pub trait Broadcast {
    fn broadcast_round_bytes(&mut self, context: &mut BroadcastContext, buffer_next: &mut[u8], buffer_prev: &mut[u8], message: &[u8]) -> MpcResult<()>;

    fn broadcast_round<F: Field>(&mut self, context: &mut BroadcastContext, buffer_next: &mut[F], buffer_prev: &mut[F], message: &[F]) -> MpcResult<()>
        where CommChannel: FieldVectorCommChannel<F>, Sha256: FieldDigestExt<F>;

    fn open_rss<F: Field>(&mut self, context: &mut BroadcastContext, share_i: &[F], share_ii: &[F]) -> MpcResult<Vec<F>> where CommChannel: FieldVectorCommChannel<F>, Sha256: FieldDigestExt<F>;

    fn compare_view(&mut self, context: BroadcastContext) -> MpcResult<()>;

    fn open_rss_to<F: Field>(&mut self, context: &mut BroadcastContext, shares: &[RssShare<F>], to: usize) -> MpcResult<Option<Vec<F>>> where CommChannel: FieldVectorCommChannel<F>, Sha256: FieldDigestExt<F>;
}

impl BroadcastContext {
    pub fn new() -> Self {
        Self {
            view_next: Sha256::new(),
            view_prev: Sha256::new(),
        }
    }

}

impl Broadcast for Party {
    fn broadcast_round_bytes(&mut self, context: &mut BroadcastContext, buffer_next: &mut [u8], buffer_prev: &mut[u8], message: &[u8]) -> MpcResult<()> {
        // first send to P+1
        self.comm_next.write(message)?;
        // receive from P-1
        self.comm_prev.read(buffer_prev)?;
        Digest::update(&mut context.view_prev, buffer_prev);

        // then send to P-1
        self.comm_prev.write(message)?;
        // receive from P+1
        self.comm_next.read(buffer_next)?;
        Digest::update(&mut context.view_next, buffer_next);
        Ok(())
    }

    fn broadcast_round<F: Field>(&mut self, context: &mut BroadcastContext, buffer_next: &mut [F], buffer_prev: &mut[F], message: &[F]) -> MpcResult<()>
        where CommChannel: FieldVectorCommChannel<F>, Sha256: FieldDigestExt<F>{
        // first send to P+1
        self.comm_next.write_vector(message)?;
        // receive from P-1
        self.comm_prev.read_vector(buffer_prev)?;
        FieldDigestExt::update(&mut context.view_prev, buffer_prev);

        // then send to P-1
        self.comm_prev.write_vector(message)?;
        // receive from P+1
        self.comm_next.read_vector(buffer_next)?;
        FieldDigestExt::update(&mut context.view_next, buffer_next);
        Ok(())
    }

    fn open_rss<F: Field>(&mut self, context: &mut BroadcastContext, share_i: &[F], share_ii: &[F]) -> MpcResult<Vec<F>>
    where CommChannel: FieldVectorCommChannel<F>,
    Sha256: FieldDigestExt<F>
    {
        // send share_i to P+1
        self.comm_next.write_vector(share_i)?;
        // receive share_iii from P-1
        let mut share_iii = vec![F::zero(); share_i.len()];
        self.comm_prev.read_vector(&mut share_iii)?;
        FieldDigestExt::update(&mut context.view_prev, &share_iii);

        // also update view_next as we would have received share_ii from P+1 (but due to RSS we know it already)
        FieldDigestExt::update(&mut context.view_next, &share_ii);

        // reconstruct
        let mut value = Vec::with_capacity(share_i.len());
        for (i, siii) in share_iii.into_iter().enumerate() {
            value.push(share_i[i].clone() + share_ii[i].clone() + siii);
        }
        Ok(value)
    }

    fn open_rss_to<F: Field>(&mut self, context: &mut BroadcastContext, shares: &[RssShare<F>], to: usize) -> MpcResult<Option<Vec<F>>>
        where CommChannel: FieldVectorCommChannel<F>, Sha256: FieldDigestExt<F>
    {
        match (self.i, to) {
            (0,0) | (1,1) | (2,2) => {
                // receive share from P-1
                let mut siii = vec![F::zero(); shares.len()];
                self.comm_prev.read_vector(&mut siii)?;
                FieldDigestExt::update(&mut context.view_prev, &siii);
                // reconstruct
                Ok(Some(shares.iter().zip(siii).map(|(s, siii)| s.si.clone() + s.sii.clone() + siii).collect()))
            },
            (0, 1) | (1,2) | (2,0) => {
                //send my share to P+1
                self.comm_next.write_vector(&shares.iter().map(|s| s.si.clone()).collect::<Vec<_>>())?;
                Ok(None)
            },
            (2,1) | (0,2) | (1,0) => {
                // update my view of P+1 (who virtually sent sii)
                FieldDigestExt::update(&mut context.view_next, &shares.iter().map(|s| s.sii.clone()).collect::<Vec<_>>());
                Ok(None)
            }
            _ => unreachable!()
        }
    }


    fn compare_view(&mut self, context: BroadcastContext) -> MpcResult<()> {
        // send my view of P-1 to P+1
        let view = context.view_prev.finalize_fixed();
        self.comm_next.write(&view)?;
        // receive P-1's view of P+1
        let mut view_next = [0u8; 256/8];
        self.comm_prev.read(&mut view_next)?;

        let check_next = context.view_next.finalize_fixed();
        for i in 0..(256/8) {
            if view_next[i] != check_next[i] {
                return Err(MpcError::BroadcastError);
            }
        }
        return Ok(())
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
    use rand::thread_rng;
    use crate::party::broadcast::{Broadcast, BroadcastContext};
    use crate::party::Party;
    use crate::party::test::localhost_setup;
    use crate::share::{FieldRngExt, RssShare};
    use crate::share::field::GF8;
    use crate::share::test::secret_share;

    #[test]
    fn open_rss_gf8() {
        let mut rng = thread_rng();
        const N: usize = 100;
        let x = rng.generate(N);
        let mut x1 = Vec::new();
        let mut x2 = Vec::new();
        let mut x3 = Vec::new();
        for i in 0..N {
            let (s1,s2,s3) = secret_share(&mut rng, &x[i]);
            x1.push(s1);
            x2.push(s2);
            x3.push(s3);
        }

        let compute = |share: Vec<RssShare<GF8>>| {
            move |p: &mut Party| {
                let mut context = BroadcastContext::new();
                let xi: Vec<_> = share.iter().map(|s|s.si.clone()).collect();
                let xii: Vec<_> = share.iter().map(|s|s.sii.clone()).collect();
                let res = p.open_rss(&mut context, &xi, &xii).unwrap();
                p.compare_view(context).unwrap();
                res
            }
        };

        let (h1, h2, h3) = localhost_setup(compute(x1), compute(x2), compute(x3));
        let (o1, _) = h1.join().unwrap();
        let (o2, _) = h2.join().unwrap();
        let (o3, _) = h3.join().unwrap();

        assert_eq!(&o1, &x);
        assert_eq!(&o2, &x);
        assert_eq!(&o3, &x);
    }

    #[test]
    fn open_rss_to_gf8() {
        const N: usize = 100;
        let mut rng = thread_rng();
        let x = rng.generate(3*N);
        let mut x1 = Vec::new();
        let mut x2 = Vec::new();
        let mut x3 = Vec::new();
        for i in 0..3*N {
            let (s1,s2,s3) = secret_share(&mut rng, &x[i]);
            x1.push(s1);
            x2.push(s2);
            x3.push(s3);
        }

        let program = |x: Vec<RssShare<GF8>>| {
            move |p: &mut Party| {
                let mut context = BroadcastContext::new();
                let open1 = p.open_rss_to(&mut context, &x[0..N], 0).unwrap();
                let open2 = p.open_rss_to(&mut context, &x[N..2*N], 1).unwrap();
                let open3 = p.open_rss_to(&mut context, &x[2*N..3*N], 2).unwrap();
                p.compare_view(context).unwrap();
                match p.i {
                    0 => {
                        assert_eq!(open2, None);
                        assert_eq!(open3, None);
                        open1
                    },
                    1 => {
                        assert_eq!(open1, None);
                        assert_eq!(open3, None);
                        open2
                    },
                    2 => {
                        assert_eq!(open1, None);
                        assert_eq!(open2, None);
                        open3
                    }
                    _ => unreachable!()
                }
            }
        };

        let (h1, h2, h3) = localhost_setup(program(x1), program(x2), program(x3));
        let (open1, _) = h1.join().unwrap();
        let (open2, _) = h2.join().unwrap();
        let (open3, _) = h3.join().unwrap();

        let open1 = open1.unwrap();
        let open2 = open2.unwrap();
        let open3 = open3.unwrap();

        assert_eq!(&open1, &x[0..N]);
        assert_eq!(&open2, &x[N..2*N]);
        assert_eq!(&open3, &x[2*N..3*N]);
    }
}
