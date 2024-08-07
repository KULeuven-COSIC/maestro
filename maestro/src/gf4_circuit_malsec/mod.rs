
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::{aes::GF8InvBlackBox, furukawa, gf4_circuit, network::{task::IoLayerOwned, ConnectedParty}, party::{broadcast::{Broadcast, BroadcastContext}, error::{MpcError, MpcResult}, ArithmeticBlackBox, MainParty, MulTripleRecorder, MulTripleVector, Party}, share::{gf4::BsGF4, gf8::GF8, FieldDigestExt, FieldRngExt, RssShare}, wollut16_malsec};

mod offline;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MultCheckType {
    /// recursive mult. check at the end of the online phase
    Recursive { check_after_sbox: bool},
    /// recursive mult. check to create beaver triples, then sacrifice
    RecursiveBeaver,
    /// Bucket cut-and-choose to create beaver triples, then sacrifice
    BucketBeaver,
}

pub struct GF4CircuitASParty {
    inner: MainParty,
    broadcast_context: BroadcastContext,
    gf4_triples_to_check: MulTripleVector<BsGF4>,
    check_type: MultCheckType,
    gf4_beaver_triples: MulTripleVector<BsGF4>,
}

impl GF4CircuitASParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, check_type: MultCheckType) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads).map(|party| Self {
            inner: party,
            broadcast_context: BroadcastContext::new(),
            gf4_triples_to_check: MulTripleVector::new(),
            check_type,
            gf4_beaver_triples: MulTripleVector::new(),
        })
    }

    pub fn verify_multiplications(&mut self) -> MpcResult<()> {
        if self.gf4_triples_to_check.len() > 0 {
            match self.check_type {
                MultCheckType::Recursive { .. } => {
                    let res = if self.inner.has_multi_threading() {
                        wollut16_malsec::mult_verification::verify_multiplication_triples_mt(&mut self.inner, &mut self.broadcast_context, &mut self.gf4_triples_to_check, &mut MulTripleVector::new(), &mut MulTripleVector::new(), false)
                    }else{
                        wollut16_malsec::mult_verification::verify_multiplication_triples(&mut self.inner, &mut self.broadcast_context, &mut self.gf4_triples_to_check, &mut MulTripleVector::new(), &mut MulTripleVector::new(), false)
                    };
                    match res {
                        Ok(true) => Ok(()),
                        Ok(false) => Err(MpcError::MultCheck),
                        Err(err) => Err(err),
                    }
                },
                MultCheckType::RecursiveBeaver | MultCheckType::BucketBeaver => {
                    let n = self.gf4_triples_to_check.len();
                    if self.gf4_beaver_triples.len() < n {
                        panic!("Not enough beaver triples left to sacrifice!");
                    }
                    let from = self.gf4_beaver_triples.len() - n;
                    let (ai, aii, bi, bii, ci, cii) = self.gf4_beaver_triples.as_mut_slices();
                    let res = if self.inner.has_multi_threading() {
                        furukawa::offline::sacrifice_mt(&mut self.inner, n, 1, self.gf4_triples_to_check.ai(), self.gf4_triples_to_check.aii(), self.gf4_triples_to_check.bi(), self.gf4_triples_to_check.bii(), self.gf4_triples_to_check.ci(), self.gf4_triples_to_check.cii(), &mut ai[from..], &mut aii[from..], &mut bi[from..], &mut bii[from..], &mut ci[from..], &mut cii[from..])
                    }else{
                        furukawa::offline::sacrifice(&mut self.inner, n, 1, self.gf4_triples_to_check.ai(), self.gf4_triples_to_check.aii(), self.gf4_triples_to_check.bi(), self.gf4_triples_to_check.bii(), self.gf4_triples_to_check.ci(), self.gf4_triples_to_check.cii(), &mut ai[from..], &mut aii[from..], &mut bi[from..], &mut bii[from..], &mut ci[from..], &mut cii[from..])
                    };
                    self.gf4_beaver_triples.shrink(from);
                    res
                }
            }
        }else{
            Ok(())
        }
    }
}

impl ArithmeticBlackBox<GF8> for GF4CircuitASParty
where
    ChaCha20Rng: FieldRngExt<GF8>,
    Sha256: FieldDigestExt<GF8>,
{
    type Rng = ChaCha20Rng;
    type Digest = Sha256;

    fn pre_processing(&mut self, _n_multiplications: usize) -> MpcResult<()> {
       // nothing to do
        Ok(())
    }

    fn io(&self) -> &IoLayerOwned {
        self.inner.io()
    }

    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }

    fn generate_random(&mut self, n: usize) -> Vec<RssShare<GF8>> {
        self.inner.generate_random(n)
    }

    fn generate_alpha(&mut self, n: usize) -> impl Iterator<Item=GF8> {
        self.inner.generate_alpha(n)
    }

    fn input_round(&mut self, _my_input: &[GF8]) -> MpcResult<(Vec<RssShare<GF8>>, Vec<RssShare<GF8>>, Vec<RssShare<GF8>>)> {
        unimplemented!()
    }

    fn mul(&mut self, _ci: &mut [GF8], _cii: &mut [GF8], _ai: &[GF8], _aii: &[GF8], _bi: &[GF8], _bii: &[GF8]) -> MpcResult<()> {
        unimplemented!()
    }

    fn output_round(&mut self, si: &[GF8], sii: &[GF8]) -> MpcResult<Vec<GF8>> {
        self.inner.open_rss(&mut self.broadcast_context, si, sii)
    }

    fn finalize(&mut self) -> MpcResult<()> {
        self.verify_multiplications()?;
        let context = std::mem::replace(&mut self.broadcast_context, BroadcastContext::new());
        self.inner.compare_view(context)
    }
}

impl GF8InvBlackBox for GF4CircuitASParty {
    fn constant(&self, value: GF8) -> RssShare<GF8> {
        self.inner.constant(value)
    }
    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        let n_mul_ks = (4 * 10 * n_keys * 5)/2; // 4 S-boxes per round, 10 rounds, 5 mult. per S-box (but 2 GF4 elements are packed together)
        let n_mul = (16 * 10 * n_blocks * 5)/2; // 16 S-boxes per round, 10 rounds, 5 mult. per S-box (but 2 GF4 elements are packed together)
        // allocate more memory for triples
        self.gf4_triples_to_check.reserve_for_more_triples(n_mul_ks + n_mul);
        match self.check_type {
            MultCheckType::Recursive { .. } => (), // no additional preprocessing
            MultCheckType::RecursiveBeaver => {
                // compute n_mul_ks + n_mul many beaver triples and check them using recursive check
                self.gf4_beaver_triples.reserve_for_more_triples(n_mul_ks + n_mul);
                offline::prepare_beaver_triples_recursive_check(&mut self.inner, &mut self.gf4_beaver_triples, &mut self.broadcast_context, n_mul_ks + n_mul)?;
            },
            MultCheckType::BucketBeaver => {
                // compute n_mul_ks + n_mul many beaver triples and check them using cut-and-choose
                offline::prepare_beaver_triples_bucket(&mut self.inner, &mut self.gf4_beaver_triples, n_mul_ks + n_mul)?;
            }
        }
        Ok(())
    }
    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        if self.inner.has_multi_threading() && si.len() >= 2 * self.inner.num_worker_threads() {
            gf4_circuit::gf8_inv_via_gf4_mul_opt_mt(&mut self.inner, &mut self.gf4_triples_to_check, si, sii)?;
        } else {
            gf4_circuit::gf8_inv_via_gf4_mul_opt(&mut self.inner, &mut self.gf4_triples_to_check, si, sii)?;
        }
        if let MultCheckType::Recursive { check_after_sbox: true } = self.check_type {
            self.verify_multiplications()?;
        }
        Ok(())
    }
    fn main_party_mut(&mut self) -> &mut MainParty {
        &mut self.inner
    }
}

#[cfg(test)]
mod test {
    use std::thread::JoinHandle;

    use crate::{aes::test::{test_aes128_keyschedule_gf8, test_aes128_no_keyschedule_gf8, test_inv_aes128_no_keyschedule_gf8, test_sub_bytes}, network::ConnectedParty, party::test::{localhost_connect, TestSetup}};

    use super::{GF4CircuitASParty, MultCheckType};


    fn localhost_setup_gf4_circuit_as<T1: Send + 'static, F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3 + 'static>(f1: F1, f2: F2, f3: F3, n_worker_threads: Option<usize>, check_type: MultCheckType) -> (JoinHandle<(T1,GF4CircuitASParty)>, JoinHandle<(T2,GF4CircuitASParty)>, JoinHandle<(T3,GF4CircuitASParty)>) {
        fn adapter<T, Fx: FnOnce(&mut GF4CircuitASParty)->T>(conn: ConnectedParty, f: Fx, n_worker_threads: Option<usize>, check_type: MultCheckType) -> (T,GF4CircuitASParty) {
            let mut party = GF4CircuitASParty::setup(conn, n_worker_threads, check_type).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(move |conn_party| adapter(conn_party, f1, n_worker_threads, check_type), move |conn_party| adapter(conn_party, f2, n_worker_threads, check_type), move |conn_party| adapter(conn_party, f3, n_worker_threads, check_type))
    }

    pub struct GF4CircuitAsSetup;
    impl TestSetup<GF4CircuitASParty> for GF4CircuitAsSetup {
        fn localhost_setup<
                    T1: Send + 'static,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1 + 'static,
                    T2: Send + 'static,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2 + 'static,
                    T3: Send + 'static,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3 + 'static,
                >(f1: F1, f2: F2, f3: F3) -> (
                    JoinHandle<(T1, GF4CircuitASParty)>,
                    JoinHandle<(T2, GF4CircuitASParty)>,
                    JoinHandle<(T3, GF4CircuitASParty)>,
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, None, MultCheckType::Recursive { check_after_sbox: false })
        }

        fn localhost_setup_multithreads<
                    T1: Send + 'static,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1 + 'static,
                    T2: Send + 'static,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2 + 'static,
                    T3: Send + 'static,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3 + 'static,
                >(n_worker_threads: usize, f1: F1, f2: F2, f3: F3) -> (
                    JoinHandle<(T1, GF4CircuitASParty)>,
                    JoinHandle<(T2, GF4CircuitASParty)>,
                    JoinHandle<(T3, GF4CircuitASParty)>,
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, Some(n_worker_threads), MultCheckType::Recursive { check_after_sbox: false })
        }
    }

    #[test]
    fn sub_bytes() {
        test_sub_bytes::<GF4CircuitAsSetup,_>(None)
    }

    #[test]
    fn sub_bytes_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<GF4CircuitAsSetup,_>(Some(N_THREADS))
    }

    #[test]
    fn aes128_keyschedule() {
        test_aes128_keyschedule_gf8::<GF4CircuitAsSetup, _>(None)
    }

    #[test]
    fn aes128_keyschedule_mt() {
        const N_THREADS: usize = 3;
        test_aes128_keyschedule_gf8::<GF4CircuitAsSetup, _>(Some(N_THREADS))
    }

    #[test]
    fn aes_128_no_keyschedule() {
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsSetup, _>(100, Some(N_THREADS))
    }

    #[test]
    fn inv_aes128_no_keyschedule() {
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsSetup, _>(1, None)
    }

    #[test]
    fn inv_aes128_no_keyschedule_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsSetup, _>(100, Some(N_THREADS))
    }

    pub struct GF4CircuitAsBucketBeaverSetup;
    impl TestSetup<GF4CircuitASParty> for GF4CircuitAsBucketBeaverSetup {
        fn localhost_setup<
                    T1: Send + 'static,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1 + 'static,
                    T2: Send + 'static,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2 + 'static,
                    T3: Send + 'static,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3 + 'static,
                >(f1: F1, f2: F2, f3: F3) -> (
                    JoinHandle<(T1, GF4CircuitASParty)>,
                    JoinHandle<(T2, GF4CircuitASParty)>,
                    JoinHandle<(T3, GF4CircuitASParty)>,
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, None, MultCheckType::BucketBeaver)
        }

        fn localhost_setup_multithreads<
                    T1: Send + 'static,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1 + 'static,
                    T2: Send + 'static,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2 + 'static,
                    T3: Send + 'static,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3 + 'static,
                >(n_worker_threads: usize, f1: F1, f2: F2, f3: F3) -> (
                    JoinHandle<(T1, GF4CircuitASParty)>,
                    JoinHandle<(T2, GF4CircuitASParty)>,
                    JoinHandle<(T3, GF4CircuitASParty)>,
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, Some(n_worker_threads), MultCheckType::BucketBeaver)
        }
    }
    
    #[test]
    fn sub_bytes_bucket_beaver_check() {
        test_sub_bytes::<GF4CircuitAsBucketBeaverSetup,_>(None)
    }

    #[test]
    fn sub_bytes_bucket_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<GF4CircuitAsBucketBeaverSetup,_>(Some(N_THREADS))
    }

    #[test]
    fn aes128_keyschedule_bucket_beaver_check() {
        test_aes128_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(None)
    }

    #[test]
    fn aes128_keyschedule_bucket_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_aes128_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(Some(N_THREADS))
    }

    #[test]
    fn aes_128_no_keyschedule_bucket_beaver_check() {
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_bucket_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(100, Some(N_THREADS))
    }

    #[test]
    fn inv_aes128_no_keyschedule_bucket_beaver_check() {
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(1, None)
    }

    #[test]
    fn inv_aes128_no_keyschedule_bucket_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsBucketBeaverSetup, _>(100, Some(N_THREADS))
    }

    pub struct GF4CircuitAsRecBeaverSetup;
    impl TestSetup<GF4CircuitASParty> for GF4CircuitAsRecBeaverSetup {
        fn localhost_setup<
                    T1: Send + 'static,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1 + 'static,
                    T2: Send + 'static,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2 + 'static,
                    T3: Send + 'static,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3 + 'static,
                >(f1: F1, f2: F2, f3: F3) -> (
                    JoinHandle<(T1, GF4CircuitASParty)>,
                    JoinHandle<(T2, GF4CircuitASParty)>,
                    JoinHandle<(T3, GF4CircuitASParty)>,
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, None, MultCheckType::RecursiveBeaver)
        }

        fn localhost_setup_multithreads<
                    T1: Send + 'static,
                    F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1 + 'static,
                    T2: Send + 'static,
                    F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2 + 'static,
                    T3: Send + 'static,
                    F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3 + 'static,
                >(n_worker_threads: usize, f1: F1, f2: F2, f3: F3) -> (
                    JoinHandle<(T1, GF4CircuitASParty)>,
                    JoinHandle<(T2, GF4CircuitASParty)>,
                    JoinHandle<(T3, GF4CircuitASParty)>,
                ) {
            localhost_setup_gf4_circuit_as(f1, f2, f3, Some(n_worker_threads), MultCheckType::RecursiveBeaver)
        }
    }

    #[test]
    fn sub_bytes_rec_beaver_check() {
        test_sub_bytes::<GF4CircuitAsRecBeaverSetup,_>(None)
    }

    #[test]
    fn sub_bytes_rec_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_sub_bytes::<GF4CircuitAsRecBeaverSetup,_>(Some(N_THREADS))
    }

    #[test]
    fn aes128_keyschedule_rec_beaver_check() {
        test_aes128_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(None)
    }

    #[test]
    fn aes128_keyschedule_rec_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_aes128_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(Some(N_THREADS))
    }

    #[test]
    fn aes_128_no_keyschedule_rec_beaver_check() {
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_rec_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_aes128_no_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(100, Some(N_THREADS))
    }

    #[test]
    fn inv_aes128_no_keyschedule_rec_beaver_check() {
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(1, None)
    }

    #[test]
    fn inv_aes128_no_keyschedule_rec_beaver_check_mt() {
        const N_THREADS: usize = 3;
        test_inv_aes128_no_keyschedule_gf8::<GF4CircuitAsRecBeaverSetup, _>(100, Some(N_THREADS))
    }
}
