use std::time::{Duration, Instant};


use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::{aes::{self, GF8InvBlackBox}, benchmark::{BenchmarkProtocol, BenchmarkResult}, gf4_circuit, network::{task::IoLayerOwned, ConnectedParty}, party::{broadcast::{Broadcast, BroadcastContext}, error::{MpcError, MpcResult}, ArithmeticBlackBox, CombinedCommStats, MainParty, MulTripleRecorder, MulTripleVector, Party}, share::{gf4::BsGF4, gf8::GF8, FieldDigestExt, FieldRngExt, RssShare}, wollut16_malsec};


pub struct GF4CircuitASParty {
    inner: MainParty,
    check_after_sbox: bool,
    broadcast_context: BroadcastContext,
    gf4_triples_to_check: MulTripleVector<BsGF4>,
}

impl GF4CircuitASParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>, check_after_sbox: bool) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads).map(|party| Self {
            inner: party,
            check_after_sbox,
            broadcast_context: BroadcastContext::new(),
            gf4_triples_to_check: MulTripleVector::new(),
        })
    }

    pub fn verify_multiplications(&mut self) -> MpcResult<()> {
        if self.gf4_triples_to_check.len() > 0 {
            let res = if self.inner.has_multi_threading() {
                wollut16_malsec::mult_verification::verify_multiplication_triples_mt(&mut self.inner, &mut self.broadcast_context, &mut self.gf4_triples_to_check, &mut MulTripleVector::new())
            }else{
                wollut16_malsec::mult_verification::verify_multiplication_triples(&mut self.inner, &mut self.broadcast_context, &mut self.gf4_triples_to_check, &mut MulTripleVector::new())
            };
            match res {
                Ok(true) => Ok(()),
                Ok(false) => Err(MpcError::MultCheck),
                Err(err) => Err(err),
            }
        }else{
            Ok(())
        }
    }
}

pub struct GF4CircuitASBenchmark;
pub struct GF4CircuitAllCheckASBenchmark;

fn run(
    conn: ConnectedParty,
    simd: usize,
    n_worker_threads: Option<usize>,
    check_after_sbox: bool,
) -> BenchmarkResult {
    let mut party = GF4CircuitASParty::setup(conn, n_worker_threads, check_after_sbox).unwrap();
    let _setup_comm_stats = party.io().reset_comm_stats();
    println!("After setup");

    let input = aes::random_state(&mut party.inner, simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(&mut party.inner);

    let start = Instant::now();
    let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
    party.finalize().unwrap();
    let duration = start.elapsed();
    println!("After online");
    let online_comm_stats = party.io().reset_comm_stats();
    let _ = aes::output(&mut party, output).unwrap();
    println!("After output");
    party.inner.teardown().unwrap();
    println!("After teardown");

    BenchmarkResult::new(
        Duration::from_secs(0),
        duration,
        CombinedCommStats::empty(),
        online_comm_stats,
        party.inner.get_additional_timers(),
    )
}

impl BenchmarkProtocol for GF4CircuitASBenchmark {
    fn protocol_name(&self) -> String {
        "mal-gf4-circuit".to_string()
    }

    fn run(
            &self,
            conn: ConnectedParty,
            simd: usize,
            n_worker_threads: Option<usize>,
        ) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, false)
    }
    
}

impl BenchmarkProtocol for GF4CircuitAllCheckASBenchmark {
    fn protocol_name(&self) -> String {
        "mal-gf4-circuit-all-check".to_string()
    }

    fn run(
            &self,
            conn: ConnectedParty,
            simd: usize,
            n_worker_threads: Option<usize>,
        ) -> BenchmarkResult {
        run(conn, simd, n_worker_threads, true)
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

    fn generate_alpha(&mut self, n: usize) -> Vec<GF8> {
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

    fn output_to(&mut self, to_p1: &[RssShare<GF8>], to_p2: &[RssShare<GF8>], to_p3: &[RssShare<GF8>]) -> MpcResult<Vec<GF8>> {
        self.inner.open_rss_to_multiple(&mut self.broadcast_context, to_p1, to_p2, to_p3)
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
        Ok(())
    }
    fn gf8_inv(&mut self, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
        if self.inner.has_multi_threading() && si.len() >= 2 * self.inner.num_worker_threads() {
            gf4_circuit::gf8_inv_via_gf4_mul_opt_mt(&mut self.inner, &mut self.gf4_triples_to_check, si, sii)?;
        } else {
            gf4_circuit::gf8_inv_via_gf4_mul_opt(&mut self.inner, &mut self.gf4_triples_to_check, si, sii)?;
        }
        if self.check_after_sbox {
            self.verify_multiplications()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::thread::JoinHandle;

    use crate::{aes::test::{test_aes128_keyschedule_gf8, test_aes128_no_keyschedule_gf8, test_inv_aes128_no_keyschedule_gf8, test_sub_bytes}, network::ConnectedParty, party::test::{localhost_connect, TestSetup}};

    use super::GF4CircuitASParty;


    fn localhost_setup_gf4_circuit_as<T1: Send + 'static, F1: Send + FnOnce(&mut GF4CircuitASParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut GF4CircuitASParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut GF4CircuitASParty) -> T3 + 'static>(f1: F1, f2: F2, f3: F3, n_worker_threads: Option<usize>) -> (JoinHandle<(T1,GF4CircuitASParty)>, JoinHandle<(T2,GF4CircuitASParty)>, JoinHandle<(T3,GF4CircuitASParty)>) {
        fn adapter<T, Fx: FnOnce(&mut GF4CircuitASParty)->T>(conn: ConnectedParty, f: Fx, n_worker_threads: Option<usize>) -> (T,GF4CircuitASParty) {
            let mut party = GF4CircuitASParty::setup(conn, n_worker_threads, false).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(move |conn_party| adapter(conn_party, f1, n_worker_threads), move |conn_party| adapter(conn_party, f2, n_worker_threads), move |conn_party| adapter(conn_party, f3, n_worker_threads))
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
            localhost_setup_gf4_circuit_as(f1, f2, f3, None)
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
            localhost_setup_gf4_circuit_as(f1, f2, f3, Some(n_worker_threads))
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
    
}
