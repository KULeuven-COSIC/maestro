use std::time::Instant;

use itertools::izip;
use rayon::{iter::{IndexedParallelIterator, ParallelIterator}, slice::{ParallelSlice, ParallelSliceMut}};

use crate::{aes::{self, ss::GF8InvBlackBoxSS}, benchmark::{BenchmarkProtocol, BenchmarkResult}, network::{task::Direction, ConnectedParty}, party::{error::MpcResult, MainParty, NoMulTripleRecording, Party}, share::{gf8::GF8, Field}};

use super::{lut256_tables, offline, RndOhv256OutputSS};

pub struct Lut256SSParty {
    inner: MainParty,
    prep_ohv: Vec<RndOhv256OutputSS>,
}

pub struct Lut256SSBenchmark;

impl Lut256SSParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads).map(|inner| Self {
            inner,
            prep_ohv: Vec::new(),
        })
    }
}

impl BenchmarkProtocol for Lut256SSBenchmark {
    fn protocol_name(&self) -> String {
        "lut256_ss".to_string()
    }
    fn run(
            &self,
            conn: ConnectedParty,
            simd: usize,
            n_worker_threads: Option<usize>,
        ) -> BenchmarkResult {
            let mut party = Lut256SSParty::setup(conn, n_worker_threads).unwrap();
            let _setup_comm_stats = party.inner.io().reset_comm_stats();
            println!("After setup");
            let start_prep = Instant::now();
            party.do_preprocessing(0, simd).unwrap();
            let prep_duration = start_prep.elapsed();
            let prep_comm_stats = party.inner.io().reset_comm_stats();
            println!("After pre-processing");
            let input = aes::ss::random_state(&mut party.inner, simd);
            // create random key states for benchmarking purposes
            let ks = aes::random_keyschedule(&mut party.inner);
    
            let start = Instant::now();
            let output = aes::ss::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
            let duration = start.elapsed();
            println!("After online");
            let online_comm_stats = party.inner.io().reset_comm_stats();
            let _ = aes::ss::output(&mut party, output).unwrap();
            println!("After output");
            party.inner.teardown().unwrap();
            println!("After teardown");
    
            BenchmarkResult::new(
                prep_duration,
                duration,
                prep_comm_stats,
                online_comm_stats,
                party.inner.get_additional_timers(),
            )
    }
}

impl GF8InvBlackBoxSS for Lut256SSParty {

    fn constant(&self, value: GF8) -> GF8 {
        if self.inner.i == 0 {
            value
        }else{
            GF8::ZERO
        }
    }

    fn do_preprocessing(&mut self, n_keys: usize, n_blocks: usize) -> MpcResult<()> {
        let n_rnd_ohv_ks = 4 * 10 * n_keys; // 4 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_rnd_ohv = 16 * 10 * n_blocks; // 16 S-boxes per round, 10 rounds, 1 LUT per S-box
        let n_prep = n_rnd_ohv + n_rnd_ohv_ks;

        let mut prep =
            if self.inner.has_multi_threading() && 2 * n_prep > self.inner.num_worker_threads() {
                offline::generate_rndohv256_ss_mt(&mut self.inner, &mut NoMulTripleRecording,  n_prep)?
            } else {
                offline::generate_rndohv256_ss(&mut self.inner, &mut NoMulTripleRecording, n_prep)?
            };
        if self.prep_ohv.is_empty() {
            self.prep_ohv = prep;
        } else {
            self.prep_ohv.append(&mut prep);
        }
        Ok(())
    }

    fn gf8_inv(&mut self, s: &mut [GF8]) -> MpcResult<()> {
        let n = s.len();
        if self.prep_ohv.len() < n {
            panic!("Not enough pre-processed random one-hot vectors available. Use LUT256SSParty::do_preprocessing to generate them.");
        }

        let rnd_ohv = &self.prep_ohv[self.prep_ohv.len() - n..];
        let rcv_cii = self.inner.io().receive_field(Direction::Next, s.len());
        let rcv_ciii = self.inner.io().receive_field(Direction::Previous, s.len());

        izip!(s.iter_mut(), self.inner.generate_alpha::<GF8>(n), rnd_ohv.iter())
            .for_each(|(dst, alpha, ohv)| {
                *dst += alpha + ohv.random_si
            });
        self.inner.io().send_field::<GF8>(Direction::Next, s.iter(), n);
        self.inner.io().send_field::<GF8>(Direction::Previous, s.iter(), n);

        let cii = rcv_cii.rcv()?;
        s.iter_mut().zip(cii).for_each(|(dst, cii)| *dst += cii);
        let ciii = rcv_ciii.rcv()?;
        s.iter_mut().zip(ciii).for_each(|(dst, ciii)| *dst += ciii);

        if self.inner.has_multi_threading() && 2 * n > self.inner.num_worker_threads() {
            let ranges = self.inner.split_range_equally(n);
            let chunk_size = ranges[0].1 - ranges[0].0;

            self.inner.run_in_threadpool(|| {
                s.par_chunks_mut(chunk_size).zip_eq(rnd_ohv.par_chunks(chunk_size)).for_each(|(s_chunk, ohv_chunk)| {
                    s_chunk.iter_mut().zip(ohv_chunk).for_each(|(dst, ohv)| {
                        *dst = ohv.ohv.lut(dst.0 as usize, &lut256_tables::GF8_INV_BITSLICED_LUT);
                    });
                });
                Ok(())
            })?;
        }else{
            s.iter_mut().zip(rnd_ohv).for_each(|(dst, ohv)| {
                *dst = ohv.ohv.lut(dst.0 as usize, &lut256_tables::GF8_INV_BITSLICED_LUT);
            });
        }
        
        self.prep_ohv.truncate(self.prep_ohv.len() - n);
        self.inner.wait_for_completion();
        Ok(())
    }

    fn finalize(&mut self) -> MpcResult<()> {
        // for semi-honest security, nothing to do
        Ok(())
    }

    fn output(&mut self, data: &[GF8]) -> MpcResult<Vec<GF8>> {
        let rcv_data_ii = self.inner.io().receive_field(Direction::Next, data.len());
        let rcv_data_iii = self.inner.io().receive_field(Direction::Previous, data.len());
        self.inner.io().send_field::<GF8>(Direction::Next, data.iter(), data.len());
        self.inner.io().send_field::<GF8>(Direction::Previous, data.iter(), data.len());

        let data_ii = rcv_data_ii.rcv()?;
        let data_iii = rcv_data_iii.rcv()?;
        let res = izip!(data, data_ii, data_iii).map(|(&si, sii, siii)| si + sii + siii).collect();
        self.inner.io().wait_for_completion();
        Ok(res)
    }

}

#[cfg(test)]
mod test {
    use std::thread::JoinHandle;

    use crate::{aes::ss::test::{test_aes128_no_keyschedule_gf8_ss, test_inv_aes128_no_keyschedule_gf8_ss, test_sub_bytes_ss}, network::ConnectedParty, party::test::{localhost_connect, TestSetup}};

    use super::Lut256SSParty;

    fn localhost_setup_lut256_ss<
        T1: Send + 'static,
        F1: Send + FnOnce(&mut Lut256SSParty) -> T1 + 'static,
        T2: Send + 'static,
        F2: Send + FnOnce(&mut Lut256SSParty) -> T2 + 'static,
        T3: Send + 'static,
        F3: Send + FnOnce(&mut Lut256SSParty) -> T3 + 'static,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        n_worker_threads: Option<usize>,
    ) -> (
        JoinHandle<(T1, Lut256SSParty)>,
        JoinHandle<(T2, Lut256SSParty)>,
        JoinHandle<(T3, Lut256SSParty)>,
    ) {
        fn adapter<T, Fx: FnOnce(&mut Lut256SSParty) -> T>(
            conn: ConnectedParty,
            f: Fx,
            n_worker_threads: Option<usize>,
        ) -> (T, Lut256SSParty) {
            let mut party = Lut256SSParty::setup(conn, n_worker_threads).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(
            move |conn_party| adapter(conn_party, f1, n_worker_threads),
            move |conn_party| adapter(conn_party, f2, n_worker_threads),
            move |conn_party| adapter(conn_party, f3, n_worker_threads),
        )
    }

    struct Lut256SSSetup;
    impl TestSetup<Lut256SSParty> for Lut256SSSetup {
        fn localhost_setup<
                    T1: Send + 'static,
                    F1: Send + FnOnce(&mut Lut256SSParty) -> T1 + 'static,
                    T2: Send + 'static,
                    F2: Send + FnOnce(&mut Lut256SSParty) -> T2 + 'static,
                    T3: Send + 'static,
                    F3: Send + FnOnce(&mut Lut256SSParty) -> T3 + 'static,
                >(
                    f1: F1,
                    f2: F2,
                    f3: F3,
                ) -> (
                    std::thread::JoinHandle<(T1, Lut256SSParty)>,
                    std::thread::JoinHandle<(T2, Lut256SSParty)>,
                    std::thread::JoinHandle<(T3, Lut256SSParty)>,
                ) {
            localhost_setup_lut256_ss(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<
                    T1: Send + 'static,
                    F1: Send + FnOnce(&mut Lut256SSParty) -> T1 + 'static,
                    T2: Send + 'static,
                    F2: Send + FnOnce(&mut Lut256SSParty) -> T2 + 'static,
                    T3: Send + 'static,
                    F3: Send + FnOnce(&mut Lut256SSParty) -> T3 + 'static,
                >(
                    n_threads: usize,
                    f1: F1,
                    f2: F2,
                    f3: F3,
                ) -> (
                    JoinHandle<(T1, Lut256SSParty)>,
                    JoinHandle<(T2, Lut256SSParty)>,
                    JoinHandle<(T3, Lut256SSParty)>,
                ) {
            localhost_setup_lut256_ss(f1, f2, f3, Some(n_threads))
        }
    }

    #[test]
    fn sub_bytes() {
        test_sub_bytes_ss::<Lut256SSSetup, _>(None)
    }

    #[test]
    fn sub_bytes_mt() {
        test_sub_bytes_ss::<Lut256SSSetup, _>(Some(3))
    }

    #[test]
    fn aes_128_no_keyschedule_lut256_ss() {
        test_aes128_no_keyschedule_gf8_ss::<Lut256SSSetup, _>(1, None)
    }

    #[test]
    fn aes_128_no_keyschedule_lut256_ss_mt() {
        test_aes128_no_keyschedule_gf8_ss::<Lut256SSSetup, _>(100, Some(3))
    }

    #[test]
    fn inv_aes_128_no_keyschedule_lut256_ss() {
        test_inv_aes128_no_keyschedule_gf8_ss::<Lut256SSSetup, _>(1, None)
    }

    #[test]
    fn inv_aes_128_no_keyschedule_lut256_ss_mt() {
        test_inv_aes128_no_keyschedule_gf8_ss::<Lut256SSSetup, _>(100, Some(3))
    }
}