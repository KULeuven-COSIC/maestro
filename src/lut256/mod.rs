use std::time::{Duration, Instant};


use crate::{aes::{self, GF8InvBlackBox}, benchmark::{BenchmarkProtocol, BenchmarkResult}, chida::ChidaParty, network::{task::{IoLayerOwned}, ConnectedParty}, party::{error::MpcResult, ArithmeticBlackBox}, share::gf8::GF8};
mod online;
mod offline;


/// a random one-hot vector of size 256
#[derive(Clone, Copy)]
pub struct RndOhv([u8; 256]);

// Party for LUT-256
pub struct LUT256Party {
    inner: ChidaParty,
    prep_ohv: Vec<RndOhv256Output>,
    lut_time: Duration,
}

/// Output of the random one-hot vector pre-processing.
/// Contains a (2,3)-sharing of a size 256 one-hot vector `RndOhv` and a (2,3)-sharing of the corresponding `GF8` element that indicates
/// the position of 1 in the vector.
pub struct RndOhv256Output {
    /// share i of one-hot vector
    pub si: RndOhv,
    /// share i+1 of one-hot vector
    pub sii: RndOhv,
    /// (2,3) sharing of the position of the 1 in the vector
    pub random_si: GF8,
    pub random_sii: GF8,
}

impl LUT256Party {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>) -> MpcResult<Self> {
        ChidaParty::setup(connected, n_worker_threads).map(|party| {
            Self {
                inner: party,
                prep_ohv: Vec::new(),
                lut_time: Duration::from_secs(0),
            }
        })
    }

    pub fn io(&self) -> &IoLayerOwned {
        <ChidaParty as ArithmeticBlackBox<GF8>>::io(&self.inner)
    }
}

impl RndOhv {

    pub fn new(table: [u8; 256]) -> Self {
        Self(table)
    }

    pub fn lut(&self, offset: usize, table: &[u8]) -> GF8 {
        let mut res = 0u8;
        for i in 0..table.len() {
            res ^= self.0[i] & table[i ^ offset];
        }
        GF8(res)
    }
}

pub fn lut256_benchmark(connected: ConnectedParty, simd: usize, n_worker_threads: Option<usize>) {
    let mut party = LUT256Party::setup(connected, n_worker_threads).unwrap();
    let setup_comm_stats = party.io().reset_comm_stats();
    let start_prep = Instant::now();
    party.do_preprocessing(0, simd).unwrap();
    let prep_duration = start_prep.elapsed();
    let prep_comm_stats = party.io().reset_comm_stats();

    let input = aes::random_state(&mut party.inner, simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(&mut party.inner);

    let start = Instant::now();
    let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
    let duration = start.elapsed();
    let online_comm_stats = party.io().reset_comm_stats();
    let _ = aes::output(&mut party.inner, output).unwrap();
    party.inner.teardown().unwrap();
    
    println!("Finished benchmark");
    
    println!("Party {}: LUT-256 with SIMD={} took {}s (pre-processing) and {}s (online phase)", party.inner.party_index(), simd, prep_duration.as_secs_f64(), duration.as_secs_f64());
    println!("LUT time: {}s", party.lut_time.as_secs_f64());
    println!("Setup:");
    setup_comm_stats.print_comm_statistics(party.inner.party_index());
    println!("Pre-Processing:");
    prep_comm_stats.print_comm_statistics(party.inner.party_index());
    println!("Online Phase:");
    online_comm_stats.print_comm_statistics(party.inner.party_index());
    party.inner.print_statistics();
}

pub struct LUT256Benchmark;

impl BenchmarkProtocol for LUT256Benchmark {
    fn protocol_name(&self) -> String {
        "lut256".to_string()
    }
    fn run(&self, conn: ConnectedParty, simd: usize, n_worker_threads: Option<usize>) -> BenchmarkResult {
        let mut party = LUT256Party::setup(conn, n_worker_threads).unwrap();
        let _setup_comm_stats = party.io().reset_comm_stats();
        println!("After setup");
        let start_prep = Instant::now();
        party.do_preprocessing(0, simd).unwrap();
        let prep_duration = start_prep.elapsed();
        let prep_comm_stats = party.io().reset_comm_stats();
        println!("After pre-processing");
        let input = aes::random_state(&mut party.inner, simd);
        // create random key states for benchmarking purposes
        let ks = aes::random_keyschedule(&mut party.inner);

        let start = Instant::now();
        let output = aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap();
        let duration = start.elapsed();
        println!("After online");
        let online_comm_stats = party.io().reset_comm_stats();
        let _ = aes::output(&mut party.inner, output).unwrap();
        println!("After output");
        party.inner.teardown().unwrap();
        println!("After teardown");
        
        BenchmarkResult::new(prep_duration, duration, prep_comm_stats, online_comm_stats, party.inner.get_additional_timers())
    }
}

#[cfg(test)]
mod test {
    use std::thread::JoinHandle;


    use crate::{network::ConnectedParty, party::test::{localhost_connect, TestSetup}};

    use super::LUT256Party;

    pub fn localhost_setup_lut256<T1: Send + 'static, F1: Send + FnOnce(&mut LUT256Party) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut LUT256Party) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut LUT256Party) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,LUT256Party)>, JoinHandle<(T2,LUT256Party)>, JoinHandle<(T3,LUT256Party)>) {
        fn adapter<T, Fx: FnOnce(&mut LUT256Party)->T>(conn: ConnectedParty, f: Fx) -> (T,LUT256Party) {
            let mut party = LUT256Party::setup(conn, None).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(|conn_party| adapter(conn_party, f1), |conn_party| adapter(conn_party, f2), |conn_party| adapter(conn_party, f3))
    }

    pub struct LUT256Setup;
    impl TestSetup<LUT256Party> for LUT256Setup {
        fn localhost_setup<T1: Send + 'static, F1: Send + FnOnce(&mut LUT256Party) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut LUT256Party) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut LUT256Party) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,LUT256Party)>, JoinHandle<(T2,LUT256Party)>, JoinHandle<(T3,LUT256Party)>) {
            localhost_setup_lut256(f1, f2, f3)
        }
        fn localhost_setup_multithreads<T1: Send + 'static, F1: Send + FnOnce(&mut LUT256Party) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut LUT256Party) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut LUT256Party) -> T3 + 'static>(_n_threads: usize, _f1: F1, _f2: F2, _f3: F3) -> (JoinHandle<(T1,LUT256Party)>, JoinHandle<(T2,LUT256Party)>, JoinHandle<(T3,LUT256Party)>) {
            unimplemented!()
        }
    }
}
