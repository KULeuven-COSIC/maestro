//! This module provides the basic party for the MPC protocols.
//! 
//! TODO: Add documentation
pub mod broadcast;
mod commitment;
pub mod correlated_randomness;
pub mod error;
mod thread_party;
mod mul_triple_vec;

use crate::network::task::{Direction, IoLayerOwned};
use crate::network::{self, ConnectedParty};
use crate::party::correlated_randomness::SharedRng;
use crate::share::{Field, FieldDigestExt, FieldRngExt, RssShare, RssShareVec};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::borrow::Borrow;
use std::io::{self, Write};
use std::thread;

use self::error::MpcResult;
pub use self::thread_party::ThreadParty;
pub use self::mul_triple_vec::{MulTripleRecorder, NoMulTripleRecording, MulTripleVector};
use std::time::Duration;
#[cfg(feature = "verbose-timing")]
use {
    crate::network::task::IO_TIMER,
    lazy_static::lazy_static,
    std::{collections::HashMap, sync::Mutex},
};

#[derive(Clone, Copy)]
pub struct CommStats {
    bytes_received: u64,
    bytes_sent: u64,
    rounds: usize,
}

impl CommStats {
    pub fn empty() -> Self {
        Self {
            bytes_received: 0,
            bytes_sent: 0,
            rounds: 0,
        }
    }

    pub fn new(bytes_received: u64, bytes_sent: u64, rounds: usize) -> Self {
        Self {
            bytes_received,
            bytes_sent,
            rounds,
        }
    }

    pub fn reset(&mut self) {
        self.bytes_received = 0;
        self.bytes_sent = 0;
        self.rounds = 0;
    }
}

#[derive(Clone, Copy)]
pub struct CombinedCommStats {
    pub prev: CommStats,
    pub next: CommStats,
}

impl CombinedCommStats {
    pub fn empty() -> Self {
        Self {
            prev: CommStats::empty(),
            next: CommStats::empty(),
        }
    }

    pub fn print_comm_statistics(&self, i: usize) {
        let p_next = ((i + 1) % 3) + 1;
        let p_prev = ((3 + i - 1) % 3) + 1;
        println!(
            "Communication to P{}: {} bytes sent, {} bytes received, {} rounds",
            p_next, self.next.bytes_sent, self.next.bytes_received, self.next.rounds
        );
        println!(
            "Communication to P{}: {} bytes sent, {} bytes received, {} rounds",
            p_prev, self.prev.bytes_sent, self.prev.bytes_received, self.prev.rounds
        );
        println!(
            "Total communication: {} bytes send, {} bytes received",
            self.next.bytes_sent + self.prev.bytes_sent,
            self.next.bytes_received + self.prev.bytes_received
        );
    }

    pub fn write_to_csv<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        write!(
            writer,
            "{},{},{},{},{},{}",
            self.next.bytes_sent,
            self.next.bytes_received,
            self.next.rounds,
            self.prev.bytes_sent,
            self.prev.bytes_received,
            self.prev.rounds
        )?;
        Ok(())
    }
}

pub trait ArithmeticBlackBox<F: Field> {
    type Digest: FieldDigestExt<F>;
    type Rng: FieldRngExt<F>;

    fn pre_processing(&mut self, n_multiplications: usize) -> MpcResult<()>;
    fn generate_random(&mut self, n: usize) -> RssShareVec<F>;
    /// returns alpha_i s.t. alpha_1 + alpha_2 + alpha_3 = 0
    fn generate_alpha(&mut self, n: usize) -> Vec<F>;
    fn io(&self) -> &IoLayerOwned;

    fn input_round(
        &mut self,
        my_input: &[F],
    ) -> MpcResult<(RssShareVec<F>, RssShareVec<F>, RssShareVec<F>)>;
    fn constant(&self, value: F) -> RssShare<F>;
    fn mul(
        &mut self,
        ci: &mut [F],
        cii: &mut [F],
        ai: &[F],
        aii: &[F],
        bi: &[F],
        bii: &[F],
    ) -> MpcResult<()>;

    /// Outputs the share (si,sii) to all parties
    fn output_round(&mut self, si: &[F], sii: &[F]) -> MpcResult<Vec<F>>;
    
    /// Outputs the shares to the respective parties
    fn output_to(&mut self, to_p1: &[RssShare<F>], to_p2: &[RssShare<F>], to_p3: &[RssShare<F>]) -> MpcResult<Vec<F>>;
    fn finalize(&mut self) -> MpcResult<()>;
}

pub trait Party {
    fn generate_random<F: Field>(&mut self, n: usize) -> RssShareVec<F>
    where
        ChaCha20Rng: FieldRngExt<F>;
    /// returns alpha_i s.t. alpha_1 + alpha_2 + alpha_3 = 0
    fn generate_alpha<F: Field>(&mut self, n: usize) -> Vec<F>
    where
        ChaCha20Rng: FieldRngExt<F>;
    fn constant<F: Field>(&self, value: F) -> RssShare<F>;

    // I/O operations
    fn send_field<'a, F: Field + 'a>(
        &self,
        direction: Direction,
        elements: impl IntoIterator<Item = impl Borrow<F>>,
        len: usize,
    );
    fn receive_field<F: Field>(
        &self,
        direction: Direction,
        num_elements: usize,
    ) -> network::FieldVectorReceiver<F>;
    fn receive_field_slice<'a, F: Field>(
        &self,
        direction: Direction,
        dst: &'a mut [F],
    ) -> network::FieldSliceReceiver<'a, F>;
}

pub struct MainParty {
    pub i: usize,
    io: Option<IoLayerOwned>,
    stats: CombinedCommStats,
    random_next: SharedRng,
    random_prev: SharedRng,
    random_local: ChaCha20Rng,
    thread_pool: Option<ThreadPool>,
}

impl MainParty {
    pub fn setup(mut party: ConnectedParty, n_worker_threads: Option<usize>) -> MpcResult<Self> {
        let mut rng = ChaCha20Rng::from_entropy();

        let (rand_next, rand_prev) = match party.i {
            0 => {
                let rand01 =
                    SharedRng::setup_pairwise(&mut rng, &mut party.comm_next, 0, 1).unwrap();
                let rand02 =
                    SharedRng::setup_pairwise(&mut rng, &mut party.comm_prev, 0, 2).unwrap();
                (rand01, rand02)
            }
            1 => {
                let rand01 =
                    SharedRng::setup_pairwise(&mut rng, &mut party.comm_prev, 1, 0).unwrap();
                let rand12 =
                    SharedRng::setup_pairwise(&mut rng, &mut party.comm_next, 1, 2).unwrap();
                (rand12, rand01)
            }
            2 => {
                let rand02 =
                    SharedRng::setup_pairwise(&mut rng, &mut party.comm_next, 2, 0).unwrap();
                let rand12 =
                    SharedRng::setup_pairwise(&mut rng, &mut party.comm_prev, 2, 1).unwrap();
                (rand02, rand12)
            }
            _ => unreachable!(),
        };

        Ok(Self {
            i: party.i,
            io: Some(IoLayerOwned::spawn_io(party.comm_prev, party.comm_next)?),
            random_next: rand_next,
            random_prev: rand_prev,
            random_local: rng,
            stats: CombinedCommStats::empty(),
            thread_pool: n_worker_threads.map(Self::build_thread_pool),
        })
    }

    fn build_thread_pool(n_worker_threads: usize) -> ThreadPool {
        let mut builder = ThreadPoolBuilder::new();
        if n_worker_threads == 0 {
            // spawn as many threads as there are cores
            let n_cores = thread::available_parallelism().unwrap().get();
            builder = builder.num_threads(n_cores);
        } else {
            // spawn n_worker_threads
            builder = builder.num_threads(n_worker_threads);
        }
        builder = builder.thread_name(|i| format!("worker-{}", i));
        builder.build().unwrap()
    }

    pub fn setup_semi_honest(
        party: ConnectedParty,
        n_worker_threads: Option<usize>,
    ) -> MpcResult<Self> {
        let mut rng = ChaCha20Rng::from_entropy();
        let io_layer = IoLayerOwned::spawn_io(party.comm_prev, party.comm_next)?;
        let (rand_next, rand_prev) =
            SharedRng::setup_all_pairwise_semi_honest(&mut rng, &io_layer).unwrap();

        Ok(Self {
            i: party.i,
            io: Some(io_layer),
            random_next: rand_next,
            random_prev: rand_prev,
            random_local: rng,
            stats: CombinedCommStats::empty(),
            thread_pool: n_worker_threads.map(Self::build_thread_pool),
        })
    }

    pub fn io(&self) -> &IoLayerOwned {
        self.io.as_ref().expect("Teardown was called.")
    }

    pub fn wait_for_completion(&self) {
        self.io().wait_for_completion()
    }

    pub fn has_multi_threading(&self) -> bool {
        self.thread_pool.is_some()
    }

    pub fn num_worker_threads(&self) -> usize {
        self.thread_pool
            .as_ref()
            .map(|tp| tp.current_num_threads())
            .unwrap_or(1)
    }

    pub fn teardown(&mut self) -> MpcResult<()> {
        self.thread_pool.take().into_iter().for_each(drop);
        let io = self.io.take();
        debug_assert!(io.is_some());
        if let Some(io) = io {
            let (nb_prev, nb_next) = io.shutdown()?;
            let mut comm_next = nb_next.into_channel()?;
            let mut comm_prev = nb_prev.into_channel()?;
            match self.i {
                0 => {
                    // 01
                    comm_next.teardown()?;
                    // 02
                    comm_prev.teardown()?;
                }
                1 => {
                    // 01
                    comm_prev.teardown()?;
                    // 12
                    comm_next.teardown()?;
                }
                2 => {
                    // 02
                    comm_next.teardown()?;
                    // 12
                    comm_prev.teardown()?;
                }
                _ => unreachable!(),
            };
            let stats_next = CommStats {
                bytes_received: comm_next.get_bytes_received(),
                bytes_sent: comm_next.get_bytes_sent(),
                rounds: comm_next.get_rounds(),
            };
            let stats_prev = CommStats {
                bytes_received: comm_prev.get_bytes_received(),
                bytes_sent: comm_prev.get_bytes_sent(),
                rounds: comm_prev.get_rounds(),
            };
            self.stats.prev = stats_prev;
            self.stats.next = stats_next;
            return Ok(());
        }
        Ok(())
    }

    pub fn print_statistics(&self) {
        assert!(self.io.is_none(), "Call teardown() first");
        #[cfg(feature = "verbose-timing")]
        {
            let kv = self.get_additional_timers();
            for (key, dur) in kv.iter() {
                println!("\t{}:\t{}s", key, dur.as_secs_f64());
            }
        }
    }

    pub fn get_additional_timers(&self) -> Vec<(String, Duration)> {
        assert!(self.io.is_none(), "Call teardown() first");
        #[cfg(feature = "verbose-timing")]
        {
            println!("Verbose timing data:");
            let mut guard = IO_TIMER.lock().unwrap();
            let mut kv: Vec<(String, Duration)> = guard.times.drain().collect();
            drop(guard);
            let mut guard = PARTY_TIMER.lock().unwrap();
            kv.extend(guard.times.drain());
            drop(guard);

            kv.sort_by_key(|(k, _)| k.clone());
            return kv;
        }
        #[cfg(not(feature = "verbose-timing"))]
        return Vec::new();
    }

    fn split_range_helper(
        n_parts: usize,
        length: usize,
        end_exclusive: usize,
    ) -> Vec<(usize, usize)> {
        let mut start = 0;
        let mut remaining = end_exclusive;
        let mut vec = Vec::with_capacity(n_parts);
        for i in 0..n_parts {
            if i != n_parts - 1 {
                vec.push((start, start + length));
            } else {
                vec.push((start, start + remaining))
            }
            start += length;
            remaining = remaining.overflowing_sub(length).0;
        }
        vec
    }

    pub fn chunk_size_for_task(&self, task_size: usize) -> usize {
        if task_size % self.num_worker_threads() == 0 {
            task_size / self.num_worker_threads()
        }else{
            (task_size / self.num_worker_threads()) +1
        }
    }

    pub fn split_range_equally(&self, end_exclusive: usize) -> Vec<(usize, usize)> {
        let n_parts = self
            .thread_pool
            .as_ref()
            .map(|tp| tp.current_num_threads())
            .unwrap_or(1);
        let length = if end_exclusive % n_parts == 0 {
            end_exclusive / n_parts
        } else {
            end_exclusive / n_parts + 1
        };
        Self::split_range_helper(n_parts, length, end_exclusive)
    }

    /// Returns intervals of equal, even length where the last interval may be shorter and of odd length
    pub fn split_range_equally_even(&self, end_exclusive: usize) -> Vec<(usize, usize)> {
        let n_parts = self
            .thread_pool
            .as_ref()
            .map(|tp| tp.current_num_threads())
            .unwrap_or(1);
        if n_parts == 1 {
            return vec![(0, end_exclusive)];
        }
        let length = {
            if end_exclusive % n_parts == 0 {
                if end_exclusive / n_parts % 2 == 0 {
                    end_exclusive / n_parts
                } else {
                    // next larger, even number
                    end_exclusive / n_parts + 1
                }
            } else {
                let new = end_exclusive / n_parts + 1;
                if new % 2 == 0 {
                    new
                } else {
                    // next larger, even number
                    new + 1
                }
            }
        };
        if (n_parts - 1) * length > end_exclusive {
            panic!("Range is too small to be divided into even slices");
        }
        Self::split_range_helper(n_parts, length, end_exclusive)
    }

    pub fn create_thread_parties(&mut self, ranges: Vec<(usize, usize)>) -> Vec<ThreadParty<()>> {
        self.create_thread_parties_with_additional_data(ranges, |_, _| ())
    }

    pub fn create_thread_parties_with_additional_data<T, F: FnMut(usize, usize) -> T>(
        &mut self,
        ranges: Vec<(usize, usize)>,
        mut data: F,
    ) -> Vec<ThreadParty<T>> {
        assert!(self.io.is_some(), "I/O closed");
        let mut vec = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            let random_local = ChaCha20Rng::from_rng(&mut self.random_local).unwrap();
            let random_next = SharedRng::seeded_from(&mut self.random_next);
            let random_prev = SharedRng::seeded_from(&mut self.random_prev);
            let io = self.io().clone_io_layer();
            let i = self.i;
            vec.push(ThreadParty::new(
                i,
                start,
                end,
                random_next,
                random_prev,
                random_local,
                io,
                data(start, end),
            ))
        }
        vec
    }

    pub fn run_in_threadpool<T: Send, F: FnOnce() -> MpcResult<T> + Send>(
        &self,
        f: F,
    ) -> MpcResult<T> {
        self.thread_pool
            .as_ref()
            .expect("Thread pool not enabled")
            .install(f)
    }

    pub fn run_in_threadpool_scoped<
        'scope,
        R: Send,
        F: FnOnce(&rayon::Scope<'scope>) -> R + Send,
    >(
        &self,
        f: F,
    ) -> R {
        self.thread_pool
            .as_ref()
            .expect("Thread pool not enabled")
            .scope(f)
    }
}

#[inline]
fn generate_alpha<F: Field, R: Rng + CryptoRng>(next: &mut R, prev: &mut R, n: usize) -> Vec<F>
where
    R: FieldRngExt<F>,
{
    next.generate(n)
        .into_iter()
        .zip(prev.generate(n))
        .map(|(next, prev)| next - prev)
        .collect()
}

#[inline]
fn generate_random<F: Field, R: Rng + CryptoRng>(
    next: &mut R,
    prev: &mut R,
    n: usize,
) -> RssShareVec<F>
where
    R: FieldRngExt<F>,
{
    let si = prev.generate(n);
    let sii = next.generate(n);
    si.into_iter()
        .zip(sii)
        .map(|(si, sii)| RssShare::from(si, sii))
        .collect()
}

#[inline]
fn constant<F: Field>(i: usize, value: F) -> RssShare<F> {
    if i == 0 {
        RssShare::from(value, F::ZERO)
    } else if i == 2 {
        RssShare::from(F::ZERO, value)
    } else {
        RssShare::from(F::ZERO, F::ZERO)
    }
}

impl Party for MainParty {
    /// returns alpha_i s.t. alpha_1 + alpha_2 + alpha_3 = 0
    fn generate_alpha<F: Field>(&mut self, n: usize) -> Vec<F>
    where
        ChaCha20Rng: FieldRngExt<F>,
    {
        generate_alpha(self.random_next.as_mut(), self.random_prev.as_mut(), n)
    }

    fn generate_random<F: Field>(&mut self, n: usize) -> RssShareVec<F>
    where
        ChaCha20Rng: FieldRngExt<F>,
    {
        generate_random(self.random_next.as_mut(), self.random_prev.as_mut(), n)
    }

    #[inline]
    fn constant<F: Field>(&self, value: F) -> RssShare<F> {
        constant(self.i, value)
    }

    // I/O
    fn send_field<'a, F: Field + 'a>(
        &self,
        direction: Direction,
        elements: impl IntoIterator<Item = impl Borrow<F>>,
        len: usize,
    ) {
        self.io().send_field(direction, elements, len)
    }

    fn receive_field<F: Field>(
        &self,
        direction: Direction,
        num_elements: usize,
    ) -> network::FieldVectorReceiver<F> {
        self.io().receive_field(direction, num_elements)
    }

    fn receive_field_slice<'a, F: Field>(
        &self,
        direction: Direction,
        dst: &'a mut [F],
    ) -> network::FieldSliceReceiver<'a, F> {
        self.io().receive_field_slice(direction, dst)
    }
}

#[cfg(feature = "verbose-timing")]
lazy_static! {
    pub static ref PARTY_TIMER: Mutex<Timer> = Mutex::new(Timer::new());
}

#[cfg(feature = "verbose-timing")]
pub struct Timer {
    times: HashMap<String, Duration>,
}

#[cfg(feature = "verbose-timing")]
impl Timer {
    pub fn new() -> Self {
        Self {
            times: HashMap::new(),
        }
    }

    pub fn report_time(&mut self, key: &str, duration: Duration) {
        if !self.times.contains_key(key) {
            self.times.insert(key.to_string(), Duration::from_secs(0));
        }
        if let Some(dur) = self.times.get_mut(key) {
            *dur += duration;
        }
    }
}

#[cfg(any(test, feature = "benchmark-helper"))]
pub mod test {
    use crate::network::task::Direction;
    use crate::network::{Config, ConnectedParty, CreatedParty};
    use crate::party::correlated_randomness::SharedRng;
    use crate::party::MainParty;
    use rand::RngCore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::fs::File;
    use std::io::BufReader;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::thread;
    use std::thread::JoinHandle;

    const TEST_KEY_DIR: &str = "keys";

    type KeyPair = (PrivateKeyDer<'static>, CertificateDer<'static>);

    pub fn create_certificates() -> (KeyPair, KeyPair, KeyPair) {
        fn key_path(filename: &str) -> PathBuf {
            let mut p = PathBuf::from("./");
            p.push(TEST_KEY_DIR);
            p.push(filename);
            return p;
        }

        fn load_key(name: &str) -> PrivateKeyDer<'static> {
            let mut reader =
                BufReader::new(File::open(key_path(name)).expect(&format!("Cannot open {}", name)));
            let key = rustls_pemfile::private_key(&mut reader)
                .expect(&format!("Cannot read private key in {}", name))
                .expect(&format!("No private key in {}", name));
            return key;
        }

        fn load_cert(name: &str) -> CertificateDer<'static> {
            let mut reader =
                BufReader::new(File::open(key_path(name)).expect(&format!("Cannot open {}", name)));
            let cert: Vec<_> = rustls_pemfile::certs(&mut reader)
                .map(|r| r.expect(&format!("Cannot read certificate in {}", name)))
                .collect();
            assert_eq!(cert.len(), 1);
            let cert = cert[0].clone();
            return cert;
        }

        return (
            (load_key("p1.key"), load_cert("p1.pem")),
            (load_key("p2.key"), load_cert("p2.pem")),
            (load_key("p3.key"), load_cert("p3.pem")),
        );
    }

    pub trait TestSetup<P> {
        fn localhost_setup<
            T1: Send + 'static,
            F1: Send + FnOnce(&mut P) -> T1 + 'static,
            T2: Send + 'static,
            F2: Send + FnOnce(&mut P) -> T2 + 'static,
            T3: Send + 'static,
            F3: Send + FnOnce(&mut P) -> T3 + 'static,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            JoinHandle<(T1, P)>,
            JoinHandle<(T2, P)>,
            JoinHandle<(T3, P)>,
        );
        fn localhost_setup_multithreads<
            T1: Send + 'static,
            F1: Send + FnOnce(&mut P) -> T1 + 'static,
            T2: Send + 'static,
            F2: Send + FnOnce(&mut P) -> T2 + 'static,
            T3: Send + 'static,
            F3: Send + FnOnce(&mut P) -> T3 + 'static,
        >(
            n_threads: usize,
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            JoinHandle<(T1, P)>,
            JoinHandle<(T2, P)>,
            JoinHandle<(T3, P)>,
        );
    }

    pub fn localhost_connect<
        T1: Send + 'static,
        F1: Send + FnOnce(ConnectedParty) -> T1 + 'static,
        T2: Send + 'static,
        F2: Send + FnOnce(ConnectedParty) -> T2 + 'static,
        T3: Send + 'static,
        F3: Send + FnOnce(ConnectedParty) -> T3 + 'static,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
    ) -> (JoinHandle<T1>, JoinHandle<T2>, JoinHandle<T3>) {
        let addr: Vec<Ipv4Addr> = (0..3)
            .map(|_| Ipv4Addr::from_str("127.0.0.1").unwrap())
            .collect();
        let party1 = CreatedParty::bind(0, IpAddr::V4(addr[0]), 0).unwrap();
        let party2 = CreatedParty::bind(1, IpAddr::V4(addr[1]), 0).unwrap();
        let party3 = CreatedParty::bind(2, IpAddr::V4(addr[2]), 0).unwrap();

        // get ports
        let port1 = party1.port().unwrap();
        let port2 = party2.port().unwrap();
        let port3 = party3.port().unwrap();

        // create certificates
        let certs = create_certificates();
        let (sk1, pk1) = certs.0;
        let (sk2, pk2) = certs.1;
        let (sk3, pk3) = certs.2;

        let certificates = vec![pk1.clone(), pk2.clone(), pk3.clone()];

        let ports = vec![port1, port2, port3];
        // println!("Ports: {:?}", ports);

        let party1 = {
            let config = Config::new(addr, ports.clone(), certificates.clone(), pk1, sk1);
            thread::Builder::new()
                .name("party1".to_string())
                .spawn(move || {
                    // println!("P1 running");
                    let party1 = party1.connect(config, None).unwrap();
                    // println!("P1 connected");
                    let res = f1(party1);
                    res
                })
                .unwrap()
        };

        let party2 = {
            let addr: Vec<Ipv4Addr> = (0..3)
                .map(|_| Ipv4Addr::from_str("127.0.0.1").unwrap())
                .collect();
            let config = Config::new(addr, ports.clone(), certificates.clone(), pk2, sk2);
            thread::Builder::new()
                .name("party2".to_string())
                .spawn(move || {
                    // println!("P2 running");
                    let party2 = party2.connect(config, None).unwrap();
                    // println!("P2 connected");
                    let res = f2(party2);
                    res
                })
                .unwrap()
        };

        let party3 = {
            let addr: Vec<Ipv4Addr> = (0..3)
                .map(|_| Ipv4Addr::from_str("127.0.0.1").unwrap())
                .collect();
            let config = Config::new(addr, ports, certificates, pk3, sk3);
            thread::Builder::new()
                .name("party3".to_string())
                .spawn(move || {
                    // println!("P3 running");
                    let party3 = party3.connect(config, None).unwrap();
                    // println!("P3 connected");
                    let res = f3(party3);
                    res
                })
                .unwrap()
        };

        (party1, party2, party3)
    }

    pub fn localhost_setup<
        T1: Send + 'static,
        F1: Send + FnOnce(&mut MainParty) -> T1 + 'static,
        T2: Send + 'static,
        F2: Send + FnOnce(&mut MainParty) -> T2 + 'static,
        T3: Send + 'static,
        F3: Send + FnOnce(&mut MainParty) -> T3 + 'static,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
        n_threads: Option<usize>,
    ) -> (
        JoinHandle<(T1, MainParty)>,
        JoinHandle<(T2, MainParty)>,
        JoinHandle<(T3, MainParty)>,
    ) {
        let _f1 = move |p: ConnectedParty| {
            // println!("P1: Before Setup");
            let mut p = MainParty::setup(p, n_threads).unwrap();
            // println!("P1: After Setup");
            let res = f1(&mut p);
            p.teardown().unwrap();
            (res, p)
        };
        let _f2 = move |p: ConnectedParty| {
            // println!("P2: Before Setup");
            let mut p = MainParty::setup(p, n_threads).unwrap();
            // println!("P2: After Setup");
            let res = f2(&mut p);
            p.teardown().unwrap();
            (res, p)
        };
        let _f3 = move |p: ConnectedParty| {
            // println!("P3: Before Setup");
            let mut p = MainParty::setup(p, n_threads).unwrap();
            // println!("P3: After Setup");
            let res = f3(&mut p);
            p.teardown().unwrap();
            (res, p)
        };
        localhost_connect(_f1, _f2, _f3)
    }

    pub struct PartySetup;
    impl TestSetup<MainParty> for PartySetup {
        fn localhost_setup<
            T1: Send + 'static,
            F1: Send + FnOnce(&mut MainParty) -> T1 + 'static,
            T2: Send + 'static,
            F2: Send + FnOnce(&mut MainParty) -> T2 + 'static,
            T3: Send + 'static,
            F3: Send + FnOnce(&mut MainParty) -> T3 + 'static,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            JoinHandle<(T1, MainParty)>,
            JoinHandle<(T2, MainParty)>,
            JoinHandle<(T3, MainParty)>,
        ) {
            localhost_setup(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<
            T1: Send + 'static,
            F1: Send + FnOnce(&mut MainParty) -> T1 + 'static,
            T2: Send + 'static,
            F2: Send + FnOnce(&mut MainParty) -> T2 + 'static,
            T3: Send + 'static,
            F3: Send + FnOnce(&mut MainParty) -> T3 + 'static,
        >(
            n_threads: usize,
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            JoinHandle<(T1, MainParty)>,
            JoinHandle<(T2, MainParty)>,
            JoinHandle<(T3, MainParty)>,
        ) {
            localhost_setup(f1, f2, f3, Some(n_threads))
        }
    }

    pub fn simple_localhost_setup<
        F: Send + Clone + Fn(&mut MainParty) -> T + 'static,
        T: Send + 'static,
    >(
        f: F,
    ) -> ((T, T, T), (MainParty, MainParty, MainParty)) {
        let (h1, h2, h3) = localhost_setup(f.clone(), f.clone(), f, None);
        let (t1, p1) = h1.join().unwrap();
        let (t2, p2) = h2.join().unwrap();
        let (t3, p3) = h3.join().unwrap();
        ((t1, t2, t3), (p1, p2, p3))
    }

    #[test]
    fn correct_channel_connection() {
        let f1 = |mut p: ConnectedParty| {
            p.comm_next.write("P12".as_bytes()).unwrap();
            let mut buf = [0u8; 3];
            p.comm_prev.read(&mut buf).unwrap();
            assert_eq!(&buf, "P31".as_bytes());
        };
        let f2 = |mut p: ConnectedParty| {
            p.comm_next.write("P23".as_bytes()).unwrap();
            let mut buf = [0u8; 3];
            p.comm_prev.read(&mut buf).unwrap();
            assert_eq!(&buf, "P12".as_bytes());
        };
        let f3 = |mut p: ConnectedParty| {
            p.comm_next.write("P31".as_bytes()).unwrap();
            let mut buf = [0u8; 3];
            p.comm_prev.read(&mut buf).unwrap();
            assert_eq!(&buf, "P23".as_bytes());
        };
        let (p1, p2, p3) = localhost_connect(f1, f2, f3);
        p1.join().unwrap();
        p2.join().unwrap();
        p3.join().unwrap();
    }

    #[test]
    fn correct_party_setup() {
        let (_, (mut p1, mut p2, mut p3)) = simple_localhost_setup(|_| ());
        // check correlated randomness
        fn assert_common_randomness(
            shared_random1: &mut SharedRng,
            shared_random2: &mut SharedRng,
        ) {
            let mut expected = [0u8; 100];
            let mut actual = [0u8; 100];
            shared_random1.as_mut().fill_bytes(&mut expected);
            shared_random2.as_mut().fill_bytes(&mut actual);
            assert_eq!(&expected, &actual);
        }

        assert_common_randomness(&mut p1.random_next, &mut p2.random_prev);
        assert_common_randomness(&mut p2.random_next, &mut p3.random_prev);
        assert_common_randomness(&mut p3.random_next, &mut p1.random_prev);

        // check local rngs are not correlated
        let mut buf1 = [0u8; 100];
        let mut buf2 = [0u8; 100];
        let mut buf3 = [0u8; 100];
        p1.random_local.fill_bytes(&mut buf1);
        p2.random_local.fill_bytes(&mut buf2);
        p3.random_local.fill_bytes(&mut buf3);

        assert_ne!(&buf1, &buf2);
        assert_ne!(&buf2, &buf3);
        assert_ne!(&buf1, &buf3);
    }

    #[test]
    fn correct_party_teardown() {
        fn send_receive_teardown(p: &mut MainParty) {
            let mut buf = vec![0u8; 16];
            p.io().send(Direction::Next, buf.clone());
            let rcv_buf = p.io().receive_slice(Direction::Previous, &mut buf);
            rcv_buf.rcv().unwrap();
            // localhost_setup calls teardown
        }
        let (p1, p2, p3) = localhost_setup(
            send_receive_teardown,
            send_receive_teardown,
            send_receive_teardown,
            None,
        );
        p1.join().unwrap();
        p2.join().unwrap();
        p3.join().unwrap();
    }

    #[test]
    fn correct_split_range_single_thread() {
        const THREADS: usize = 3;
        fn split_range_single_test(p: &mut MainParty) {
            let range = p.split_range_equally(3);
            assert_eq!(vec![(0, 3)], range);
            let range = p.split_range_equally(300);
            assert_eq!(vec![(0, 300)], range);
            let range = p.split_range_equally(100);
            assert_eq!(vec![(0, 100)], range);
        }
        let (p1, p2, p3) = localhost_setup(
            split_range_single_test,
            split_range_single_test,
            split_range_single_test,
            None,
        );
        p1.join().unwrap();
        p2.join().unwrap();
        p3.join().unwrap();
    }

    #[test]
    fn correct_split_range() {
        const THREADS: usize = 3;
        fn split_range_test(p: &mut MainParty) {
            let range = p.split_range_equally(3);
            assert_eq!(vec![(0, 1), (1, 2), (2, 3)], range);
            let range = p.split_range_equally(300);
            assert_eq!(vec![(0, 100), (100, 200), (200, 300)], range);
            let range = p.split_range_equally(100);
            assert_eq!(vec![(0, 34), (34, 68), (68, 100)], range);
        }
        let (p1, p2, p3) = localhost_setup(
            split_range_test,
            split_range_test,
            split_range_test,
            Some(THREADS),
        );
        p1.join().unwrap();
        p2.join().unwrap();
        p3.join().unwrap();
    }

    #[test]
    fn correct_split_range_even() {
        const THREADS: usize = 3;
        fn split_range_even_test(p: &mut MainParty) {
            let range = p.split_range_equally_even(30);
            assert_eq!(vec![(0, 10), (10, 20), (20, 30)], range);
            let range = p.split_range_equally_even(31);
            assert_eq!(vec![(0, 12), (12, 24), (24, 31)], range);
            let range = p.split_range_equally_even(5);
            assert_eq!(vec![(0, 2), (2, 4), (4, 5)], range);
            let range = p.split_range_equally_even(4);
            assert_eq!(vec![(0, 2), (2, 4), (4, 4)], range);
        }
        let (p1, p2, p3) = localhost_setup(
            split_range_even_test,
            split_range_even_test,
            split_range_even_test,
            Some(THREADS),
        );
        p1.join().unwrap();
        p2.join().unwrap();
        p3.join().unwrap();
    }

    #[test]
    fn can_create_multiple_party_instances_in_same_thread_after_teardown() {
        const N_THREADS: usize = 3;
        let addr1 = Ipv4Addr::from_str("127.0.0.1").unwrap();
        let addr2 = Ipv4Addr::from_str("127.0.0.1").unwrap();
        let addr3 = Ipv4Addr::from_str("127.0.0.1").unwrap();
        let party1 = CreatedParty::bind(0, IpAddr::V4(addr1), 0).unwrap();
        let party2 = CreatedParty::bind(1, IpAddr::V4(addr2), 0).unwrap();
        let party3 = CreatedParty::bind(2, IpAddr::V4(addr3), 0).unwrap();

        // get ports
        let port1 = party1.port().unwrap();
        let port2 = party2.port().unwrap();
        let port3 = party3.port().unwrap();

        // create certificates
        let certs = create_certificates();
        let (sk1, pk1) = certs.0;
        let (sk2, pk2) = certs.1;
        let (sk3, pk3) = certs.2;

        let certificates = vec![pk1.clone(), pk2.clone(), pk3.clone()];
        let ports = vec![port1, port2, port3];

        let party1 = {
            let config = Config::new(
                vec![addr1, addr2, addr3],
                ports.clone(),
                certificates.clone(),
                pk1,
                sk1,
            );
            thread::Builder::new()
                .name("party1".to_string())
                .spawn(move || {
                    let mut party1 = MainParty::setup(
                        party1.connect(config.clone(), None).unwrap(),
                        Some(N_THREADS),
                    )
                    .unwrap();
                    // teardown
                    party1.teardown().unwrap();
                    drop(party1);

                    // create another party in the same thread
                    let party1 = CreatedParty::bind(0, IpAddr::V4(addr1), port1).unwrap();
                    let party1 = party1.connect(config, None).unwrap();
                    let mut party1 = MainParty::setup(party1, Some(N_THREADS)).unwrap();
                    // ok
                    party1.teardown().unwrap()
                })
                .unwrap()
        };

        let party2 = {
            let config = Config::new(
                vec![addr1, addr2, addr3],
                ports.clone(),
                certificates.clone(),
                pk2,
                sk2,
            );
            thread::Builder::new()
                .name("party2".to_string())
                .spawn(move || {
                    let mut party2 = MainParty::setup(
                        party2.connect(config.clone(), None).unwrap(),
                        Some(N_THREADS),
                    )
                    .unwrap();
                    // teardown
                    party2.teardown().unwrap();
                    drop(party2);

                    // create another party in the same thread
                    let party2 = CreatedParty::bind(1, IpAddr::V4(addr2), port2).unwrap();
                    let party2 = party2.connect(config, None).unwrap();
                    let mut party2 = MainParty::setup(party2, Some(N_THREADS)).unwrap();

                    // ok
                    party2.teardown().unwrap()
                })
                .unwrap()
        };

        let party3 = {
            let config = Config::new(vec![addr1, addr2, addr3], ports, certificates, pk3, sk3);
            thread::Builder::new()
                .name("party3".to_string())
                .spawn(move || {
                    let mut party3 = MainParty::setup(
                        party3.connect(config.clone(), None).unwrap(),
                        Some(N_THREADS),
                    )
                    .unwrap();
                    // teardown
                    party3.teardown().unwrap();
                    drop(party3);

                    // create another party in the same thread
                    let party3 = CreatedParty::bind(2, IpAddr::V4(addr3), port3).unwrap();
                    let party3 = party3.connect(config, None).unwrap();
                    let mut party3 = MainParty::setup(party3, Some(N_THREADS)).unwrap();

                    // ok
                    party3.teardown().unwrap()
                })
                .unwrap()
        };

        party1.join().unwrap();
        party2.join().unwrap();
        party3.join().unwrap();
    }
}
