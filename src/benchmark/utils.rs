use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufWriter, Write},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use itertools::Itertools;

use crate::{aes::{self, AesVariant, GF8InvBlackBox}, share::gf8::GF8, util::ArithmeticBlackBox};
use crate::rep3_core::{network::{Config, ConnectedParty}, party::{error::MpcResult, CombinedCommStats}};

pub struct BenchmarkResult {
    prep_time: Duration,
    online_time: Duration,
    finalize_time: Duration,
    prep_comm_stats: CombinedCommStats,
    online_comm_stats: CombinedCommStats,
    finalize_comm_stats: CombinedCommStats,
    additional_timers: HashMap<String, Duration>,
}

pub trait BenchmarkProtocol {
    fn protocol_name(&self) -> String;
    fn run(
        &self,
        conn: ConnectedParty,
        variant: AesVariant,
        simd: usize,
        n_worker_threads: Option<usize>,
        prot_string: Option<String>,
    ) -> BenchmarkResult;
}

pub struct AggregatedBenchmarkResult {
    prep_times: Vec<Duration>,
    online_times: Vec<Duration>,
    finalize_times: Vec<Duration>,
    prep_comm_stats: CombinedCommStats,
    online_comm_stats: CombinedCommStats,
    finalize_comm_stats: CombinedCommStats,
    additional_timers: HashMap<String, Vec<Duration>>,
    prep_time_avg_s: f64,
    online_time_avg_s: f64,
    finalize_time_avg_s: f64,
}

const WAIT_BETWEEN_SEC: u64 = 2;

fn benchmark(
    party_index: usize,
    config: &Config,
    variant: AesVariant,
    iterations: usize,
    simd: usize,
    n_worker_threads: Option<usize>,
    protocol: &Box<dyn BenchmarkProtocol>,
    prot_str: String,
) -> AggregatedBenchmarkResult {
    let mut agg = AggregatedBenchmarkResult::new();
    for i in 0..iterations {
        println!("Iteration {}", i + 1);
        let conn = ConnectedParty::bind_and_connect(
            party_index,
            config.clone(),
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        let res = protocol.run(conn, variant, simd, n_worker_threads, Some(prot_str.clone()));
        agg.update(res);
        thread::sleep(Duration::from_secs(WAIT_BETWEEN_SEC));
    }
    agg.compute_avg();
    agg
}

pub fn benchmark_protocols(
    party_index: usize,
    config: &Config,
    variant: AesVariant,
    iterations: usize,
    simd: Vec<usize>,
    n_worker_threads: Option<usize>,
    protocols: Vec<Box<dyn BenchmarkProtocol>>,
    output: PathBuf,
) -> io::Result<()> {
    // header
    let mut writer = BufWriter::new(File::create(output.clone())?);
    writeln!(&mut writer, "protocol,simd,pre-processing-time,online-time,finalize-time,pre-processing-bytes-sent-to-next,pre-processing-bytes-received-from-next,pre-processing-bytes-rounds-next,pre-processing-bytes-sent-to-prev,pre-processing-bytes-received-from-prev,pre-processing-bytes-rounds-prev,online-bytes-sent-to-next,online-bytes-received-from-next,online-bytes-rounds-next,online-bytes-sent-to-prev,online-bytes-received-from-prev,online-bytes-rounds-prev,finalize-bytes-sent-to-next,finalize-bytes-received-from-next,finalize-bytes-rounds-next,finalize-bytes-sent-to-prev,finalize-bytes-received-from-prev,finalize-bytes-rounds-prev")?;

    let mut results = Vec::new();

    let protocol_names = protocols.iter().map(|p| p.protocol_name()).join(", ");
    let benchmark_prot_string = format!("MAESTRO benchmark [rep: {}, simd: {:?}, threads: {:?}, targets: {}]", iterations, &simd, n_worker_threads, protocol_names);

    for simd_i in &simd {
        let mut results_of_simd_i = Vec::new();
        for prot in &protocols {
            println!("Benchmarking {}", prot.protocol_name());
            let agg = benchmark(
                party_index,
                config,
                variant,
                iterations,
                *simd_i,
                n_worker_threads,
                prot,
                format!("{} current benchmark [protocol: {}, simd: {}]", &benchmark_prot_string, prot.protocol_name(), *simd_i),
            );
            println!("Finished benchmark for {}", prot.protocol_name());
            agg.write_to_csv(&mut writer, &prot.protocol_name(), &simd_i.to_string())?;
            // flush the writer
            writer.flush()?;
            results_of_simd_i.push(agg);
        }
        results.push(results_of_simd_i);
    }
    

    println!(
        "Writing CSV-formatted benchmark results to {}",
        output.to_str().unwrap()
    );
    Ok(())
}

impl BenchmarkResult {
    pub fn new(
        prep_time: Duration,
        online_time: Duration,
        finalize_time: Duration,
        prep_comm_stats: CombinedCommStats,
        online_comm_stats: CombinedCommStats,
        finalize_comm_stats: CombinedCommStats,
        additional_timers: Vec<(String, Duration)>,
    ) -> Self {
        let additional_timers: HashMap<String, Duration> = additional_timers.into_iter().collect();
        Self {
            prep_time,
            online_time,
            finalize_time,
            prep_comm_stats,
            online_comm_stats,
            finalize_comm_stats,
            additional_timers,
        }
    }
}

impl Default for AggregatedBenchmarkResult {
    fn default() -> Self {
        Self::new()
    }
}

impl AggregatedBenchmarkResult {
    pub fn new() -> Self {
        Self {
            prep_times: Vec::new(),
            online_times: Vec::new(),
            finalize_times: Vec::new(),
            prep_comm_stats: CombinedCommStats::empty(),
            online_comm_stats: CombinedCommStats::empty(),
            finalize_comm_stats: CombinedCommStats::empty(),
            additional_timers: HashMap::new(),
            prep_time_avg_s: 0.0,
            online_time_avg_s: 0.0,
            finalize_time_avg_s: 0.0,
        }
    }

    pub fn n_iterations(&self) -> usize {
        self.prep_times.len()
    }

    fn update(&mut self, mut result: BenchmarkResult) {
        self.prep_times.push(result.prep_time);
        self.online_times.push(result.online_time);
        self.finalize_times.push(result.finalize_time);
        self.prep_comm_stats = result.prep_comm_stats;
        self.online_comm_stats = result.online_comm_stats;
        self.finalize_comm_stats = result.finalize_comm_stats;

        if self.additional_timers.is_empty() {
            for (k, v) in result.additional_timers.drain() {
                self.additional_timers.insert(k, vec![v]);
            }
        } else {
            // merge
            assert_eq!(
                self.additional_timers.len(),
                result.additional_timers.len(),
                "BenchmarkResult does have different keys"
            );
            result.additional_timers.drain().for_each(|(k, v)| {
                self.additional_timers.get_mut(&k).unwrap().push(v);
            });
        }
    }

    fn avg(v: &[Duration]) -> f64 {
        let n = v.len() as f64;
        v.iter().map(|d| d.as_secs_f64()).sum::<f64>() / n
    }

    fn compute_avg(&mut self) {
        assert!(self.n_iterations() > 0);
        self.prep_time_avg_s = Self::avg(&self.prep_times);
        self.online_time_avg_s = Self::avg(&self.online_times);
        self.finalize_time_avg_s = Self::avg(&self.finalize_times);
    }

    pub fn write_to_csv<W: Write>(&self, writer: &mut W, name: &str, simd: &str) -> io::Result<()> {
        for i in 0..self.n_iterations() {
            write!(writer, "\"{}\",{},", name, simd)?;
            write!(
                writer,
                "{},{},{},",
                self.prep_times[i].as_secs_f64(),
                self.online_times[i].as_secs_f64(),
                self.finalize_times[i].as_secs_f64(),
            )?;
            self.prep_comm_stats.write_to_csv(writer)?;
            write!(writer, ",")?;
            self.online_comm_stats.write_to_csv(writer)?;
            write!(writer, ",")?;
            self.finalize_comm_stats.write_to_csv(writer)?;
            writeln!(writer)?;
        }
        Ok(())
    }
}

pub(crate) fn run_benchmark<Protocol: GF8InvBlackBox, ABB: ArithmeticBlackBox<GF8>, F, H, I, J>(
    conn: ConnectedParty,
    variant: AesVariant,
    simd: usize,
    n_worker_threads: Option<usize>,
    prot_str: Option<String>,
    setup_f: F,
    abb_f: H,
    prep_f: Option<I>,
    finalize_f: Option<J>,
) -> BenchmarkResult
where F: FnOnce(ConnectedParty, Option<usize>, Option<String>) -> Protocol,
H: FnOnce(&mut Protocol) -> &mut ABB,
I: FnOnce(&mut Protocol, usize, AesVariant) -> MpcResult<()>,
J: FnOnce(&mut Protocol) -> MpcResult<()>,
{
    let mut party = setup_f(conn, n_worker_threads, prot_str);
    let _setup_comm_stats = party.main_party_mut().io().reset_comm_stats();
    println!("After setup");

    let (prep_time, prep_comm_stats) = match prep_f {
        Some(prep_f) => {
            let start = Instant::now();
            prep_f(&mut party, simd, variant).unwrap();
            let prep_time = start.elapsed();
            let prep_comm_stats = party.main_party_mut().io().reset_comm_stats();
            println!("After preprocessing");
            (prep_time, prep_comm_stats)
        },
        None => (Duration::from_secs(0), CombinedCommStats::empty()),
    };
    // create random input for benchmarking purposes
    let input = aes::random_state(party.main_party_mut(), simd);
    // create random key states for benchmarking purposes
    let ks = aes::random_keyschedule(party.main_party_mut(), variant);

    let start = Instant::now();
    let output = match variant {
        AesVariant::Aes128 => aes::aes128_no_keyschedule(&mut party, input, &ks).unwrap(),
        AesVariant::Aes256 => aes::aes256_no_keyschedule(&mut party, input, &ks).unwrap(),
    };
    let duration = start.elapsed();
    println!("After online");
    let online_comm_stats = party.main_party_mut().io().reset_comm_stats();

    let (finalize_time, finalize_comm_stats) = match finalize_f {
        Some(finalize_f) => {
            let start = Instant::now();
            finalize_f(&mut party).unwrap();
            let finalize_time = start.elapsed();
            let finalize_comm_stats = party.main_party_mut().io().reset_comm_stats();
            println!("After finalize");
            (finalize_time, finalize_comm_stats)
        },
        None => (Duration::from_secs(0), CombinedCommStats::empty()),
    };

    let _ = aes::output(abb_f(&mut party), output).unwrap();
    println!("After output");
    party.main_party_mut().teardown().unwrap();
    println!("After teardown");

    BenchmarkResult::new(
        prep_time,
        duration,
        finalize_time,
        prep_comm_stats,
        online_comm_stats,
        finalize_comm_stats,
        party.main_party_mut().get_additional_timers(),
    )
}

pub(crate) fn run_benchmark_no_prep<Protocol: GF8InvBlackBox, ABB: ArithmeticBlackBox<GF8>, F, H, J>(
    conn: ConnectedParty,
    variant: AesVariant,
    simd: usize,
    n_worker_threads: Option<usize>,
    prot_str: Option<String>,
    setup_f: F,
    abb_f: H,
    finalize_f: Option<J>,
) -> BenchmarkResult
where F: FnOnce(ConnectedParty, Option<usize>, Option<String>) -> Protocol,
H: FnOnce(&mut Protocol) -> &mut ABB,
J: FnOnce(&mut Protocol) -> MpcResult<()>,
{
    run_benchmark(conn, variant, simd, n_worker_threads, prot_str, setup_f, abb_f, None as Option<fn(&mut Protocol, usize, AesVariant) -> MpcResult<()>>, finalize_f)
}

pub(crate) fn run_benchmark_no_finalize<Protocol: GF8InvBlackBox, ABB: ArithmeticBlackBox<GF8>, F, H, I>(
    conn: ConnectedParty,
    variant: AesVariant,
    simd: usize,
    n_worker_threads: Option<usize>,
    prot_str: Option<String>,
    setup_f: F,
    abb_f: H,
    prep_f: Option<I>,
) -> BenchmarkResult
where F: FnOnce(ConnectedParty, Option<usize>, Option<String>) -> Protocol,
H: FnOnce(&mut Protocol) -> &mut ABB,
I: FnOnce(&mut Protocol,usize,AesVariant) -> MpcResult<()>,
{
    run_benchmark(conn, variant, simd, n_worker_threads, prot_str, setup_f, abb_f, prep_f, None as Option<fn(&mut Protocol) -> MpcResult<()>>)
}

pub(crate) fn run_benchmark_no_prep_no_finalize<Protocol: GF8InvBlackBox, ABB: ArithmeticBlackBox<GF8>, F, H>(
    conn: ConnectedParty,
    variant: AesVariant,
    simd: usize,
    n_worker_threads: Option<usize>,
    prot_str: Option<String>,
    setup_f: F,
    abb_f: H,
) -> BenchmarkResult
where F: FnOnce(ConnectedParty, Option<usize>, Option<String>) -> Protocol,
H: FnOnce(&mut Protocol) -> &mut ABB
{
    run_benchmark(conn, variant, simd, n_worker_threads, prot_str, setup_f, abb_f, None as Option<fn(&mut Protocol, usize, AesVariant) -> MpcResult<()>>, None as Option<fn(&mut Protocol) -> MpcResult<()>>)
}

#[macro_export]
macro_rules! impl_benchmark_protocol {
    // match arm for no preprocessing and no finalize
    ($struct_name:ident, $prot_name:literal, $setup_fn:expr,$abb_fn:expr, None, None) => {
        crate::impl_benchmark_protocol!($struct_name, $prot_name, 
            fn run(&self, conn: ConnectedParty, variant: crate::aes::AesVariant, simd: usize, n_worker_threads: Option<usize>, prot_str: Option<String>) -> crate::BenchmarkResult {
                crate::benchmark::utils::run_benchmark_no_prep_no_finalize(conn, variant, simd, n_worker_threads, prot_str, $setup_fn, $abb_fn)
            }   
        );
    };
    // match arm for no preprocessing but finalize
    ($struct_name:ident, $prot_name:literal, $setup_fn:expr, $abb_fn:expr, None, $finalize_fn:expr) => {
        crate::impl_benchmark_protocol!($struct_name, $prot_name, 
            fn run(&self, conn: ConnectedParty, variant: crate::aes::AesVariant, simd: usize, n_worker_threads: Option<usize>, prot_str: Option<String>) -> crate::BenchmarkResult {
                crate::benchmark::utils::run_benchmark_no_prep(conn, variant, simd, n_worker_threads, prot_str, $setup_fn, $abb_fn, Some($finalize_fn))
            }   
        );
    };
    // match arm for preprocessing and no finalize
    ($struct_name:ident, $prot_name:literal, $setup_fn:expr, $abb_fn:expr, $prep_fn:expr, None) => {
        crate::impl_benchmark_protocol!($struct_name, $prot_name, 
            fn run(&self, conn: ConnectedParty, variant: crate::aes::AesVariant, simd: usize, n_worker_threads: Option<usize>, prot_str: Option<String>) -> crate::BenchmarkResult {
                crate::benchmark::utils::run_benchmark_no_finalize(conn, variant, simd, n_worker_threads, prot_str, $setup_fn, $abb_fn, Some($prep_fn))
            }   
        );
    };
    // match arm for everything
    ($struct_name:ident, $prot_name:literal, $setup_fn:expr, $abb_fn:expr, $prep_fn:expr, $finalize_fn:expr) => {
        crate::impl_benchmark_protocol!($struct_name, $prot_name, 
            fn run(&self, conn: ConnectedParty, variant: crate::aes::AesVariant, simd: usize, n_worker_threads: Option<usize>, prot_str: Option<String>) -> crate::BenchmarkResult {
                crate::benchmark::utils::run_benchmark(conn, variant, simd, n_worker_threads, prot_str, $setup_fn, $abb_fn, Some($prep_fn), Some($finalize_fn))
            }   
        );
    };
    // match arm to write out the impl
    ($struct_name:ident, $prot_name:literal, $run_impl:item) => {
        pub(crate) struct $struct_name;

        impl crate::BenchmarkProtocol for $struct_name {
            fn protocol_name(&self) -> String {
                $prot_name.to_string()
            }

            $run_impl
        }
    };
}