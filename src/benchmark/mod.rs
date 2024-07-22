use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufWriter, Write},
    path::PathBuf,
    thread,
    time::Duration,
};

use crate::{
    network::{Config, ConnectedParty},
    party::CombinedCommStats,
};

pub struct BenchmarkResult {
    prep_time: Duration,
    online_time: Duration,
    prep_comm_stats: CombinedCommStats,
    online_comm_stats: CombinedCommStats,
    additional_timers: HashMap<String, Duration>,
}

pub trait BenchmarkProtocol {
    fn protocol_name(&self) -> String;
    fn run(
        &self,
        conn: ConnectedParty,
        simd: usize,
        n_worker_threads: Option<usize>,
    ) -> BenchmarkResult;
}

pub struct AggregatedBenchmarkResult {
    prep_times: Vec<Duration>,
    online_times: Vec<Duration>,
    prep_comm_stats: CombinedCommStats,
    online_comm_stats: CombinedCommStats,
    additional_timers: HashMap<String, Vec<Duration>>,
    prep_time_avg_s: f64,
    online_time_avg_s: f64,
}

const WAIT_BETWEEN_SEC: u64 = 2;

fn benchmark(
    party_index: usize,
    config: &Config,
    iterations: usize,
    simd: usize,
    n_worker_threads: Option<usize>,
    protocol: &Box<dyn BenchmarkProtocol>,
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
        let res = protocol.run(conn, simd, n_worker_threads);
        agg.update(res);
        thread::sleep(Duration::from_secs(WAIT_BETWEEN_SEC));
    }
    agg.compute_avg();
    agg
}

pub fn benchmark_protocols(
    party_index: usize,
    config: &Config,
    iterations: usize,
    simd: usize,
    n_worker_threads: Option<usize>,
    protocols: Vec<Box<dyn BenchmarkProtocol>>,
    output: PathBuf,
) -> io::Result<()> {
    let mut results = Vec::new();
    for prot in &protocols {
        println!("Benchmarking {}", prot.protocol_name());
        let agg = benchmark(
            party_index,
            config,
            iterations,
            simd,
            n_worker_threads,
            prot,
        );
        results.push(agg);
        println!("Finished benchmark for {}", prot.protocol_name());
    }

    println!(
        "Writing CSV-formatted benchmark results to {}",
        output.to_str().unwrap()
    );
    // header
    let mut writer = BufWriter::new(File::create(output)?);
    writeln!(&mut writer, "protocol,simd,pre-processing-time,online-time,pre-processing-bytes-sent-to-next,pre-processing-bytes-received-from-next,pre-processing-bytes-rounds-next,pre-processing-bytes-sent-to-prev,pre-processing-bytes-received-from-prev,pre-processing-bytes-rounds-prev,online-bytes-sent-to-next,online-bytes-received-from-next,online-bytes-rounds-next,online-bytes-sent-to-prev,online-bytes-received-from-prev,online-bytes-rounds-prev")?;
    for (agg, prot) in results.into_iter().zip(protocols) {
        agg.write_to_csv(&mut writer, &prot.protocol_name(), &simd.to_string())?;
    }
    Ok(())
}

impl BenchmarkResult {
    pub fn new(
        prep_time: Duration,
        online_time: Duration,
        prep_comm_stats: CombinedCommStats,
        online_comm_stats: CombinedCommStats,
        additional_timers: Vec<(String, Duration)>,
    ) -> Self {
        let additional_timers: HashMap<String, Duration> = additional_timers.into_iter().collect();
        Self {
            prep_time,
            online_time,
            prep_comm_stats,
            online_comm_stats,
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
            prep_comm_stats: CombinedCommStats::empty(),
            online_comm_stats: CombinedCommStats::empty(),
            additional_timers: HashMap::new(),
            prep_time_avg_s: 0.0,
            online_time_avg_s: 0.0,
        }
    }

    pub fn n_iterations(&self) -> usize {
        self.prep_times.len()
    }

    fn update(&mut self, mut result: BenchmarkResult) {
        self.prep_times.push(result.prep_time);
        self.online_times.push(result.online_time);
        self.prep_comm_stats = result.prep_comm_stats;
        self.online_comm_stats = result.online_comm_stats;

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
    }

    pub fn write_to_csv<W: Write>(&self, writer: &mut W, name: &str, simd: &str) -> io::Result<()> {
        for i in 0..self.n_iterations() {
            write!(writer, "\"{}\",{},", name, simd)?;
            write!(
                writer,
                "{},{},",
                self.prep_times[i].as_secs_f64(),
                self.online_times[i].as_secs_f64()
            )?;
            self.prep_comm_stats.write_to_csv(writer)?;
            write!(writer, ",")?;
            self.online_comm_stats.write_to_csv(writer)?;
            writeln!(writer)?;
        }
        Ok(())
    }
}
