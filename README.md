# NAME OF CRATE

This crate implements different oblivious AES protocols for three parties.

## Setup and Building

1. Install rust ([https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install))
2. Install openssl (only required for generating certificates for the benchmark setup if the benchmark is not run over localhost)
3. Install python and the following packages: `pandas numpy` (only required to parse the benchmark results)
4. Build and run the tests `RUSTFLAGS='-C target-cpu=native' cargo test`
5. Run the clmul benchmark to verify that the machine offers hardware support for carry-less multiplication `RUSTFLAGS='-C target-cpu=native' cargo bench "CLMUL Multiplication"`
    You should see similar output like
    ```
    Running benches/gf2p64_mult_benchmark.rs (target/release/deps/gf2p64_mult_benchmark-1203033260aede3b)
    Gnuplot not found, using plotters backend
    Benchmarking CLMUL Multiplication: Collecting 100 samples in estimated 5.0000 s CLMUL Multiplication    time:   [2.2679 ns 2.2710 ns 2.2742 ns]
    Found 5 outliers among 100 measurements (5.00%)
    2 (2.00%) high mild
    3 (3.00%) high severe
    ```
    If so, then clmul has hardware support.

6. Build the benchmark binary `RUSTFLAGS='-C target-cpu=native' cargo build --release`

## Running benchmarks
The benchmark always requires three parties. These can all be run on one machine (and communicate via localhost) or are on separate machines.

### On localhost
Running three parties on localhost requires no additional configuration. The config files in the repository `p1.toml`, `p2.toml` and `p3.toml` as well as the required key material `keys/p{i}.key`/`keys/p{i}.pem` is already prepared
and should work out of the box.

The CLI for the benchmark binary (found in `target/release/rep3-aes`) offers some description and help on the parameters. It looks as follows
```
$> target/release/rep3-aes -h
Usage: rep3-aes [OPTIONS] --config <FILE> <COMMAND>

Commands:
  chida-benchmark        Benchmarks the Oblivious AES protocol from Chida et al., "High-Throughput Secure AES Computation" in WAHC'18
  mal-chida-benchmark    Benchmarks the Oblivious AES protocol from Chida et al., "High-Throughput Secure AES Computation" in WAHC'18 in the **malicious** setting using the protocol from Furukawa et al with bucket-cut-and-choose and post-sacrifice to check correctness of multiplications
  lut16-benchmark        Benchmarks the LUT-16 variant with semi-honest security
  gf4-circuit-benchmark  Benchmarks the GF(2^4) circuit variant with semi-honest security
  lut256-benchmark       Benchmarks the LUT-256 variant with semi-honest security
  benchmark              Benchmarks one or more protocols with runtime and communication data written to CSV file
  help                   Print this message or the help of the given subcommand(s)

Options:
      --config <FILE>        
      --threads <N_THREADS>  The number of worker threads. Set to 0 to indicate the number of cores on the machine. Optional, default single-threaded
  -h, --help                 Print help
```
and for the `benchmark` command in particular
```
$> target/release/rep3-aes --config p1.toml benchmark -h
Benchmarks one or more protocols with runtime and communication data written to CSV file

Usage: rep3-aes --config <FILE> benchmark [OPTIONS] --simd <SIMD> --rep <REP> [TARGET]...

Arguments:
  [TARGET]...  [possible values: chida, mal-chida, lut16, gf4-circuit, lut256, mal-lut16, mal-gf4-circuit]

Options:
      --simd <SIMD>  The number of parallel AES calls to benchmark.
      --rep <REP>    The number repetitions of the protocol execution
      --csv <CSV>    Path to write benchmark result data as CSV. Default: result.csv [default: result.csv]
  -h, --help         Print help
```
The `benchmark` command runs the specified protocols `<REP>` times, each computing the forward direction of `<SIMD>` AES blocks in parallel (without keyschedule). The relevant time and communication metrics are written to the file `<CSV>` in csv format.

The protocols are

- `chida`: the baseline work from [Chida et al., "High-Throughput Secure AES Computation" in WAHC'18](https://doi.org/10.1145/3267973.3267977). In the paper this is named GF(2^8)-Circuit
- `mal-chida`: the maliciously secure adaptation of the `chida` baseline. In the paper this is named Mal. GF(2^8)-Circuit
- `lut16`: Protocol 2 and Protocol 4 with pre-processing from Protocol 6
- `gf4-circuit`: Protocol 2 where GF(2^4) inversion is computed via x^2 * x^4 * x^8
- `lut256`: S-box computed via 8-bit LUT (Protocol 4) with pre-processing from Protocol 5
- `mal-lut16`: maliciously secure version of `lut16` using Protocol 8 to verify multiplications
- `mal-gf4-circuit`: maliciously secure version of `gf4-circuit` using Protocol 8 to verify multiplications

To start the benchmark, run (**in 3 terminals**) 
- `target/release/rep3-aes --config p1.toml --threads 4 benchmark --simd 250000 --rep 10 --csv result-p1.csv chida mal-chida lut16 gf4-circuit lut256 mal-lut16 mal-gf4-circuit`
- `target/release/rep3-aes --config p2.toml --threads 4 benchmark --simd 250000 --rep 10 --csv result-p2.csv chida mal-chida lut16 gf4-circuit lut256 mal-lut16 mal-gf4-circuit`
- `target/release/rep3-aes --config p3.toml --threads 4 benchmark --simd 250000 --rep 10 --csv result-p3.csv chida mal-chida lut16 gf4-circuit lut256 mal-lut16 mal-gf4-circuit`

(where the number of threads, SIMD etc can be adapted depending on the capabilities of the machine)

The benchmark should print some information about the progress. Note that it waits 2 seconds between each run to give proper time to shutdown all network components.

At the end, the benchmark should print something like this
```
Benchmarking chida
Iteration 1
 <...>
Writing CSV-formatted benchmark results to result-p1.csv
```
and `result-p1.csv`, `result-p2.csv`, `result-p3.csv` should be created.

### On three different machines
Suppose that the machines are reachable under IP addresses `M1:PORT1`, `M2:PORT2` and `M3:PORT3`.
1. Create matching TLS certificates in `keys` folder:
    - for each machine, create `openssl-config-mX.txt` with the following content
    ```
    [ req ]
    default_md = sha256
    prompt = no
    req_extensions = req_ext
    distinguished_name = req_distinguished_name
    [ req_distinguished_name ]
    commonName = Party 1
    countryName = XX
    organizationName = MPC Org
    [ req_ext ]
    keyUsage=critical,digitalSignature,keyEncipherment
    extendedKeyUsage=critical,serverAuth,clientAuth
    [ SAN ]
    subjectAltName = IP:M1 <-- change the IP address to e.g. IP:192.168.1.10
    ```
    - Run
    ```
    for i in "m1" "m2" "m3" 
    do
        openssl genpkey -algorithm ED25519 > $i.key
        openssl req -new -out req.csr -key $i.key -sha256 -nodes -extensions v3_req -reqexts SAN -config openssl-config-$i.txt
        openssl x509 -req  -days 3650 -in req.csr -signkey $i.key -out $i.pem -extfile openssl-config-$i.txt -extensions SAN
    done
    rm req.csr
    ```
    to generate the certificates.
2. (In the main folder) Create TOML config files for each machine, e.g. `m1.toml` as
    ```
    party_index = 1               <-- set to 1, 2 or 3
    [p1]
    address = "127.0.0.1"         <-- IP address of party 1
    port = 8100                   <-- port of party 1
    certificate = "keys/p1.pem"   <-- path to certificate of party 1 (required)
    private_key = "keys/p1.key"   <-- path to corresponding private key of party 1
                                      (optional if party_index != 1)

    [p2]
    address = "127.0.0.1"
    port = 8101
    certificate = "keys/p2.pem"
    private_key = "keys/p2.key"

    [p3]
    address = "127.0.0.1"
    port = 8102
    certificate = "keys/p3.pem"
    private_key = "keys/p3.key"
    ```
3. Make sure that config file `m1.toml` is on machine 1, `m2.toml` on machine 2, etc. and that all certificates (`.pem`) files are on **all** machines.
4. Now the benchmark can be started as in the localhost case with similar CLI parameters (switching `p1.toml` with `m1.toml`, ...)


### Processing the benchmark data

The generated CSV files have the following format
| protocol | simd | pre-processing-time | online-time | pre-processing-bytes-sent-to-next | pre-processing-bytes-received-from-next | pre-processing-bytes-rounds-next | pre-processing-bytes-sent-to-prev | pre-processing-bytes-received-from-prev | pre-processing-bytes-rounds-prev | online-bytes-sent-to-next | online-bytes-received-from-next | online-bytes-rounds-next | online-bytes-sent-to-prev | online-bytes-received-from-prev | online-bytes-rounds-prev |
|----------|------|---------------------|-------------|-----------------------------------|-----------------------------------------|----------------------------------|-----------------------------------|-----------------------------------------|----------------------------------|---------------------------|---------------------------------|--------------------------|---------------------------|---------------------------------|--------------------------|

which is processed by running `python parse-csv.py <file1.csv> <file2.csv> <file3.csv>`.

The script collects the maximum value of each column and protocol execution from the three parties, so we report the execution times of the slowest of the three parties per protocol run.
The slowest time per execution is then averaged ove the number of repeated executions. Taking the number of AES blocks (SIMD) into account, the script also outputs the throughput in blocks per second of the pre-processing and online phase.

An example output is
```
SIMD = 750000
chida		Prep. Throughput: -	Online Throughput: 601510	Prep. Time: -s	Online Time: 1.2468604771s	Prep. Data: 0 byte	Online Data: 480000000 byte
gf4-circuit		Prep. Throughput: -	Online Throughput: 755559	Prep. Time: -s	Online Time: 0.9926423631000001s	Prep. Data: 0 byte	Online Data: 300000000 byte
lut16		Prep. Throughput: 480361	Online Throughput: 600046	Prep. Time: 1.5613252184s	Online Time: 1.2499034466999999s	Prep. Data: 165000000 byte	Online Data: 240000000 byte
lut256		Prep. Throughput: 25978	Online Throughput: 386774	Prep. Time: 28.870212009800003s	Online Time: 1.9391166385999998s	Prep. Data: 3705000000 byte	Online Data: 120000000 byte
```


## Raw Data of the benchmarks reported in the paper
The raw data of the experiments that are reported in the paper can be found in the `benchmark-data` folder. The csv data format is the same as described above.

### High-Throughput
- `benchmark-data/10Gbit/semi-honest-X` where X denotes the batch size (100000, 250000, 500000, 750000, 1500000, 2000000) contains data of the semi-honest protocols run with batch size X.
- `benchmark-data/10Gbit/malsec-X` where X denotes the batch size (100000, 250000, 500000, 750000, 1500000, 2000000) contains data of the malicious secure protocols run with batch size X.
- `benchmark-data/1Gbit` contains data of all protocols in the 1Gbit/s network.
- `benchmark-data/50Mbps-100msrtt` contains data of all protocols in the WAN network (50 Mbit/s with 100ms round trip time)

### Latency
- `benchmark-data/10Gbit-latency` contains data for 1 AES block in the 10 Gbit/s network,
- `benchmark-data/1Gbit-latency` contains data for 1 AES block in the 1 Gbit/s network,
- `benchmark-data/50Mbps-100msrtt-latency` contains data for 1 AES block in the WAN network.

### Protocol Names
The protocol names denote the following variants reported in the paper.
- `chida`, `lut16`, `gf4-circuit` and `lut256` denote the semi-honest protocols GF(2^8)-Circuit, LUT-16, GF(2^4)-Circuit and (2,3) LUT-256, respectively.
- `mal-chida` denotes the actively secure GF(2^8)-Circuit protocol variant
- `mal-lut16`, `mal-lut16-prep-check` and `mal-lut16-all-check` denote maliciously secure variants of LUT-16 where 
  - `mal-lut16` performs one multiplication check at the end,
  - `mal-lut16-prep-check` performs one multiplication check at the end of the pre-processing and one multiplication check at the end of the online phase. This is denoted as LUT-16 (prep) in the paper.
  - `mal-lut16-all-check` performs one multiplication check at the end of the pre-processing, and one multiplication check after each S-box. This is denoted as LUT-16 (prep+sbox)
- `mal-gf4-circuit` and `mal-gf4-circuit-all-check` denote the maliciously secure variants of GF(2^4)-Circuit where
  - `mal-gf4-circuit` performs one multiplication check at the end,
  - `mal-gf4-circuit-all-check` performs one multiplication check after each S-box. This is denoted as (sbox) in the paper.

## Documentation

All details on the implemented protocols are found in the research paper. 

To generate and view the code documentation run
```
cargo doc --open
```