# MAESTRO

This crate implements different oblivious AES protocols for three parties. The new protocols are described in "[MAESTRO: Multi-party AES using Lookup Tables](https://eprint.iacr.org/2024/1317)".

If you found the software in this repository useful, please consider citing the paper below.
```
@misc{cryptoeprint:2024/1317,
      author = {Hiraku Morita and Erik Pohle and Kunihiko Sadakane and Peter Scholl and Kazunari Tozawa and Daniel Tschudi},
      title = {{MAESTRO}: Multi-party {AES} using Lookup Tables},
      howpublished = {Cryptology {ePrint} Archive, Paper 2024/1317},
      year = {2024},
      url = {https://eprint.iacr.org/2024/1317}
}
```

## Setup and Building

1. Install rust ([https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install))
2. Install openssl (only required for generating certificates for the benchmark setup if the benchmark is not run over localhost)
3. Install python and the following packages: `pandas numpy` (only required to parse the benchmark results)
4. Build and run the tests `RUSTFLAGS='-C target-cpu=native' cargo test --lib`
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

6. Build the benchmark binary `RUSTFLAGS='-C target-cpu=native' cargo build --release --bin maestro --features="clmul"`

## Running benchmarks
The benchmark always requires three parties. These can all be run on one machine (and communicate via localhost) or are on separate machines.

### On localhost
Running three parties on localhost requires no additional configuration. The config files in the repository `p1.toml`, `p2.toml` and `p3.toml` as well as the required key material `keys/p{i}.key`/`keys/p{i}.pem` is already prepared
and should work out of the box.

The CLI for the benchmark binary (found in `target/release/maestro`) offers some description and help on the parameters. It looks as follows
```
$> target/release/maestro -h
Usage: maestro [OPTIONS] --config <FILE> --rep <REP> [TARGET]...

Arguments:
  [TARGET]...  [possible values: chida, mal-chida, mal-chida-rec-check, lut16, gf4-circuit, lut256, lut256-ss, mal-lut256-ss, mal-lut256-ss-opt, mal-lut16-bitstring, mal-lut16-ohv, mal-gf4-circuit, mal-gf4-circuit-opt]

Options:
      --config <FILE>        
      --threads <N_THREADS>  The number of worker threads. Set to 0 to indicate the number of cores on the machine. Optional, default single-threaded
      --simd <SIMD>...       The number of parallel AES calls to benchmark. You can pass multiple values.
      --rep <REP>            The number repetitions of the protocol execution
      --csv <CSV>            Path to write benchmark result data as CSV. Default: result.csv [default: result.csv]
      --all                  If set, benchmark all protocol variants and ignore specified targets.
      --aes256               If set, the benchmark will compute AES-256, otherwise AES-128 is computed
  -h, --help                 Print help (see more with '--help')
```
The benchmark binary runs the specified protocols `<REP>` times, each computing the forward direction of `<SIMD>` AES blocks in parallel (without keyschedule). The relevant time and communication metrics are written to the file `<CSV>` in csv format.

The protocols are
- with semi-honest security
  - `chida`: the baseline work from [Chida et al., "High-Throughput Secure AES Computation" in WAHC'18](https://doi.org/10.1145/3267973.3267977). In the paper this is named GF(2^8)-Circuit.
  - `lut16`: Protocol 3 and Protocol 4 with pre-processing from Protocol 9
  - `gf4-circuit`: Protocol 3 where GF(2^4) inversion is computed via x^2 * x^4 * x^8
  - `lut256`: S-box computed via 8-bit LUT (Protocol 4) with pre-processing from Protocol 5
  - `lut256-ss`: S-box computed via 8-bit LUT (Protocol 6) with pre-processing from Protocol 4 (variant)
- with active security
  - `mal-chida`: the maliciously secure adaptation of the `chida` baseline. In the paper this is named Mal. GF(2^8)-Circuit.
  - `mal-chida-rec-check`: the maliciously secure adaptation of the `chida` baseline using Protocol 2 to verify multiplications.
  - `mal-lut16-bitstring`: maliciously secure version of `lut16` using Protocol 2 to verify multiplications.
  - `mal-lut16-ohv`: maliciously secure version of `lut16` using Protocol 2 to verify multiplications with reduced number of multiplications to verify (cf. Sect. 3.2 and Appendix C).
  - `mal-gf4-circuit`: maliciously secure version of `gf4-circuit` using Protocol 2 to verify multiplications
  - `mal-gf4-circuit-opt`: maliciously secure version of `gf4-circuit` using Protocol 2 to verify multiplications with reduced number of multiplications to verify (cf. Sect. 3.2)
  - `mal-lut256-ss`: maliciously secure version of `lut256-ss` using Protocol 2 and Protocol 7 (VerifiySbox)
  - `mal-lut256-ss-opt`: maliciously secure version of `lut256-ss` using Protocol 2 and Protocol 7 (VerifiySbox) with reduced number of multiplications to verify (cf. Appendix C)

To start the benchmark, run (**in 3 terminals**) 
- `target/release/maestro --config p1.toml --threads 4 benchmark --simd 250000 --rep 10 --csv result-p1.csv chida mal-chida lut16 gf4-circuit lut256 mal-lut16 mal-gf4-circuit`
- `target/release/maestro --config p2.toml --threads 4 benchmark --simd 250000 --rep 10 --csv result-p2.csv chida mal-chida lut16 gf4-circuit lut256 mal-lut16 mal-gf4-circuit`
- `target/release/maestro --config p3.toml --threads 4 benchmark --simd 250000 --rep 10 --csv result-p3.csv chida mal-chida lut16 gf4-circuit lut256 mal-lut16 mal-gf4-circuit`

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

| protocol | simd | pre-processing-time | online-time | finalize-time | pre-processing-bytes-sent-to-next | pre-processing-bytes-received-from-next | pre-processing-bytes-rounds-next | pre-processing-bytes-sent-to-prev | pre-processing-bytes-received-from-prev | pre-processing-bytes-rounds-prev | online-bytes-sent-to-next | online-bytes-received-from-next | online-bytes-rounds-next | online-bytes-sent-to-prev | online-bytes-received-from-prev | online-bytes-rounds-prev | finalize-bytes-sent-to-next | finalize-bytes-received-from-next | finalize-bytes-rounds-next | finalize-bytes-sent-to-prev | finalize-bytes-received-from-prev | finalize-bytes-rounds-prev |
| ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ |

which is processed by running `python parse-csv.py <file1.csv> <file2.csv> <file3.csv>`.

The script collects the maximum value of each column and protocol execution from the three parties, so we report the execution times of the slowest of the three parties per protocol run.
The slowest time per execution is then averaged ove the number of repeated executions. Taking the number of AES blocks (SIMD) into account, the script also outputs the throughput in blocks per second of the pre-processing and online phase.

An example output is
```
### SIMD = 50000

| Protocol | Prep Time | Prep Data (MB) | Online Time | Online Data (MB) | Finalize Time | Prep Throughput | Online Throughput | Total Throughput |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| chida 		|  |  | 0.44 | 32.00 | 0.00 |  | 114 528 | 114 528
| gf4-circuit 		|  |  | 0.32 | 20.00 | 0.00 |  | 158 013 | 158 013
| lut16 		| 0.24 | 11.00 | 0.30 | 16.00 | 0.00 | 206 463 | 167 955 | 92 614
| lut256 		| 4.60 | 247.00 | 0.42 | 8.00 | 0.00 | 10 867 | 117 704 | 9 949
| lut256_ss 		| 0.97 | 22.00 | 0.34 | 16.00 | 0.00 | 51 596 | 148 917 | 38 319
| mal-chida 		| 9.57 | 234.88 | 0.87 | 96.00 | 0.70 | 5 226 | 31 908 | 4 490
| mal-chida-rec-check 		|  |  | 0.83 | 32.00 | 2.18 |  | 16 626 | 16 626
| mal-gf4-circuit 		|  |  | 0.55 | 20.00 | 3.88 |  | 11 293 | 11 293
| mal-gf4-circuit-gf4p4 		|  |  | 0.98 | 20.00 | 2.08 |  | 16 347 | 16 347
| mal-lut16-bitstring 		| 1.24 | 11.00 | 0.71 | 16.00 | 2.22 | 40 376 | 17 037 | 11 981
| mal-lut16-ohv 		| 0.30 | 11.00 | 0.70 | 16.00 | 2.18 | 167 899 | 17 365 | 15 737
| mal-lut256-ss 		| 1.04 | 22.00 | 0.49 | 16.00 | 14.89 | 48 049 | 3 250 | 3 044
| mal-lut256-ss-opt 		| 1.07 | 22.00 | 0.55 | 16.00 | 3.90 | 46 658 | 11 229 | 9 051


| Protocol | Latency (ms) |
| ----- | ----- |
| chida 		| 437
| gf4-circuit 		| 316
| lut16 		| 298
| lut256 		| 425
| lut256_ss 		| 336
| mal-chida 		| 1567
| mal-chida-rec-check 		| 3007
| mal-gf4-circuit 		| 4427
| mal-gf4-circuit-gf4p4 		| 3059
| mal-lut16-bitstring 		| 2935
| mal-lut16-ohv 		| 2879
| mal-lut256-ss 		| 15382
| mal-lut256-ss-opt 		| 4453



### SIMD = 100000

| Protocol | Prep Time | Prep Data (MB) | Online Time | Online Data (MB) | Finalize Time | Prep Throughput | Online Throughput | Total Throughput |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| chida 		|  |  | 0.90 | 64.00 | 0.00 |  | 110 956 | 110 956
| gf4-circuit 		|  |  | 0.58 | 40.00 | 0.00 |  | 172 312 | 172 312
| lut16 		| 0.43 | 22.00 | 0.56 | 32.00 | 0.00 | 231 412 | 179 335 | 101 036
| lut256 		| 9.15 | 494.00 | 1.01 | 16.00 | 0.00 | 10 928 | 99 155 | 9 843
| lut256_ss 		| 1.85 | 44.00 | 0.70 | 32.00 | 0.00 | 54 056 | 142 052 | 39 156
| mal-chida 		| 19.82 | 469.76 | 1.61 | 192.00 | 1.36 | 5 045 | 33 646 | 4 387
| mal-chida-rec-check 		|  |  | 1.70 | 64.00 | 4.00 |  | 17 559 | 17 559
| mal-gf4-circuit 		|  |  | 1.08 | 40.00 | 7.64 |  | 11 477 | 11 477
| mal-gf4-circuit-gf4p4 		|  |  | 1.95 | 40.00 | 3.88 |  | 17 165 | 17 165
| mal-lut16-bitstring 		| 3.08 | 22.00 | 1.72 | 32.00 | 4.00 | 32 452 | 17 487 | 11 363
| mal-lut16-ohv 		| 0.55 | 22.00 | 1.43 | 32.00 | 3.92 | 180 460 | 18 691 | 16 937
| mal-lut256-ss 		| 2.11 | 44.00 | 1.08 | 32.00 | 31.04 | 47 465 | 3 112 | 2 921
| mal-lut256-ss-opt 		| 1.98 | 44.00 | 0.96 | 32.00 | 7.82 | 50 482 | 11 381 | 9 287


| Protocol | Latency (ms) |
| ----- | ----- |
| chida 		| 901
| gf4-circuit 		| 580
| lut16 		| 558
| lut256 		| 1009
| lut256_ss 		| 704
| mal-chida 		| 2972
| mal-chida-rec-check 		| 5695
| mal-gf4-circuit 		| 8713
| mal-gf4-circuit-gf4p4 		| 5826
| mal-lut16-bitstring 		| 5718
| mal-lut16-ohv 		| 5350
| mal-lut256-ss 		| 32125
| mal-lut256-ss-opt 		| 8786



### SIMD = 250000

| Protocol | Prep Time | Prep Data (MB) | Online Time | Online Data (MB) | Finalize Time | Prep Throughput | Online Throughput | Total Throughput |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| chida 		|  |  | 2.01 | 160.00 | 0.00 |  | 124 290 | 124 290
| gf4-circuit 		|  |  | 1.39 | 100.00 | 0.00 |  | 179 369 | 179 369
| lut16 		| 1.12 | 55.00 | 1.38 | 80.00 | 0.00 | 222 340 | 180 606 | 99 656
| lut256 		| 22.56 | 1235.00 | 2.49 | 40.00 | 0.00 | 11 083 | 100 214 | 9 979
| lut256_ss 		| 4.74 | 110.00 | 2.12 | 80.00 | 0.00 | 52 769 | 117 991 | 36 462
| mal-chida 		| 84.70 | 1879.05 | 4.11 | 480.00 | 3.66 | 2 951 | 32 185 | 2 703
| mal-chida-rec-check 		|  |  | 3.47 | 160.00 | 15.42 |  | 13 235 | 13 235
| mal-gf4-circuit 		|  |  | 2.56 | 100.00 | 15.70 |  | 13 689 | 13 689
| mal-gf4-circuit-gf4p4 		|  |  | 5.22 | 100.00 | 8.06 |  | 18 829 | 18 829
| mal-lut16-bitstring 		| 8.45 | 55.00 | 5.05 | 80.00 | 15.67 | 29 580 | 12 067 | 8 570
| mal-lut16-ohv 		| 1.33 | 55.00 | 4.18 | 80.00 | 8.90 | 187 348 | 19 113 | 17 344
| mal-lut256-ss 		| 5.60 | 110.00 | 2.98 | 80.00 | 65.72 | 44 630 | 3 639 | 3 364
| mal-lut256-ss-opt 		| 5.22 | 110.00 | 2.82 | 80.00 | 15.64 | 47 884 | 13 547 | 10 560


| Protocol | Latency (ms) |
| ----- | ----- |
| chida 		| 2011
| gf4-circuit 		| 1394
| lut16 		| 1384
| lut256 		| 2495
| lut256_ss 		| 2119
| mal-chida 		| 7767
| mal-chida-rec-check 		| 18888
| mal-gf4-circuit 		| 18262
| mal-gf4-circuit-gf4p4 		| 13277
| mal-lut16-bitstring 		| 20717
| mal-lut16-ohv 		| 13079
| mal-lut256-ss 		| 68700
| mal-lut256-ss-opt 		| 18453
```


## Raw Data of the benchmarks reported in the paper
The raw data of the experiments that are reported in the paper can be found in the `benchmark-data` folder. The csv data format is the same as described above.

### Throughput
- `benchmark-data/10Gbit` contains data of all protocols in the 10 Gbit/s network with batch sizes 50 000, 100 000 and 250 000.
- `benchmark-data/1Gbit` contains data of all protocols in the 1 Gbit/s network with batch sizes 50 000, 100 000 and 250 000.
- `benchmark-data/50Mbps-100msrtt` contains data of all protocols in the WAN network (50 Mbit/s with 100ms round trip time) with batch sizes 10 000m 50 000 and 100 000.

### Latency
- `benchmark-data/10Gbit-latency` contains data for 1 AES block in the 10 Gbit/s network,
- `benchmark-data/1Gbit-latency` contains data for 1 AES block in the 1 Gbit/s network,
- `benchmark-data/50Mbps-100msrtt-latency` contains data for 1 AES block in the WAN network.

## Documentation

All details on the implemented protocols are found in the research paper. 

To generate and view the code documentation run
```
cargo doc --open
```