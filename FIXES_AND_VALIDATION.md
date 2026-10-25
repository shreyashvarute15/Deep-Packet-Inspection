# DPI Engine Fixes and Validation

## Fixes in this review

### 1. Load-balancer counter-vector crash

`LoadBalancer` moved the constructor parameter `fp_queues` into the member `fp_queues_`, then sized `per_fp_counts_` using `fp_queues.size()`. The moved-from parameter can be empty, so the counter vector could have zero elements. `LoadBalancer::run()` later indexed `per_fp_counts_[fp_index]`, causing an out-of-bounds write and a reproducible segmentation fault.

The counter vector is now sized from `fp_queues_.size()`, the stored vector after the move.

### 2. Deterministic queue draining during shutdown

The LB and fast-path worker loops previously used `while (running_)`. `stop()` set `running_` false before workers drained their queues, so packets could be abandoned. The engine also relied on fixed 500 ms and 200 ms sleeps rather than a completion condition.

Workers now continue consuming queued items after their queues are shut down and exit only when a shut-down queue is empty. Shutdown proceeds in pipeline order: join reader, drain/stop load balancers, drain/stop fast-path workers, then shut down and drain the output writer. The fixed sleeps were removed.

### 3. Comparable and validated benchmark

The old benchmark compared `packet_analyzer --output` (which writes JSON) against `dpi_engine` (which writes a filtered PCAP). That was not a valid performance comparison.

The revised benchmark runs the same `dpi_engine` binary with two configurations: 1 LB/1 FP and 2 LBs/2 FPs. It uses identical inputs and blocking rules, enforces a 60-second timeout per run, validates output PCAP structure and packet counts, and refuses to report a speed ratio when either configuration fails. It is a worker-scaling comparison, not a comparison against a truly single-threaded implementation.

## Validation performed

Test environment: Linux x86-64, GCC 14.2, CMake 3.31.6. The Windows/MSYS2 UCRT64 toolchain was not available in this review environment, so rebuild on the target Windows machine before relying on the deliverable there.

- CMake Debug build: all project targets built.
- Unit tests: TLS SNI, HTTP Host, DNS query, and RuleManager tests passed.
- AddressSanitizer + UndefinedBehaviorSanitizer build: DPI engine and unit tests ran without reported sanitizer errors on the smoke PCAP.
- Synthetic 57-packet PCAP: 1-LB/1-FP and 2-LB/2-FP each exited successfully and wrote 55 packets after blocking the two test packets from source IP `192.168.1.50`.
- Repeated smoke test: 10 runs per configuration (20 total), all exited successfully and produced the expected 55 packets.
- Original `test_dpi.pcap`: 5 runs per configuration (10 total) with YouTube blocking; all produced 76 output packets.
- Invalid configuration (`--lbs 0`): correctly rejected.
- Full benchmark: all 4 input sizes completed for both configurations, with all output packet counts matching the expected count.

## Benchmark results (Release build, this test environment)

| Input size | Input packets | 1 LB / 1 FP mean | 2 LBs / 2 FPs mean | Relative ratio (baseline / parallel) |
|---|---:|---:|---:|---:|
| Small | 57 | 5.69 ms | 6.63 ms | 0.86x |
| Medium | 235 | 6.60 ms | 8.44 ms | 0.78x |
| Large | 870 | 9.01 ms | 10.34 ms | 0.87x |
| XLarge | 2,175 | 16.37 ms | 20.36 ms | 0.80x |

These synthetic-file measurements show that the parallel configuration was slower in this run. They do **not** prove that multithreading is always slower; the current inputs are small and process startup/coordination overhead is significant. Do not advertise a multithreaded speedup based on these results.

## Running on Windows with MSYS2 UCRT64

From the repository root in the UCRT64 shell, ensure the UCRT64 tools are on `PATH`, then run:

```bash
export PATH="/c/msys64/ucrt64/bin:$PATH"
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build -j2
./build/unit_tests.exe
python benchmark.py
```

The benchmark expects `build/dpi_engine.exe` on Windows. You can override the executable path with `DPI_ENGINE_PATH` if you build it elsewhere.

## Additional fix: hostname-to-application classification

- Replaced broad substring matching with DNS-label-boundary matching (exact domain or subdomain).
- This prevents `x.com` from matching `netflix.com` and `t.co` from matching `microsoft.com`.
- Added regression tests for Microsoft, Netflix, Twitter/X, unknown lookalike domains, and Host values containing a port.
- Validation in this environment: all targets built and all unit tests passed; the sample PCAP report correctly labels `www.microsoft.com` as Microsoft and `www.netflix.com` as Netflix.
- Rebuild and rerun tests on Windows with the UCRT64 toolchain before replacing the current working copy.
