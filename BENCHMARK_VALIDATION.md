# Candidate validation, 3 October 2026

Historical ordinary-core baseline. Current dual-core and compressed-format validation is in [BIMODAL_VALIDATION.md](BIMODAL_VALIDATION.md).

The ordinary-core research candidate builds and produces real, verifiable signatures for a 65,536-member ring. It uses secret width 18, the selected composite proof modulus and exact rational CKS sampling with interval acceptance coins. It implements the full transcript, 1,133 compiled scalar constraints, corrected proof backend and bounded 87,634-byte codec.

## Final measurements

Measured on AMD Ryzen 7 9700X, Ubuntu-26.04 under WSL, GCC 15.2.0, Release build. No analyzer or sanitizer job ran concurrently with these five samples. Each run used the same public parameters/ring and fresh complete proof attempts.

| Run | Attempts | Sign seconds | Verify seconds |
|---|---:|---:|---:|
| 1, cold caches | 20 | 2.592 | 0.550 |
| 2, warm caches | 6 | 1.858 | 0.536 |
| 3, warm caches | 16 | 2.854 | 0.542 |
| 4, warm caches | 21 | 3.191 | 0.559 |
| 5, warm caches | 8 | 2.005 | 0.561 |

Median signing was **2.592 seconds**; median verification was **0.550 seconds**. All five succeeded, with zero sampler aborts. Five observations are a small performance sample, and earlier exploratory signing runs took up to 12.76 seconds because of rejection variability. These numbers do not establish an expected attempt count or a worst-case signing bound.

The wire signature is **87,634 bytes, 85.580 KiB**. The ring is **16 MiB**, with 65,536 distinct synthetic keys and one valid signer. The encoded proof CRS is 1,886,764 bytes; public statement matrices add 9,216 bytes. Peak process RSS was **134,348 KiB, 131.20 MiB**, including the ring, temporary data and allocator caches. It is not a measurement of node database storage or live allocation bytes.

Setup took 4.7 ms, backend initialization 9.8 ms, synthetic ring generation 42.0 ms, and ring hashing 67.1 ms. Projection results depend on each commitment prefix and are recomputed on every attempt. The recorded folding phase includes witness selection and staged recommitments. Public decoys are uniform canonical keys, rather than a simulated history of minted cryptocurrency outputs.

Raw samples are in [benchmark_results.json](benchmark_results.json). The [manifest](benchmark_results.json.manifest.json) identifies the CRS and fourteen profile-defining implementation files. [Fixture SHA-256 digests](benchmark_fixture_digests.json) cover the public statement, CRS, ring, message, manifest and signature. Binary fixtures are retained locally and ignored by Git; no secret fixture is saved.

## Commands and outcomes

```powershell
.\build.ps1
```

Passed: dependency build, CMake Release build and three CTest tests. The script uses the existing WSL/Sage environment and installs no software.

Inside WSL, from this workspace:

```sh
cmake --build build -j8
ctest --test-dir build --output-on-failure
./build/blrs_bench --runs 3 --integration-tests --output benchmark_results.json
./build/blrs_bench --runs 5 --output benchmark_results.json
./build/blrs_bench --verify-fixture benchmark_results.json
python3 tools/check_candidate_artifacts.py benchmark_results.json --digest-output benchmark_fixture_digests.json
python3 proof_profile_explore.py --check
python3 check_specification.py
python3 measure_security.py --self-check
```

All passed. The three-run integration command exercised valid proofs for both private signs at indices 0 and 65,535, verified same-secret linking across different rings/messages, invalid-signature linking rejection, zero attempt-budget exhaustion, and independent mutations of message, ring order, tag, identifier, commitment, evaluation lane, range bound, response bound, truncation and trailing bytes. The later five-run command replaced the timing report and fixture with the final profile. Its `integration_tests:false` field describes that measurement command, rather than the separate integration coverage.

The relation test checks negacyclic multiplication, SHAKE/framing vectors, both signs, all 1,133 constraints and independent direct coefficient residuals. The sampler test checks independent Python-derived CKS vectors, distribution sanity checks and failure contracts. The codec test checks canonical CRS/signature round trips and bounded rejection. The Python fixture checker independently reconstructs statement/proof/ring/CRS identifiers and checks the wire layout and numerical bounds. It does not verify the lattice proof equations. Fresh C++ fixture replay performs full verification and passed in 0.644 seconds.

Sanitizer build and checks:

```sh
cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_PREFIX_PATH=/home/reuben/.cache/spark-pq-measure-20261002/sage-env \
  '-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer' \
  '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined'
cmake --build build-sanitize -j8
ctest --test-dir build-sanitize --output-on-failure
./build-sanitize/blrs_bench --runs 1 --output benchmark_sanitize.json
./build-sanitize/blrs_bench --verify-fixture benchmark_results.json
```

Passed: all three targeted tests, one complete signing/verifying round, and replay of the final public signature fixture. The complete round took 13 attempts; final sanitized replay passed in 5.079 seconds. C++ sources were instrumented; imported LaZer/HEXL/Falcon static libraries were not rebuilt with sanitizers. No claim of complete C/assembly sanitizer coverage is made.

## Review and analysis

Independent source reviews covered the relation/compiler, sampler laws, staged commitments, manifest, parsers, replay and linking. They found two issues that were corrected: an oversized reconstructed z22 norm could overflow the backend's 128-bit accumulator, and a ring-order mutation test reused an already altered message. The norm verifier now checks the largest squared coefficient before summation. The exact parameter generator checks that the guarded full accumulation fits. Full proof tests passed after relinking this fix.

Clang-Tidy 21.1.8 analyzed the nine project C++ translation units and the actual monolithic LaZer C translation unit, using the matching CMake/Make compile commands. The checks were:

```sh
clang-tidy -p analysis \
  '--checks=-*,clang-diagnostic-*,clang-analyzer-*,bugprone-*,performance-*' \
  '--header-filter=WORKSPACE/(include|backend|vendor/lazer/src/(lnp-quad|lazer-in2))' SOURCE
```

Every invocation exited 0, with diagnostics inspected. A final pass used `-p build` for changed candidate/sampler/benchmark sources. Nonblocking advisories remain for bounded multiplication widening and adjacent parameters. Vendor diagnostics include its pre-existing monolithic `.c` inclusion pattern. Exit 0 is not reported as a warning-free analysis.

```sh
cppcheck --project=build/compile_commands.json \
  --enable=warning,performance,portability --error-exitcode=1 \
  --platform=unix64 -D__linux__=1 -D__x86_64__=1 -j3
```

Passed, exit 0, across all nine project C++ translation units and included headers. An additional database included the exact Make command for `vendor/lazer/src/lazer.c`. That expanded run completed but reported inherited vendor null-pointer/right-shift diagnostics, so full vendor C analysis is **not clean**. The first attempt lacked implicit platform definitions and failed its preprocessor platform check; the configured rerun supplied the real Linux x86-64 definitions. The diagnostics concern unchanged source outside the four-file patch and are retained in local analysis logs, rather than silently suppressed or repaired outside this task.

The complete task diff was checked against isolated baseline `7a21cadb2fcd7df3d1be9b0bdeb48d189f394a71`, containing the pinned upstream C files and pre-implementation specification. New source/header/build/test files were included with intent-to-add. `git diff --check` passed. Patch-file whitespace attributes preserve the required space-prefixed context lines. The main checkout's earlier files and index were preserved; no commit or pull request was created there.

CodeRabbit 0.8.2 authentication succeeded. The scoped command was:

```text
coderabbit review --agent --dir C:\Users\reube\AppData\Local\Temp\SparkPQ-build-review-95605764a07a49cfa7cf0773399f0ff0 --base-commit 7a21cadb2fcd7df3d1be9b0bdeb48d189f394a71 --include-untracked
```

It failed before analysis with `No Git repository found`, despite the initialized repository and explicit directory. No CodeRabbit review completed, no further paid retry ran, and CodeAnt was not run. This is a missing independent paid-review check.

## Remaining limits

This candidate implements the ordinary-core profile. The optimized bimodal core is not implemented. CKS sampling and interval coins implement the ideal rational laws when their finite work limits do not abort; a certified statistical bound for these resource aborts remains unproved. The implementation does not claim the earlier planned 24-sigma truncation/error budget as a verified finite sampler bound.

Full quantum Fiat-Shamir security, Extended-MLWE/hint simulation, multi-target key recovery, anonymity/frameability and a trustless cryptocurrency setup remain unresolved. The selected key-recovery estimates do not establish 128-bit quantum security of the full signature. Secret operations are variable-time. Native Windows, other CPUs, fuzzing, every intermediate radix boundary as a full proof, OOOMP comparison, batch verification, and Firo wallet/consensus integration were not tested.
