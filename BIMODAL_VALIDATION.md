# Bimodal core and compressed format validation

3 October 2026. The research library now implements both core profiles and both wire formats for 65,536 keys and secret width 18. The default is the optimized bimodal core with lossless compressed signatures. Ordinary/raw remains selectable as a control. This report supersedes the implementation status in the historical [ordinary baseline](BENCHMARK_VALIDATION.md).

The optimized main response uses sigma1=126976/5=25395.2, M1=2 and the existing global sign on the 23 small witness polynomials. The ordinary control uses sigma1=2031616/5=406323.2 and M1=4. Evaluation and quadratic auxiliaries occupy message rows, so no unsigned slack enters the optimized block. Range and randomness-block parameters are unchanged. Exact rational sampling and interval coins are used for both cores.

## Measurements

AMD Ryzen 7 9700X, Ubuntu-26.04 under WSL, GCC 15.2.0, Release. The four benchmark commands ran sequentially after compilation, analyzers and sanitizer signing completed. Each command generated its own public parameters/ring; these are unpaired samples. Within a command, each signature uses fresh complete attempts and the same ring. The first run uses cold backend caches.

| Core and format | Runs | Median sign seconds | Median verify seconds | Signature bytes |
|---|---:|---:|---:|---:|
| bimodal, compressed | 7 | 3.448 | 0.548 | 39436-39445 |
| ordinary, raw | 7 | 4.694 | 0.540 | 87634 |
| ordinary, compressed | 1 | 4.864 | 0.551 | 40182 |
| bimodal, raw | 1 | 3.049 | 0.556 | 87634 |

The bimodal compressed median size is **39443 bytes (38.519 KiB)**, **54.99% smaller** than raw. Median encoding and decoding were 0.995 ms and 0.209 ms. Verification timing includes decoding. Seven samples do not establish an expected signing cost or a reliable speedup: ordinary/raw attempts ranged from 1 to 93, and bimodal/compressed attempts from 1 to 38. All 16 recorded samples verified with zero sampler aborts.

The ring key payload remains **16 MiB**. The CRS blob is 1,886,764 bytes, and statement matrices add 9,216 bytes. Bimodal/compressed peak process RSS was 177468 KiB (173.31 MiB), including integration checks, additional profile instances, ring copies and allocator caches. The one-run profiles without integration peaked around 131.3 MiB. These figures do not measure node database overhead or Firo transaction throughput.

Raw samples and canonical manifests are stored beside [bimodal/compressed](benchmark_bimodal_compressed.json), [ordinary/raw](benchmark_ordinary_raw.json), [ordinary/compressed](benchmark_ordinary_compressed.json), and [bimodal/raw](benchmark_bimodal_raw.json). Public binary fixtures are retained locally and ignored by Git. Each corresponding `_digests.json` file records SHA-256 values; no secret fixture is saved. Older `benchmark_results.json` belongs to the previous implementation digest and is retained as historical evidence.

## Format and identity

The compressed container uses `BLRSB002`, version 2, and a 466-byte header. It packs 60-bit Q residues, omits checked zero evaluation lanes, reconstructs the self-adjoint challenge from 32 five-bit coefficients, and uses centered remainder/quotient coding for responses and hints. A canonical 31-one escape bounds parsing work for large tails. Decoder checks cover exact body length, coefficient/norm bounds, residues, challenge values, escapes, termination and padding. Raw uses `BLRSB001`, version 1, with exactly 87,634 bytes.

Both core and encoding enter the canonical manifest and proof identifier. The verifier uses its explicitly selected expected profile; it does not adopt parameters from a signature. The implementation digest now covers sixteen source/header/parameter/patch files, including both codec files. Raw and compressed proofs have separate identifiers, even when they share public matrices. Changing profile-defining code invalidates old fixtures.

Compression is lossless with **D=0**. The optimized compressed body's minimum is 38,210 bytes and maximum is 80,650 bytes, before its header. Full Q commitments alone use 22,965 bytes. This does not reproduce BLOOM's published sizes or implement the separate commitment-rounding optimization, which would require new extraction/security bounds. See [LNP Section 6.1 and Appendix A.2](https://eprint.iacr.org/2022/284.pdf), the [wire specification](BLOOM_LRS_SPEC.md), and [numerical profiles](PROOF_PARAMETERS.md).

## Commands and outcomes

From PowerShell, `.\build.ps1` passed the pinned dependency build, CMake Release build and all four CTest tests. Its first sandboxed invocation could not access the WSL service; the host invocation passed. No software was installed. `-Benchmark -Runs N -Core bimodal -Encoding compressed` runs the new default benchmark; ordinary/raw can be selected with the same switches.

The following commands ran inside WSL from this workspace:

```sh
cmake --build build -j4
ctest --test-dir build --output-on-failure
./build/blrs_bench --core bimodal --encoding compressed --runs 7 --integration-tests --output benchmark_bimodal_compressed.json
./build/blrs_bench --core ordinary --encoding raw --runs 7 --integration-tests --output benchmark_ordinary_raw.json
./build/blrs_bench --core ordinary --encoding compressed --runs 1 --output benchmark_ordinary_compressed.json
./build/blrs_bench --core bimodal --encoding raw --runs 1 --output benchmark_bimodal_raw.json
```

All passed. Four tests cover the relation, exact sampler, bounded containers and compressed body. Codec checks include independent Python-derived fixture digests, negative/tie/escape boundaries, response norms, bounds, truncation and canonical padding. The optimized sampler check exercises k14 Gaussian scale and identical bimodal decisions for shifts v and -v under identical deterministic bitstreams.

Both seven-run commands additionally passed forced +1/index 0 and -1/index 65,535 signing, full verification and same-secret linking across different rings/messages. Invalid linking and zero attempt budgets were rejected. Mutations covered message, ring order, tag, identifier, commitment, evaluation lane, range/response bounds, truncation and trailing bytes. Other core/encoding proof identifiers and unexpected wire formats were rejected.

For **each** of the four prefixes above, these commands passed:

```sh
./build/blrs_bench --verify-fixture PREFIX --core CORE --encoding ENCODING
python3 tools/check_candidate_artifacts.py PREFIX --digest-output DIGEST_PATH
```

Each C++ replay constructed a fresh backend and performed complete proof verification. The independent Python checker reconstructed all identifiers and decoded both formats with the selected numerical bounds; it does not verify lattice equations. Release replays took 0.56-0.61 seconds. Final ASan/UBSan replay of the bimodal/compressed fixture also passed.

```sh
cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_PREFIX_PATH=/home/reuben/.cache/spark-pq-measure-20261002/sage-env \
  '-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer' \
  '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined'
cmake --build build-sanitize -j4
ctest --test-dir build-sanitize --output-on-failure
./build-sanitize/blrs_bench --runs 1 --output benchmark_sanitize.json
./build-sanitize/blrs_bench --verify-fixture benchmark_bimodal_compressed.json
python3 proof_profile_explore.py --check
python3 check_specification.py
python3 measure_security.py --self-check
```

All passed. Sanitizer signing completed in two attempts and its generated compressed proof verified. All four sanitizer tests passed after the final code changes. C++ code was instrumented; imported LaZer/HEXL/Falcon libraries were not rebuilt with sanitizers. Numerical profile and specification checks passed; expensive estimator runs were not repeated because lattice parameters and estimates are unchanged.

## Review coverage

Clang-Tidy 21.1.8 used the matching CMake compilation database for all eleven project C++ translation units and the actual Make command for the monolithic patched LaZer C translation unit. It was rerun after final fixes with:

```sh
clang-tidy -p analysis \
  '--checks=-*,clang-diagnostic-*,clang-analyzer-*,bugprone-*,performance-*' \
  '--header-filter=^WORKSPACE/(include|backend|vendor/lazer/src/(lnp-quad|lazer-in2))' SOURCE
cppcheck --project=build/compile_commands.json \
  --enable=warning,performance,portability --error-exitcode=1 \
  --platform=unix64 -D__linux__=1 -D__x86_64__=1 -j3
```

All Clang-Tidy invocations exited 0; diagnostics were inspected. Fixed enum representation and a redundant trivial move were corrected. Nonblocking advisories remain for bounded constant multiplication, adjacent numeric parameters and the intentional unsupported-enum test. Vendor C retains its monolithic-inclusion advisories. Exit 0 is not presented as warning-free analysis.

Final Cppcheck passed, exit 0, for all eleven project C++ translation units and their included headers. The expanded twelve-unit scan including vendor C exited 1 with the same inherited null-pointer/self-assignment/signed-right-shift diagnostics in unchanged LaZer/Falcon code. Full vendor analysis is not clean; those sources were not expanded into this task's cleanup scope.

Independent source review covered the main witness/auxiliary inventory, both rejection parameter structures, codec reconstruction/bounds, profile/manifest binding, CLI, tests and Python checker. No confirmed scoped blocker remains. The generated parameter header was independently reproduced exactly; the four-file upstream provenance patch passed its reverse dry run.

The complete implementation diff was inspected against ordinary snapshot `faa13534f9af0c51701a34318046ff8929a0ad29` in an isolated temporary repository. Its snapshot includes prior ordinary code; `PROOF_PARAMETERS.md` is included as new review context because the prior review snapshot did not track it. Task-owned new files were included, `git diff --check` passed, and the original workspace index/user changes were preserved. No workspace commit or pull request was created.

CodeRabbit 0.8.2 authentication succeeded. One scoped attempt was made after checking the task files for credential patterns:

```text
coderabbit review --agent --dir C:\Users\reube\AppData\Local\Temp\SparkPQ-bimodal-review-2dbcb06544ac4e13900a6032ba1761e2 --base-commit faa13534f9af0c51701a34318046ff8929a0ad29 --include-untracked
```

It failed before analysis with `No Git repository found`, despite a verified initialized Git repository and explicit directory. No CodeRabbit analysis completed, and no further paid retry or CodeAnt review ran. This required external-review check remains incomplete.

## Remaining limits

This is a variable-time research candidate. Complete hidden-sign transcript simulation, Extended-MLWE/hint analysis, quantum Fiat-Shamir signature security, anonymity/frameability, multi-target key recovery, certified finite-abort error and a trustless cryptocurrency setup remain unresolved. Passing functional tests does not certify 128-bit quantum signature security.

Commitment rounding, smaller/larger ring profiles, constant-time secret operations, full vendor sanitizer coverage, fuzzing, native Windows/other CPUs, batch verification, an OOOMP comparison and Firo wallet/consensus integration are not implemented or validated by this change. Firo still needs a complete serial/value/balance spend relation. No node-storage claim follows from this standalone LRS benchmark.
