# BLOOM-LRS: cost of targeting 128-bit quantum key recovery

Measured on 2 October 2026. Use secret width **18** as the next benchmark candidate: it adds 12.5% to the packed binary secret and explicit public matrices, and 13.1% to the measured public-key/link-tag arithmetic. Public keys remain 256 bytes. This is a parameter study, not a complete signature implementation or security certification.

## Results

| Secret width | ChaLoy21 work, bits | ADPS16 quantum work, bits | Packed binary secret | Explicit A+B | Combined As/Bs time | Arithmetic increase |
|---|---:|---:|---:|---:|---:|---:|
| 16, draft baseline | 117.963 | 121.635 | 128 B | 8 KiB | 14.25 microseconds | baseline |
| 17, smallest evaluated passing width | 133.640 | 137.800 | 136 B | 8.5 KiB | 14.98 microseconds | 5.1% |
| 18, suggested benchmark candidate | 149.831 | 154.495 | 144 B | 9 KiB | 16.12 microseconds | 13.1% |

The work columns are the minimum across the evaluated generic primal attacks under each cost model. Primal uSVP was cheapest in every case. They represent heuristic operation counts, not measured quantum execution times. Width 17 passes the 128-bit threshold in this suite, but its lower estimate leaves only 5.64 bits of margin. Width 18 leaves 21.83 bits; choosing it is a margin decision, not evidence that every unassessed attack needs that much work.

The public key `As` and link tag `Bs` each contain two degree-64 polynomials, with 16-bit coefficients: **256 bytes each at all three widths**. At `N=65,536`, the packed public-key set remains **16 MiB**. These bytes are shared output/key data, not another 16 MiB in every spend. Wider secrets do not enlarge those keys. The 9 KiB matrix figure is an explicit representation of the shared A and B parameters, not a per-output charge. Other coin fields, indexes and database overhead are excluded.

## Candidate and estimation method

The candidate is `d=64`, `p=65437`, two rows in each of A and B, secret width 18, independent uniform binary secret coefficients, and anonymity capacity `2^16`. A and B are fixed public protocol parameters, with one distinct `Bs` observation per secret. Reusing the same secret with different B matrices requires a new analysis. The modulus comes from the [original BLOOM parameter example](https://eprint.iacr.org/2022/1307.pdf); the attached LRS draft only specifies a 16-bit prime.

Stacking A and B gives four ring rows. Assuming an invertible four-column ring block, systematization produces a binary-secret/binary-error LWE model. The estimator inputs are:

```text
n = (secret_width - 4) * 64
q = 65437
Xs = Xe = Uniform({0,1})
m = 256 samples
```

Here the estimator's `m` means samples, not secret width. Flattening module-structured equations into ordinary LWE is a heuristic; specialized algebraic attacks are outside this study.

The [official lattice-estimator](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84) is pinned to commit `53da5982597709ba0fdf94ea37a84d822310fd84`. Models are `ChaLoy21()` and `ADPS16(mode="quantum")`, using quantum Core-SVP exponents 0.257 and 0.265 respectively. Primal calls use GSA. These model choices do not automatically make every search, oracle or probability component quantum-optimal.

The saved runs comprise 60 successful estimator calls:

- `security_screen.json`: uSVP at widths 16 through 24, under both models.
- `security_full.json`: uSVP, BDD, and hybrid combinations `(MITM,Babai)=(false,false)` and `(true,true)` at widths 16, 17, 18.
- `security_sensitivity.json`: the remaining hybrid combinations `(true,false)` and `(false,true)` at those widths. The official source labels the non-Babai MITM variant overly optimistic; it is included as a sensitivity check.
- `security_quantum_search.json`: the older finite-sample DH path with explicit `exhaustive_search(quantum=True)`. Its reported partial-secret search costs were higher, but its bounded optimizer and omitted remaining-secret reconstruction limit interpretation. These results are not used to certify the threshold.

The default MATZOV dual-hybrid path is excluded: at this pinned revision its cost function defaults to `params.n` samples rather than the supplied 256. No upstream estimator code was modified. Full quantum hybrid optimization, module-specific cryptanalysis, multi-target recovery, proof soundness, Module-SIS, linkability and complete LRS security remain unassessed.

## Arithmetic measurement

`measure_arithmetic.cpp` evaluates the four-row stacked matrix against binary secrets in `Z_p[X]/(X^64+1)`. It uses exact schoolbook negacyclic convolution with binary-dependent additions, a cached matrix and a deterministic pool of 16 secrets. All widths use the same input prefixes. The program includes checksum work in its timings, checks against an independent dense reference, and checks wraparound and modular boundaries.

`arithmetic_results.csv` preserves three runs, each reporting the median of nine warmed batches of 128 evaluations. The table above uses the median of those three medians. Hardware was an AMD Ryzen 7 9700X under WSL Ubuntu 26.04, GCC 15.2.0. Runtime/tool versions are in `runtime_manifest.json`.

Byte counts describe packed parameter representations. The benchmark allocates a fixed maximum-width matrix and stores each secret bit in a byte. Its branch on secret bits makes this a variable-time measurement kernel, unsuitable for production key generation. It excludes randomness, matrix derivation, encoding, proof generation and verification.

**Signature size and full signing/verifying time remain unmeasured.** Increasing the witness width requires new proof parameters, norm bounds and an exact encoding; multiplying the draft signature size by 18/16 would not produce a reliable answer. The draft also needs a precise construction for `N=2^16`, which does not directly match the original BLOOM recursion schedule. The earlier approximate 15.8 KiB signature figure is not a result for this candidate.

## Reproduction and validation

The isolated Sage 10.8/Python 3.12/SciPy runtime is retained in `/home/reuben/.cache/spark-pq-measure-20261002`. It was installed through conda-forge using official micromamba 2.9.0-0, verified against the release SHA-256 recorded in the manifest. No global Python environment or distro packages were changed.

Run these commands inside WSL, from this workspace. Use fresh output filenames; the driver refuses to overwrite measurements. The final `full` phase includes all four hybrid combinations, so these commands reproduce the same 60-call suite grouped into three files.

```sh
python3 measure_security.py --self-check
runtime=/home/reuben/.cache/spark-pq-measure-20261002
"$runtime/micromamba" --no-rc run -p "$runtime/sage-env" python measure_security.py "$runtime/lattice-estimator" security_screen_repeat.json --phase screen --width 16 17 18 19 20 21 22 23 24
"$runtime/micromamba" --no-rc run -p "$runtime/sage-env" python measure_security.py "$runtime/lattice-estimator" security_full_repeat.json --phase full --width 16 17 18
"$runtime/micromamba" --no-rc run -p "$runtime/sage-env" python measure_security.py "$runtime/lattice-estimator" security_quantum_repeat.json --phase quantum-search --width 16 17 18
g++ -std=c++20 -O3 -Wall -Wextra -Wconversion -Wpedantic measure_arithmetic.cpp -o /tmp/spark-pq-measure-arithmetic
/tmp/spark-pq-measure-arithmetic
```

Validation passed: Python syntax/input checks; all 60 estimator calls and input/sample checks; C++ independent-reference and boundary checks; ASan/UBSan; CSV dimension and median checks; `git diff --check`; Clang-Tidy and Cppcheck with the matching compilation database. Exact static-check commands were:

```sh
clang-tidy -p /tmp/spark-pq-arithmetic-checks "/mnt/c/Users/reube/OneDrive/Documents/ChatGPT/Spark PQ/measure_arithmetic.cpp"
cppcheck --project=/tmp/spark-pq-arithmetic-checks/compile_commands.json --enable=warning,style,performance,portability --inline-suppr --std=c++20 --error-exitcode=1
```

The sanitizer build/run used these flags and exited successfully without sanitizer diagnostics:

```sh
g++ -std=c++20 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Wconversion -Wpedantic measure_arithmetic.cpp -o /tmp/spark-pq-measure-arithmetic-sanitized
/tmp/spark-pq-measure-arithmetic-sanitized > /tmp/spark-pq-arithmetic-checks/sanitized.csv
```

An independent source review found two omitted hybrid variants; both were added and measured before handoff. No arithmetic defect was found. CodeRabbit 0.8.2 authenticated successfully, but both the working-directory attempt and explicit `--dir` attempt returned `No Git repository found` on a verified initialized review snapshot, before analysis. Its review is incomplete. Native Windows performance and full LRS/Firo integration tests were not run.
