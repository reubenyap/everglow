# Commitment rounding and hint tuning

4 October 2026. Fixed width-18, 65,536-member bimodal research candidate.

**Recommended next implementation candidate: D=12, gamma=573560, hint Rice low-bit width=0.** Its compact size is 36,226 bytes (35.377 KiB), calculated from the median of five fully verified experimental proofs. The minimum of the two selected quantum Core-SVP SIS estimates is 140.065 bits. This retains more modeled binding strength for only 172 bytes over the D=13 frontier candidate.

The size-first frontier is D=13, gamma=2294240, hint width=0: 36,054 bytes (35.209 KiB), with a 128.500-bit SIS estimate. Nearby gamma=2117760 gave 36,052 bytes over three samples and 128.757 bits. These few-byte differences are within sample variation; the evaluation does not identify a uniquely optimal gamma from those samples.

The production candidate remains D=0, gamma=512. Experiments used isolated source copies and the existing raw format. Compact figures below are exact bit counts on their actual proof values, including the existing 466-byte header allowance, not output from an implemented new compact signature format. Neither candidate establishes full quantum signature security.

## Results

| D | gamma | Hint low bits | Proof samples | Median compact bytes | KiB | Minimum quantum SIS model bits |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 512 | 8, current codec | 5 | 39,445 | 38.521 | 178.872 |
| 0 | 512 | 7, encoding-only tuning | same 5 | 39,383 | 38.460 | 178.872 |
| 0 | 176480 | 0 | 3 | 38,162 | 37.268 | 170.391 |
| 10 | 458848 | 0 | 3 | 36,545 | 35.688 | 153.172 |
| 12 | 573560 | 0 | 5 | 36,226 | 35.377 | 140.065 |
| 12 | 1058880 | 0 | 3 | 36,215 | 35.366 | 138.009 |
| 13 | 2117760 | 0 | 3 | 36,052 | 35.207 | 128.757 |
| 13 | 2294240 | 0 | 5 | 36,054 | 35.209 | 128.500 |

D=12/gamma573560 saves 3,219 bytes (8.16%) against the new baseline median. D=13/gamma2294240 saves 3,391 bytes (8.60%). Choosing D=12/gamma1058880 instead buys only 11 median bytes while lowering the SIS estimate below 140.

The wire search tested every integer hint low-bit width from 0 through 16 on each saved proof, selecting one fixed width per profile. Width zero uses one unary terminator bit for a zero hint and no low-part bits; nonzero corrections and the existing bounded escape remain encoded. It is a lossless coding extension, distinct from the cryptographic D/gamma changes. With the existing codec's minimum supported width of one, the mean sizes of the D12 and D13 frontier candidates would instead be 36,370 and 36,206.2 bytes. Their width-zero means are 36,224.2 and 36,052.8 bytes.

## Search and security interpretation

Kept fixed: Q=1151179879138398721, its CRT factors, degree64, k_sis20, m1=23, m2=95, eta504, sigma1=126976/5, sigma2=253952/5, the ordinary range block, the width-18 key distribution, link relation and ring size.

The exact factorization Q-1=2^9*3^2*5*13*1103*3484511087 supplies 432 positive even gamma divisors. The arithmetic sweep covered all 13,392 pairs with D=0..30. The security screen used exact, rationally certified integer bounds and the pinned lattice-estimator revision 53da5982597709ba0fdf94ea37a84d822310fd84. A monotone bound search plus cached frontier estimates required 428 optimizer calls rather than estimating every pair independently.

The conservative extraction formula is:

```text
B_half = sigma2*sqrt(2*m2*d) + (eta*2^D+gamma)/2*sqrt(k_sis*d)
B1 = 2*sigma1*sqrt(2*m1*d)
B2 = 2*B_half
beta_SIS = 4*eta*sqrt(B1^2+B2^2)
```

The historical D=0 formula retains a conservative eta/2 allowance even though that commitment low part is actually zero. Baseline reproduction gives ceil(beta)=23326878867 and floor(B_half^2)=31572639091752.

At the fixed dimensions, D=13 is the largest exponent clearing 128 in both ChaLoy21 and ADPS16 quantum Core-SVP SIS models; D=14 fails even at gamma=2 (125.159 bits). Increasing D further only increases this bound. D=12 is the largest exponent clearing 140. At those exponents, gamma2294240 and gamma573560 are the largest divisors clearing their respective thresholds. This arithmetic frontier is exhaustive within the fixed parameters and selected models. Only seven parameter profiles received native proof measurements, so the measured size comparison is not an exhaustive empirical optimization of every divisor.

The stock code generator uses gamma > 2^(D+8) to favor small hints. [LNP Section 6.1 and Appendix A.2](https://eprint.iacr.org/2022/284) distinguish this efficiency guideline from the theorem's even-divisor requirement. D12/gamma573560 lies outside the guideline and uses the native generalized integer hints; it passed all functional experiments. [BLOOM Appendix B](https://eprint.iacr.org/2022/1307.pdf#page=29) explicitly includes LNP commitment compression in its signature-size calculation.

| Bound or estimate | Recommended D12/g573560 | D13/g2294240 |
|---|---:|---:|
| floor(B_half^2) | 2786758300172674 | 14520018366691105 |
| z21 coefficient absolute cap | 52789755 | 120499038 |
| Canonical tA1 maximum | 281049775180273 | 140524887590137 |
| tA1 bits per coefficient | 48 | 47 |
| Canonical hint interval | [-1003539193055,1003539193056] | [-250884798263,250884798264] |
| ceil(beta_SIS) | 212920789719 | 485883888593 |
| ChaLoy21 quantum Core-SVP | 140.065 | 128.500 |
| ADPS16 quantum Core-SVP | 144.425 | 132.500 |
| ADPS16 classical | 159.140 | 146.000 |
| Minimum modeled large-factor CRT-lift cost | 404.518 | 352.347 |

All shortlisted beta values remain below the large CRT factor. These CRT checks are a sensitivity screen, not an exhaustive analysis of composite-module attacks. Standalone key-recovery inputs and the existing plain-LWE dimensions do not change. The existing plain-LWE quantum estimate of 140.836 is a separate assumption, not a proof of the joint hint distribution. The recommended 140-bit SIS screen approximately balances those two numerical estimates without pushing binding down to the 128-bit boundary. Full transcript simulation, Extended-MLWE, quantum Fiat-Shamir, anonymity/frameability and finite sampler abort-error obligations remain unresolved.

## Functional measurements and validation

AMD Ryzen 7 9700X, WSL Ubuntu 26.04, GCC 15.2.0, Release. Profiles ran serially without overlapping analyzers. Each profile uses fresh public parameters and a synthetic ring with one valid signing key. Proofs within a profile share the ring. Randomness and rejection counts are unpaired across profiles.

All 27 measured proofs verified when generated and in individual fresh backend processes. The initial separate one-proof smoke run is excluded from the table. Both frontier candidates additionally passed positive/negative global signs at indices 0/65535, different rings/messages, verified same-secret linking, invalid linking, exhausted attempts, and the existing malformed/altered-proof integration checks. No measured sampler abort occurred.

Median sign/verify times were 3.658/0.538 seconds for the baseline, 1.206/0.545 seconds for D12/g573560, and 1.334/0.550 seconds for D13/g2294240. Small samples and very different retry counts prevent a signing-speed claim. Verification stayed around 0.54–0.55 seconds. The purpose of this experiment was size and feasibility.

The baseline passed all four CTests. Each changed profile passed relation, sampler and candidate tests. Fixed compressed-codec golden tests were skipped for changed profiles because they embed the original size/digest/bounds. The proposed new compact format has not undergone end-to-end C++ codec tests. Its independent accounting passed signed/escape boundary tests, a width-zero round-trip check, and exact reproduction of the saved 39,442-byte baseline fixture.

Clang-Tidy and Cppcheck ran on both frontier copies using their own matching compile_commands.json. Coverage: backend/backend.cpp, src/codec.cpp, src/candidate.cpp, src/benchmark.cpp, tests/candidate_tests.cpp, including generated backend/proof_params.h through its includer. All ten Clang-Tidy calls exited 0; inspection found inherited bounded-multiplication and adjacent-numeric-argument advisories. Both five-unit Cppcheck runs exited 0 without diagnostics. Unchanged vendor C was not reanalyzed or sanitizer-instrumented. No new sanitizer or fuzzing campaign ran.

Independent source review checked the extraction arithmetic, rounding endpoints, even-modulus canonical hints, sampler ordering, native D propagation, manifest binding, isolation and size accounting. A discovered one-unit rounding-tie error in the arithmetic helper was corrected; bit widths and search results were unchanged.

The six original evaluation files were inspected in a separate Git review snapshot against baseline 6829d3ef53647bf973401d68f486bb724c2ee845; git diff --check passed. The first CodeRabbit submission was blocked before execution by automatic approval review. After the user requested publication before external review, the work was pushed to reubenyap/everglow at d6e05bd91987a2f2d3c6a0d0510bb3219f4d1a93. CodeRabbit then completed a review of the eight changed text files, excluding the public binary signature fixture. Its three minor findings concerned the dependency-prefix default, the matching reproduction instructions, and unchecked template substitutions. The follow-up removes the personal default, documents a configurable runtime path and enforces exact substitution counts, including expected zeros. No extra paid credits or alternate reviewer were used.

## Reproduction and implementation boundary

Saved summaries: [security results](rounding_security_results.json), [benchmark and size results](rounding_benchmark_results.json). Result-file driver hashes identify the originally measured scripts, available at commit d6e05bd91987a2f2d3c6a0d0510bb3219f4d1a93; they are preserved when later publication fixes change the harness. Full local fixtures, manifests, hashes, source patches, logs and per-proof fresh-verification evidence remain under analysis/rounding-baseline-five-20261004, analysis/rounding-finalists-20261004 and analysis/rounding-comparisons-20261004. Static-analysis commands and logs are in analysis/rounding-static-checks/summary.json.

Run the following from the workspace; use fresh output paths:

```text
python tools/evaluate_rounding_security.py --check
python tools/benchmark_rounding.py --self-test
python tools/measure_rounding_wire.py --check
```

Inside WSL, use an existing runtime directory containing the micromamba executable, the sage-env environment with GMP/MPFR development files, and the pinned lattice-estimator checkout. Replace the placeholder below with that directory. Use its Sage Python for the security sweep and system Python for native experiments:

```sh
runtime=/path/to/existing/runtime
"$runtime/micromamba" --no-rc run -p "$runtime/sage-env" python tools/evaluate_rounding_security.py "$runtime/lattice-estimator" analysis/rounding_security_repeat.json
python3 tools/benchmark_rounding.py --dependency-prefix "$runtime/sage-env" --candidates 12:573560 13:2294240 --runs 5 --integration-tests --results analysis/rounding-repeat
python3 tools/measure_rounding_wire.py analysis/rounding-repeat/D12-g573560/benchmark.json analysis/rounding-repeat/D13-g2294240/benchmark.json --output analysis/rounding_wire_repeat.json
```

The harness records exact configure/build/test/sign/verify commands. It uses persistent isolated source copies in the existing Linux cache, references unchanged vendor libraries, and checks production identity-source hashes before/after each experiment. No default profile, existing specification, production source, index or commit was changed.

Adoption would require a separately identified D/gamma profile, revised bounds and manifest, 48-bit tA1 encoding for the recommendation, width-zero hint support, canonical even-modulus hint endpoints, and corresponding codec/negative tests. Enforce the rounded tA1 bound at the direct Backend::verify boundary as well as Candidate::verify. The current experiment validates the latter path. Full security claims still require the outstanding cryptographic analysis.
