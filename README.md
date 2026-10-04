# BLOOM-LRS C++ research benchmark

The standalone library implements ordinary and optimized bimodal candidates for **65,536 keys and secret width 18**, with full signing, verification, verified linking, exact rational Gaussian sampling and bounded raw or compressed signature formats. The default is the bimodal core with lossless compression. It uses the pinned LaZer backend with the corrections recorded in [backend/lazer.patch](backend/lazer.patch).

This is a variable-time research implementation. Complete quantum signature security, finite sampler abort error and a trustless setup for cryptocurrency deployment remain unproved. The separate 128-bit quantum key-recovery target does not certify the complete protocol. This library does not change Firo.

## Build and run on this Windows machine

Run in PowerShell from this directory:

```powershell
.\build.ps1 -Benchmark -Runs 3
```

This builds in the existing `Ubuntu-26.04` WSL environment, uses the retained Sage dependency prefix, runs the four test executables, then writes `benchmark_local.json`. It installs no software. `-Distribution` and `-DependencyPrefix` select another existing environment. Use `-Core ordinary -Encoding raw` for the original control profile.

The pinned backend requires Linux x86-64, GCC 13.2 or later, AVX512 and AES CPU instructions. Existing build dependencies are CMake, Ninja, Python 3, make, patch, OpenSSL, GMP/GMPxx and MPFR. The first HEXL build fetches its pinned CPU Features dependency. On Linux:

```sh
python3 tools/build_lazer.py --dependency-prefix /path/to/existing/dependencies
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/path/to/existing/dependencies
cmake --build build -j4
ctest --test-dir build --output-on-failure
./build/blrs_bench --runs 3 --output benchmark_local.json
./build/blrs_bench --core ordinary --encoding raw --runs 1 --integration-tests
./build/blrs_bench --verify-fixture benchmark_local.json
python3 tools/check_candidate_artifacts.py benchmark_local.json
```

Omit the dependency-prefix options when dependencies are installed in standard system locations. The executable returns 2 if its attempt limit is exhausted, and 1 on an error. `--attempt-limit` defaults to 256 complete attempts per measured signature. Integration checks use test-only forced signs and their own limit of 512.

## Library

Link the CMake target `blrs` and include `blrs/candidate.hpp`. Generate parameters with `generate_parameters(random)`, construct `Candidate(parameters, CoreProfile::Bimodal, SignatureEncoding::Compressed)`, and call `sign_research`, `verify_research` or `link_research`. Supply an ordered ring of exactly 65,536 canonical keys and the caller's message. Signing validates the indexed key before starting. `link_research` reports equal tags only after verifying both signatures. A `Candidate` instance supports one caller at a time because the backend mutates polynomial caches.

Use `SystemRandom` for real measurements. Pass the same expected core and encoding to `encode_signature` and `decode_signature`; the defaults match the default candidate. Both choices are bound into the proof identifier, and a verifier rejects other profiles. Raw signatures serialize to exactly **87,634 bytes (85.58 KiB)**. Compressed signatures have variable size, about **38.5 KiB** in the measured bimodal sample. Public keys occupy **16 MiB per full ring** outside the signature. The explicit CRS occupies 1,886,764 bytes, plus 9,216 bytes for the statement matrices. The manifest binds those matrices and the sampler/profile choices to identifiers.

The optimized core reduces sigma1 from 406323.2 to 25395.2 and uses exact bimodal rejection with M1=2. It reuses the one global sign already applied to the 23 small witness polynomials. Auxiliary masks occupy message rows; no second sign is sampled. The ordinary range block and randomness-block rejection retain their existing parameters.

The compressed format packs Q residues into 60 bits, omits verified zero evaluation lanes, encodes the 32 independent challenge coefficients in 5 bits, and uses centered quotient coding for responses and hints. A 31-one escape bounds decoder work; coefficient/norm bounds, body lengths and canonical padding are checked before proof verification. This is lossless compression with **D=0**, so it retains full commitments and extraction bounds. It does not reproduce the paper's separate commitment-rounding optimization or its published signature sizes.

## Measurement scope

The driver generates 65,535 uniform synthetic decoys and one valid signing key. It reports total and distinct key counts. This exercises a full ring, but does not measure minting 65,536 coin outputs or node database overhead.

Every rejected signing attempt discards its complete transcript, commitments, masks and projections. The driver reports attempts, range/base rejections, sampler aborts, total signing time, verification time, codec timings, actual signature bytes and phase subtotals. `fold_seconds` includes projections, witness selection and staged recommitments. Original keys and the backend instance persist across measured runs; projected tables are recomputed for every attempt. The first run uses cold backend caches, with subsequent runs using warm caches.

Peak process RSS includes test data, temporary matrices and allocator caches. It measures process memory, rather than live library allocations. `--integration-tests` also includes validation fixtures in that peak. No node-storage or end-to-end Firo throughput claim follows from these timings.

With `--output PATH`, the driver also saves public CRS, statement, ring, message and signature fixtures beside the JSON file. It never saves the secret. The manifest includes a build-generated digest of sixteen profile-defining source/header/parameter/patch files, so changes to these files receive a different proof identifier.

The saved [bimodal compressed results](benchmark_bimodal_compressed.json) and [manifest](benchmark_bimodal_compressed.json.manifest.json) document the new default. The earlier [ordinary raw results](benchmark_results.json) retain their historical manifest and belong to the previous implementation digest. See [BIMODAL_VALIDATION.md](BIMODAL_VALIDATION.md) for the new commands, results and review limits, and [BENCHMARK_VALIDATION.md](BENCHMARK_VALIDATION.md) for the earlier baseline.
