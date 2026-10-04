# Fixed benchmark adapter

The upstream source is LaZer commit `3330e487228f633eceb322807b13a596b516770f`.
`lazer.patch` records the four modified upstream files. The unmodified archive is
retained under `vendor/lazer-source.tar.gz`; its SHA-256 is
`1714a260a3a53160a62d5ccc1325489f9d1c4ec27cf97197f416f206c585358c`.

This adapter supports ordinary and optimized bimodal cores: Q=1151179879138398721,
d=64, m1=23, m2=95, l=17, lambda=10, k_sis=20, D=0 and gamma=512. The
generated header uses the first three pinned degree-64 CRT primes. Their product
exceeds the integer lifting requirement for 128 accumulated products.
The ordinary core uses sigma1=(31/20)*2^18, M1=4 and ordinary rejection.
The optimized core uses sigma1=(31/20)*2^14, M1=2 and bimodal rejection.
Both use the same sigma2=(31/20)*2^15, M2=2 randomness-block rejection.
`Backend(crs, CoreProfile::Ordinary)` preserves the control profile;
`Backend(crs, CoreProfile::Bimodal)` selects the optimization.

`Backend` imports the explicitly sampled CRS. It does not call seeded
`abdlop_keygen`. The six auxiliary tB rows are filled by the generic evaluation
and quadratic protocols after the outer commitments have been published.

The selected prover invokes the C++ exact rational sampler for every y1/y2
coefficient and protocol rejection coin. The unused rounded variance fields in
the C parameter structure are retained for ABI compatibility. The adapter
returns rejection after one attempt. Sampler exceptions are caught inside C
callbacks, propagated after C cleanup, and require an outer restart.
The optimized rejection coin uses the existing signed witness and its shift
`c*s1`. The outer prover already samples one global sign and applies it to all
23 small witness polynomials (18 secret and 5 selectors). This adapter never
samples another sign. Evaluation masks and the final quadratic auxiliary occupy
message rows only, so no unsigned slack is appended to the optimized core.
The outer range block retains its ordinary rejection sampler. A joint proof of
hidden-sign transcript simulation remains an unresolved research obligation.

Verifier corrections enforce the 961/400 z1 bound, the full reconstructed z2
norm and the canonical hint limit. Both coefficients 0 and 32 of each evaluation
mask/output are zero, matching ten scalar repetitions packed into five
polynomials. The public wrapper rejects noncanonical coefficients and oversized
or duplicate sparse entries before importing them into C.
Before summing the recovered z22 norm in LaZer's fixed 128-bit accumulator,
check that its largest squared coefficient is at most the joint norm bound.
This necessary coordinate bound preserves every accepted valid input and makes
the subsequent 6080-coefficient joint accumulation fit in 128 bits.

The patched low-level functions are dedicated to these profiles. Other upstream
proof entry points are not supported or tested by this benchmark. LaZer's
internal SHAKE128/AES256CTR suite is retained. The exact sampler is variable-time
and has finite resource aborts. End-to-end quantum signature security and a
certified bound on finite abort error are separate unresolved questions.
Use a Backend instance from one thread at a time; upstream polynomial operations
mutate cached representations even while evaluating public matrices.

The C++ adapter asserts `RNG == RNG_AES256CTR` at compilation. Source review
confirms that evaluation, quadratic and seed-expansion hashes directly invoke
the pinned `shake128_*` functions (168-byte rate, 24 rounds and domain 0x1f).
The actual SHAKE implementation, RNG implementation, challenge sampler and
config header were compared byte-for-byte with the retained upstream archive.
There is no configurable internal hash-suite macro and no runtime hash self-test.

Build in Linux/WSL with `python3 tools/build_lazer.py --dependency-prefix PREFIX`,
where PREFIX contains existing GMP/MPFR headers and libraries. The bundled HEXL
source downloads CPU Features at its pinned commit
`32b49eb5e7809052a28422cfde2f2745fbb0eb76`. The helper does not install software.
