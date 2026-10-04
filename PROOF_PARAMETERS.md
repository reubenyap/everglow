# Numerical proof parameters and sampler derivations

3 October 2026. This report selects research profiles for the width-18, 65,536-member statement in [BLOOM_LRS_SPEC.md](BLOOM_LRS_SPEC.md). The numerical arithmetic and ideal sampler results below are established under their stated conditions. The [research candidate](README.md) implements ordinary and optimized bimodal cores, the finite exact rational sampler, and raw or lossless compressed signatures. Complete adapter simulation, a certified finite sampler abort-error bound and the quantum signature reduction remain unproved; production Sign/Verify remain gated on those results.

## Selected profiles

The ordinary core is the implementation control; the narrower bimodal core is a separately identified optimization candidate. Both are executable research profiles and use an ordinary range block and BLOOM's one-time randomness-block rejection. The latter has a hint-bearing distribution, so even the ordinary-core control is not a claim of unconditional Gaussian transcript simulation.

| Parameter | Ordinary core | Bimodal core |
|---|---:|---:|
| Statement prime p, degree d | 65437, 64 | Same |
| Second prime q2 | 17592186058933 | Same |
| Proof modulus Q=p*q2 | 1151179879138398721 | Same |
| Commitment rows k_sis | 20 | 20 |
| Residual MLWE rows k_mlwe | 52 | 52 |
| Small witness m1 | 23 polynomials | 23 |
| Complete randomness m2 | 95 polynomials | 95 |
| Core messages | 13 polynomials | 13 |
| Generic evaluation input messages | 17 polynomials | 17 |
| Total tB rows, including auxiliaries | 23 | 23 |
| Evaluation repetitions lambda | 10, packed into five polynomials | Same |
| Compression D, gamma | 0, 512 | Same |
| Challenge operator bound eta | 504 | 504 |
| Randomness coefficient distribution | Uniform on {-1,0,1} | Same |
| sigma1, core Gaussian scale | 2031616/5 = 406323.2 | 126976/5 = 25395.2 |
| sigma2, randomness Gaussian scale | 253952/5 = 50790.4 | Same |
| sigma3, range Gaussian scale | 2031616/5 = 406323.2 | Same |
| Rejection constants M1,M2,M3 | 4,2,4 | 2,2,4 |
| Reciprocal-product attempt proxy | 32 | 16 |
| Uncompressed reference signature | 87634 bytes (85.58 KiB) | Same |

The attempt proxy excludes additional filters, auxiliary rejection and dependencies in the complete protocol. It is not a measured abort rate or a proved complete-attempt acceptance bound. The raw codec uses fixed 64-bit responses, so narrower Gaussian scales do not reduce this reference wire size. The implemented lossless compressed codec has a separate encoding profile and proof_id; its variable wire size and timing measurements are recorded in [BIMODAL_VALIDATION.md](BIMODAL_VALIDATION.md).

Both factors are distinct primes congruent to 5 modulo 8, and Q=1 modulo 512. The specification's self-adjoint challenge has 17^32 possibilities and coefficient l1 bound 504. BLOOM's unit-difference lemma applies to this factor family. The parameter checker verifies primality and the exact modulus conditions.

The explicit uniform commitment-key payload is 1886720 bytes, about 1.80 MiB; its canonical blob adds 44 header bytes. This is shared setup data, separate from the 9 KiB statement matrices, ring keys and each signature. Version 0.4 replaces the public AES expansion seed with these matrices and hashes their exact blob into the manifest. Publishing the AES key did not by itself justify applying uniform-CRS security assumptions to its output. The new choice retains the uniform-matrix premise under honest setup; deployment still needs a reviewed setup process. Lattice dimensions and all cost estimates remain unchanged.

The ring public keys occupy 16777216 bytes (16 MiB) separately. They are not repeated in the signature. This is key storage alone, before node database overhead or proof working memory.

## Minimal compiled relation

Let P be the 23-polynomial signed small witness, b the scalar sign, and K=1+X+...+X^63. For each P polynomial use Y_j=P_j-((b-1)/2)K. The last binary-map polynomial is Y_23=(b+1)/2. Division by 2 uses its inverse modulo Q; extraction later establishes the intended integer values. The complete Y has 1536 coefficients. For honest witnesses, its weight is at most 1467.

Integer binarity of Y and scalarity of b imply b is the global integer sign +1 or -1. Every coefficient of P is then 0 or b. Selector tails and sums force exactly one live coefficient per selector, hence ||P||²<=1152+5=1157. A separate small-witness norm proof would add unnecessary unsigned slack witnesses. Select Z=0.

Every external relation is compiled as a constant-coefficient evaluation. For E_r=X^(-r) in the negacyclic ring, ct(E_r*f)=f_r. With involution sigma(X)=X^(-1), ct(sigma(z)*E_r*h) selects the required shifted coefficient dot product. Four folds use r=8a modulo 64 and the appropriate one of the three h polynomials. All 18 row shifts fit their eight live selector entries within one polynomial.

| External equations | Scalar evaluations |
|---|---:|
| Four folds, 18 rows each | 72 |
| Tag equality | 128 |
| Terminal membership | 144 |
| Scalar b tails | 63 |
| Five selector tails | 272 |
| Five selector sums | 5 |
| Four intermediate packing tails | 192 |
| Total | 876 |

Add one aggregate binary evaluation and 256 range-opening evaluations: **1133 input scalar evaluations**, with no input full-ring equations. The aggregate is sum_i Y_i(Y_i-1)=0 modulo Q, compiled through coefficient dot products. Scalar b tails, all 192 literal h packing-tail zeros, aggregate binarity and range openings are full-Q constraints. Membership, tag, folds and selector conditions are equations modulo p, multiplied by Q/p before embedding.

The 13 core messages plus four range-mask messages give input l=17. Five evaluation garbage polynomials and one final quadratic auxiliary give tB=23. Evaluation variables have dimension 2*(23+17)=80; the lower many-quadratic stage has dimension 2*(23+22)=90. Commitment matrix shapes are A1:20x23, A2prime:20x75, Bprime:23x75, followed by the specified identity/zero blocks.

To implement ten scalar repetitions in five garbage polynomials, both coefficients 0 and 32 must be zero in each sampled garbage polynomial and checked zero in every public base_h polynomial. The factor controlling evaluation error is q_min=p, giving p^(-10), approximately 2^(-159.98). This assumes the corrected two-lane aggregation, commitment binding and the evaluation reduction. The unmodified API checks only five scalar combinations; its corresponding p^(-5) term is approximately 2^(-79.99), so it cannot support the stated lambda=10 bound unchanged.

## Ordinary rejection proof

Define the product integer Gaussian D_sigma(z) proportional to exp(-||z||²/(2sigma²)). Sigma is its scale parameter, not a statement that its exact variance equals sigma². For an integer shift v fixed independently of the fresh Gaussian mask, propose z=y+v with y drawn from D_sigma. Accept with

```text
a_v(z) = min(1, exp((||v||²-2<z,v>)/(2sigma²))/M).
```

Write p(z)=D_sigma(z), q_v(z)=p(z-v), d_v(z)=[p(z)-M*q_v(z)]_+, and delta=sum_z d_v(z). The accepted sublaw is (p-d_v)/M. Acceptance is (1-delta)/M and the normalized law r satisfies p=(1-delta)r+delta*(d_v/delta). Thus TV(r,p)<=delta, without an extra normalization factor.

For ||v||<=T and log(M)>=T²/(2sigma²)+20T/sigma, clipping can occur only in the target tail <z,v><-20sigma||v||. The product integer Gaussian is subgaussian, so delta<=exp(-200)<2^(-288.53). Therefore acceptance lies in [(1-exp(-200))/M,1/M] and output TV distance is at most exp(-200). This is a scalar projection tail argument, not a per-coordinate 20-sigma check. The sampler only evaluates the clipped likelihood ratio above. The discrete subgaussian property follows from [Canonne, Kamath and Steinke, Lemma 8](https://proceedings.neurips.cc/paper/2020/file/b53b3a3d6ab90ce0268229151c9bde11-Paper.pdf).

For the core, T1=504*sqrt(1157)=17143.41016... and the required expression is 0.84472129..., below log(4). For the range, the deterministic ternary projection bound gives T3=16*1467=23472 and the expression is 1.15700494..., also below log(4). No Gaussian approximation of the projection distribution is used.

There are two clipped ordinary blocks in the control, so their isolated composition contributes at most 2*exp(-200), about 2^(-287.54). The optimized profile has one such block. Applying these identities to an adaptive transcript still requires its simulation proof.

## Bimodal core and one-time randomness rejection

For a fixed unsigned shift v and fresh independent uniform sign, the proposal mixture is

```text
q_v(z) = D_sigma(z)*exp(-||v||²/(2sigma²))*cosh(<z,v>/sigma²).
```

Accept with exp(||v||²/(2sigma²))/(M*cosh(<z,v>/sigma²)). If M>=exp(T²/(2sigma²)), the coin is at most one, the accepted sublaw is exactly D_sigma/M, and acceptance is exactly 1/M. For sigma1=25395.2, exp(T1²/(2sigma1²))=1.25590492...<2. This proves the isolated mixture sampler with M1=2.

The global sign also appears in commitments and adaptive folds. It cannot simply be assumed independent of the final challenge after conditioning on them. A joint hybrid for the expanded relation is required before this identity supports signature anonymity. This obligation follows the hidden-sign construction in [BLOOM Section 3.2](https://eprint.iacr.org/2022/1307.pdf).

For rho, ||c*rho||<=T2=504*sqrt(95*64). At sigma2=50790.4, T2²/(2sigma2²)<1/2<log(2), so M2=2 dominates the one-time rejection coin. For a fixed one-sided shift v, its normalized accepted law is instead

```text
D_sigma(z)*(1+tanh(<z,v>/sigma²)).
```

It integrates to one by symmetry, but retains a logistic dependence on v. Treat it through BLOOM's Extended-MLWE/hint argument, including all 43 published masked rows. It is not witness-erasing ordinary rejection. The numerical plain-LWE estimates below do not prove that strengthened assumption.

The custom parameter generator must set M2=2 explicitly. The stock gamma-to-M formula would give approximately 1.34897436 for this width and shift bound. The chosen 2 is a valid conservative constant, with additional rejection cost; unchanged generator output does not reproduce it.

## Rigorous range extraction and binary no-wrap bound

Commit P, b and four fresh Gaussian mask polynomials y3 before drawing R. Sample every R entry as the difference of two independent uniform bits: probabilities 1/4,1/2,1/4 for -1,0,+1. R has 256 rows and 1536 columns. Publish z3=y3+R*Y after ordinary rejection, and verify

```text
|z3_i| <= L3 = ceil(24*sigma3) = 9751757, for all 256 coordinates.
```

No additional z3 Euclidean filter is selected. For the ideal target, failure of this box check has probability at most 512*exp(-288)<2^(-406.49). Any finite Gaussian cutoff is a different implementation decision and error term.

For fixed pre-challenge openings, suppose some centered coefficient of Y exceeds 2L3 in absolute value. Condition on all random bits in one row except one Bernoulli bit multiplying that coefficient. Its two resulting residues have circular distance greater than 2L3, so at most one lies in [-L3,L3]. Each independent row passes with probability at most 1/2. All 256 pass with probability at most 2^(-256). This is the infinity-norm argument of [LNP22 Lemma 2.7](https://eprint.iacr.org/2022/284.pdf), and requires commitment binding before R.

Thus extracted centered coefficients satisfy |Y_i|<=E=19503514, except for that event or binding failure. The integer aggregate satisfies

```text
0 <= sum_i Y_i*(Y_i-1) <= 1536*E*(E+1)
                              = 584274551580226560 < Q.
```

Because every integer term is nonnegative, the aggregate zero equation modulo Q is an integer zero equation and every Y_i is 0 or 1. This also excludes mixed CRT sign roots. The profile removes internal beta3/beta4 range signs entirely. It does not use LNP's heuristic binomial-to-Gaussian constants 13 or 337.

These are interactive, fixed-opening bounds. A malicious prover's adaptive openings, Fiat-Shamir grinding and quantum queries require the complete reduction, rather than reinterpreting 2^(-256) as a complete signature-security claim.

## Binding bounds and verifier acceptance

Using the conservative BLOOM/LaZer extraction formulas, with D=0,

```text
B_half = sigma2*sqrt(2*m2*d) + (eta/2+gamma/2)*sqrt(k_sis*d)
       = sigma2*sqrt(12160) + 508*sqrt(1280)
B1 = 2*sigma1*sqrt(2*m1*d)
B2 = 2*B_half
beta_MSIS = 4*eta*sqrt(B1²+B2²).
```

The retained eta/2 term overbounds the uncompressed low part, which is actually zero. It preserves a conservative extraction bound. The exact-check script certifies the displayed floors and ceilings by rational inequalities and integer squaring.

| Mandatory bound | Ordinary core | Bimodal core |
|---|---:|---:|
| Squared l2 norm of z1, maximum | 486050110174658 | 1898633242869 |
| Per-coefficient abs(z1) maximum | 22046544 | 1377909 |
| Squared joint l2 norm of z21 and recovered z22, maximum | 31572639091752 | Same |
| Per-coefficient abs(z21) maximum | 5618953 | Same |
| Canonical abs(hint) maximum | 1124199100721092 | Same |
| ceil(beta_MSIS) | 91733338857 | 23326878867 |

Compute z22 as center_Q(A1*z1+A2prime*z21-c*tA1-gamma*w1), with w1 recovered by the specified compression/hint operation. Check the norm of its **concatenation with z21**, using exact integer accumulation. Check the transmitted signed integers before embedding/reducing them. The explicit canonical bounds fit signed 64-bit storage. The hint bound is floor((Q-1)/(2gamma)).

## Heuristic lattice estimates

The retained Sage 10.8 runtime executed the pinned [lattice-estimator revision 53da598](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84). The selected profiles contain 30 completed costs: SIS lattice and LWE primal uSVP, BDD, primal hybrid and dual, for three models. Saved inputs and outputs are in [proof_profile_results.json](proof_profile_results.json).

| Cost model | Ordinary SIS | Bimodal SIS | Minimum plain LWE |
|---|---:|---:|---:|
| ADPS16 classical | 174.324 bits | 203.232 bits | 160.016 bits |
| ChaLoy21 quantum Core-SVP | 153.429 | 178.872 | 140.836 |
| ADPS16 quantum Core-SVP | 158.205 | 184.440 | 145.220 |

SIS uses n=1280, m=7552, Q and the displayed binding ceiling. Finite LWE uses n=3328, m=2752, with secret and error uniform on {-1,0,1}. These dimensions account for all 23 masked message rows and 20 Ajtai rows after systematization.

Six further SIS costs screen the pure CRT lift p*v from a kernel modulo q2, using bound ceil(beta/p). Minimum modeled cost is 468.511 bits for ordinary and 605.749 for bimodal. The complementary pure lift q2*v cannot meet the selected bound because beta<q2. This check does not exhaust composite-module cryptanalysis.

These are generic flattening estimates with quantum Core-SVP reduction costs. Hybrid guessing remains classical; module structure, specialized algorithms, multi-target attacks, rejection hints and the QROM reduction are not covered. Clearing 128 bits in these models is evidence for a benchmark candidate, not certification of full quantum security. The earlier width-18 **key-recovery** estimate remains a separate statement calculation.

The challenge space has log2(17^32)=130.79881... bits, with basic interactive error 2/|C| about 2^(-129.79881). It does not establish 128-bit quantum signature security. The conditional generic square-root challenge-search scale is about 2^65.4 queries; [multi-round QROM reductions](https://eprint.iacr.org/2020/282.pdf) also incur query-dependent losses. This is a concern requiring analysis of this adapter, not a demonstrated forgery or a universal 65-bit security ceiling. The retained SHAKE128 backend and hint-bearing assumptions need analysis too. Enlarging the challenge without recomputing eta and all affected bounds is invalid.

## Practical benchmark assessment

The profiles remain research candidates and do not yet justify production use in Firo. The raw signature is 85.58 KiB; the lossless codec retains the same proof values and reduces measured wire size. Full proving/verification timings are recorded separately in [BIMODAL_VALIDATION.md](BIMODAL_VALIDATION.md). The complete quantum signature-security claim is unresolved, and the statement still needs Firo's serial, value and transaction-balance relation.

A direct implementation of all four projected matrices performs `18*128*65536 + 18*144*(8192+1024+128) = 175214592` field multiply-accumulates per attempt. A full restart repeats these challenge-dependent folds. The reciprocal-product proxies 32 and 16 therefore identify a potentially expensive signing path; they are not timing measurements. Benchmark the abort stages and actual completed-attempt costs before judging viability. The earlier 16.12 microsecond key/tag arithmetic is not a signing-time estimate.

The projected matrices occupy 2695680 bytes if stored as packed uint16 field coefficients. The original ring is another 16 MiB, and the explicit proof CRS about 1.80 MiB. These are component representation counts, not peak process memory; compiled constraints, expanded integer types and temporary buffers add overhead. Original keys, ring hashes and fixed setup can be reused. Projected matrices depend on each new commitment prefix and cannot be reused across signatures under the current transcript.

## Finite sampler contract

The mathematical laws assume independent ideal integer Gaussians and ideal coins. The research implementation uses the rational-variance exact sampler of Canonne, Kamath and Steinke and rational-interval protocol coins, rather than assuming the pinned native tables have the nominal law. It bounds each probability, refines as needed and uses fresh random bits. Per-primitive work/proposal caps of 4096 and 2^20 cause explicit aborts, never substituted samples or approximate coins. Their finite abort-error bound is uncertified. Ordinary floating-point exp/cosh is not an accuracy proof.

A finite implementation must explicitly budget Gaussian truncation, primitive runtime caps, rejection-coin approximation, number of samples/coins and conditioning on complete-attempt acceptance. This profile does not freeze unproved native table errors or a nominal precision bit count as a security bound. A practical proposed contract is at most 2^16 Gaussian coefficients and 2^16 protocol coins per attempt, coefficient cutoff ceil(24sigma), and per-coin absolute error at most 2^(-510). The cutoff union bound is then below 2^(-398), and coin error at most 2^(-494). Those contracts must be implemented and checked, including every backend auxiliary sample.

If a complete-attempt acceptance lower bound a is established, use a conservative factor 2/a when conditioning a finite-versus-ideal approximation. The product proxy 1/32 does not establish such an a. Report finite abort failure separately from statistical distance. An exact variable-time research sampler can support benchmarking; a production constant-time sampler needs additional work.

## Implemented adapter changes and remaining proof obligations

The source pin is [LaZer 3330e487](https://github.com/lazer-crypto/lazer/tree/3330e487228f633eceb322807b13a596b516770f). The research adapter implements the following corrections; [backend/ADAPTER.md](backend/ADAPTER.md) and [backend/lazer.patch](backend/lazer.patch) record the selected implementation and provenance:

- External ordinary range step with four y3 rows, no beta3/beta4, the explicit infinity check and 1133 evaluations with Z=0.
- Correct randomness-block variance through exact rejection callbacks, replacing the pinned branch's incorrect stdev1sqr argument with the selected sigma2.
- Full reconstructed z2 norm, including the transmitted z21 contribution.
- Exact z1 bound based on 961/400 and the selected core exponent, plus canonical hint limits.
- Zero coefficients 0 **and 32** in each evaluation mask and public base_h polynomial for the two packed lanes.
- Single-attempt rejection propagated to an outer restart with fresh b, rho, masks, commitments and projections.
- Optimized bimodal core with k14/M1=2 and the existing signed P, alongside the ordinary k18/M1=4 control. Backend auxiliaries occupy message rows and introduce no unsigned slack into P; the range block stays ordinary.

The adapter revision, fixed generated manifest, profile bounds, wire encoding and implementation digest are bound into proof_id. Joint hidden-sign simulation, Extended-MLWE analysis and a certified bound on finite sampler abort error remain required before production use. Neither profile is executable by passing these numbers to the unchanged tbox generator.

## Reproduction and validation

Native, dependency-free arithmetic check:

```powershell
& 'C:\Users\reube\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -X utf8 .\proof_profile_explore.py --check
& 'C:\Users\reube\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -X utf8 .\check_specification.py
```

Both checks must pass before handoff. The parameter check covers prime conditions, exact rational rejection margins, algebraic binding floors/ceilings, representation bounds, dimensions and wire arithmetic. It does not run a Gaussian sampler or generate a signature.

To reproduce costs under the retained Sage environment, choose fresh output filenames:

```sh
runtime=/home/reuben/.cache/spark-pq-measure-20261002
"$runtime/micromamba" run -p "$runtime/sage-env" python proof_profile_explore.py "$runtime/lattice-estimator" fresh-ordinary.json --message-mode ordinary
"$runtime/micromamba" run -p "$runtime/sage-env" python proof_profile_explore.py "$runtime/lattice-estimator" fresh-bimodal.json --message-mode bimodal
```

The driver refuses a mismatched estimator commit or an existing output. The report retains eight original exploratory runs unchanged with SHA-256 provenance; their legacy tbox layouts and filters are superseded by the selected profiles. Its selected-profile sections contain the corrected caps. Independent source, compiler and sampler reviews checked the derivations. Earlier documentation-only validation is recorded in the specification; current C++ checks, benchmarks and external review coverage are recorded in [BIMODAL_VALIDATION.md](BIMODAL_VALIDATION.md).
