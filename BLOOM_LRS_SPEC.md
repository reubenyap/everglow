# BLOOM LRS benchmark specification draft

Version 0.4, 3 October 2026. This document defines a proposed research implementation of the supplied BLOOM-LRS idea. Secret width 18 and a 65,536-member ring are selected. The equations and mixed-radix construction below are explicit adaptations, rather than an assertion that the short conference draft already specifies them.

The statement, witness, recursion, commitment order, outer encoding and API contract are defined. [Numerical research profiles and ideal sampler derivations](PROOF_PARAMETERS.md) are selected. The standalone [research candidate](README.md) implements ordinary and optimized bimodal cores, an exact rational sampler, and raw or lossless compressed signatures through explicitly named research signing and verification APIs. Complete security analysis and a certified bound on finite sampler abort error remain release gates for production Sign/Verify. This document does not establish 128-bit quantum security of the complete signature system.

## Security target and fixed statement parameters

The selected target is at least 128 bits of estimated **single-key quantum recovery** against the fixed public view `(A,B,As,Bs)`. The saved generic lattice estimates at width 18 are approximately 150 to 154 bits. They do not establish collision resistance, proof soundness, anonymity or quantum Fiat-Shamir security. See [the measurements](MEASUREMENTS.md) and their saved estimator inputs.

| Parameter | Value |
|---|---|
| Statement field prime `p` | 65437 |
| Polynomial degree `d` | 64 |
| Statement ring | `R_p = F_p[X]/(X^64+1)` |
| Secret width | 18 polynomials, 1152 binary coefficients |
| Public matrices | `A_key, B_link` each in `R_p^(2 x 18)` |
| Public key and tag | Each in `R_p^2`, 256 bytes each |
| Ring length `N` | Exactly 65536 |
| Selector radices | `(8,8,8,8,16)` |
| Projection count `ell` | 18 at each of four folds |
| Honest small-witness norm bound | Squared Euclidean norm at most 1157 |

`B_link` is a single fixed matrix for the statement parameter set, independent of the message, ring and signer. Different proof encodings must not silently generate a different link matrix for the same secrets. A scoped-tag construction is outside this profile.

`Setup` samples A and B independently, coefficient by coefficient, uniformly modulo p using a cryptographic random source with rejection of 16-bit candidates at least p. The public matrices are stored explicitly, occupying 9216 bytes together. This reference profile does not depend on an unspecified seeded matrix-expansion convention. These matrices are public parameters; proof commitment matrices use separate names and independently generated randomness.

`KeyGen` samples 1152 independent bits, packs them into 18 polynomials, and computes `t=A_key*s`. `Tag` computes `u=B_link*s`. No conditioning on a particular four-column invertible block is part of key generation. Invertibility was an assumption used in the heuristic estimation model, rather than an extra protocol rule.

## Exact statement and witness

For a public message byte string `msg`, an ordered ring `L=(t_0,...,t_65535)`, and public tag u, the relation is:

```text
There exist i in [0,65535] and s in {0,1}^1152 such that
    A_flat * s = flatten(t_i) mod p
    B_flat * s = flatten(u)   mod p.
```

Flatten a two-polynomial output in row-major order, with coefficients 0 through 63 in each row. Thus `A_flat,B_flat` are 128-by-1152 field matrices representing **negacyclic** multiplication. Multiplication uses `X^64=-1`; ordinary cyclic convolution is incorrect.

Let `T_0` be the 128-by-65536 matrix whose column i is `flatten(t_i)`. The message is bound into the Fiat-Shamir transcript; it is not an additional algebraic witness. Rings preserve the caller's order. They are not sorted or deduplicated inside the proof library. Duplicate keys do not increase effective anonymity, and the benchmark must report both total and distinct key counts.

The secret may include zero coefficients. Uniform generation includes the all-zero secret with negligible probability. The reference mathematical relation does not invent a separate public-key registration rule; cryptocurrency registration and duplicate-output policy need their own specification.

## Index decomposition and recursive membership equations

Let `r=(8,8,8,8,16)` and `n=(65536,8192,1024,128,16)`. For digit indices `d_j`, with `0 <= d_j < r_j`, use the most-significant-first convention:

```text
i = ((((d_0*8 + d_1)*8 + d_2)*8 + d_3)*16 + d_4).
```

Each `v_j` is a one-hot vector of length `r_j`. The tensor product `v_0 tensor ... tensor v_4` selects column i. For example, index 12345 has digits `(1,4,0,3,9)`; index 65535 has digits `(7,7,7,7,15)`.

At stage j, for j=0,1,2,3, partition `T_j` into eight **contiguous blocks**, each with `n_(j+1)` columns:

```text
T_(j,k)[:,c] = T_j[:, k*n_(j+1) + c],  k=0,...,7.
```

After the required previous commitments have been published, derive an independent uniform field matrix `Phi_j` with 18 rows. Its column count is 128 for j=0 and 144 for j=1,2,3. Define:

```text
T_(j+1)[8*a+k, c] = Phi_j[a,:] * T_(j,k)[:,c] mod p
    a=0,...,17; k=0,...,7.
```

The prover's intermediate witness is

```text
w_(j+1) = T_(j+1) * (v_(j+1) tensor ... tensor v_4) mod p.
```

Each `w_j` has 144 field coefficients. Membership is established by the following equations, plus the one-hot digit conditions:

```text
sum_k v_0[k]*w_1[8*a+k] - Phi_0[a,:]*(A_flat*s) = 0 mod p
sum_k v_j[k]*w_(j+1)[8*a+k] - Phi_j[a,:]*w_j = 0 mod p
    j=1,2,3; a=0,...,17
T_4*v_4 - w_4 = 0 mod p.
```

The separate tag equation is exact: `B_flat*s-u=0 mod p`. The recurrence processes exactly 65536 keys, without padding to 262144. Streaming or tiled construction of the projected matrices is permitted only if it produces identical coefficients and transcript inputs.

For fixed, bound witnesses and independent uniform field challenges, the four projection stages have an interactive error contribution at most `4*p^(-18)`, approximately `2^(-285.96)`, in addition to the backend's error. The commitment order and binding assumption are essential to this bound. It is not a quantum Fiat-Shamir security theorem.

## Hidden sign and quadratic proof relation

The original secret relation is intentionally not sign-invariant: a binary s generally does not remain binary after negation. Use the explicit hidden-sign construction from BLOOM Section 3.2, rather than the conference draft's contradictory statement that sign invariance is both retained and removed.

For each fresh proof attempt, sample an integer sign `b in {-1,+1}` uniformly, independently of the commitment randomness and Gaussian masks, and set:

```text
x = b*s
z_j = b*v_j
h_j = b*w_j.
```

The semantic equations over the prime field are:

```text
b^2 = 1
x_c*(x_c-b) = 0                         for each secret coefficient c
z_j[c]*(z_j[c]-b) = 0                   for c < r_j
sum_(c<r_j) z_j[c] = b
z_j[c] = 0                             for c >= r_j

sum_k z_0[k]*h_1[8*a+k] - b*Phi_0[a,:]*(A_flat*x) = 0
sum_k z_j[k]*h_(j+1)[8*a+k] - b*Phi_j[a,:]*h_j = 0
T_4*z_4-h_4 = 0
B_flat*x-b*u = 0.
```

All constraints have degree at most two. The sign is a **scalar**: if represented as a polynomial, every coefficient except coefficient zero must vanish. Recover the unsigned witness using `s=b*x`, `v_j=b*z_j`, and `w_j=b*h_j`. Over the prime field, the coefficient equations force binary s and one-hot digits, and the transformed equations recover the unsigned recurrence. Both global signs represent the same secret and tag.

These are coefficient conditions. Substituting polynomial multiplication `x*(x-b)=0` for coefficient-by-coefficient binarity is incorrect.

## Packing and compilation into the proof ring

The small-norm witness P contains the 18 signed secret polynomials x and five signed selector polynomials z_j, each selector zero-padded to 64 coefficients. It therefore contains 23 polynomials. Its honest squared norm is at most `1152+5=1157`.

Pack each h vector consecutively into three degree-64 message polynomials: entries 0 through 143, then 48 zeros. The final proof must constrain those 48 coefficients to zero. With the scalar sign first, the arbitrary-message vector is:

```text
M = (b, h_1[0:64], h_1[64:128], h_1[128:144] || zeros48,
        h_2 packed the same way,
        h_3 packed the same way,
        h_4 packed the same way).
```

This is exactly 13 witness-message polynomials. It does not count the proof backend's auxiliary messages or commitments. Their dimensions must be included in the generated profile and security estimates.

Embed P's signed integer coefficients in R_Q. For each intermediate vector, choose the unsigned w coefficients in `[0,p-1]`, form the integer h=b*w, then embed those signed values in R_Q. This preserves the global sign transformation before reduction. Only serialize their Q-residue representatives; the membership equations themselves are checked modulo p.

The proof ring is `R_Q=Z_Q[X]/(X^64+1)`, with selected candidate `Q=65437*17592186058933=1151179879138398721`. The original BLOOM modulus `4294564873` is superseded for this adaptation. For a relation modulo p, compile its coefficient residual modulo Q after multiplying by `Q/p`. Scalar dot products use constant-coefficient evaluations with explicit packing shifts. Scalar b tails and literal h packing-tail zeros are full-Q constraints, as are the aggregate binary equation and range openings. Do not replace coefficient dot products with full polynomial multiplication.

Binary/sign constraints need stronger handling than a lifted modulo-p equation. Q may be composite, so `b^2=1 mod Q` admits mixed CRT signs. Prove that coefficient zero of `(b+1)/2` is an integer binary value, constrain its other coefficients to zero, and thus force the global integer sign to be +1 or -1.

For each coefficient y of P, use the binary affine transform

```text
y = x_c - (b-1)/2
```

with the same transform for selector coefficients, including their padded tails. For b=+1 this gives the original binary coefficient; for b=-1 it gives its complement. Prove these binary values with the backend's integer/no-wrap binary mechanism. The complete binary-map output has **24 polynomials**: 23 transformed P polynomials and one scalar sign polynomial. The small-norm witness itself remains 23 polynomials. Signed selector sums and explicit zero tails then force exactly one live entry.

The honest squared norm of this binary-map output is at most **1467**, distinct from P's bound 1157. For b=-1, a zero secret maps to 1152 ones, and the five complemented selectors have 63 ones each; the scalar sign map is zero. For b=+1, the maximum including the sign bit is 1158. Parameter generation must use the bound belonging to the actual constrained vector.

Use verified extraction and no-wrap bounds, not only the honest bound 1157. A compiler using aggregate binary/norm equations must show that its integer equations are equivalent to the semantic coefficient equations and cannot wrap modulo Q.

The selected wrapper uses the explicit infinity-norm range argument in [PROOF_PARAMETERS.md](PROOF_PARAMETERS.md), rather than the stock tbox binary primitive. Integer binarity, scalarity and the selector equations imply P's norm bound, so `Z=0`: no separate norm-decomposition slack witness is added. The 876 external scalar equations, one aggregate binary equation and 256 range openings give 1133 input evaluations. Four range-mask messages extend the 13 core messages to 17; five evaluation garbage polynomials and one final auxiliary give 23 total tB rows.

## Commitments and challenge chronology

Use separate commitment matrices `A_com1,A_com2,B_msg`, independently of `A_key,B_link`. Their dimensions and distributions are part of the proof profile.

Once all expanded dimensions are fixed, independently sample and store every coefficient of `A_com1`, `A2prime` and `Bprime` uniformly in `[0,Q-1]`, independently of A_key and B_link. Read little-endian 64-bit words from the cryptographic random source, mask to the low `bit_length(Q-1)=60` bits and reject candidates at least Q. Do not reduce biased words modulo Q. Matrix shapes are respectively 20x23, 20x75 and 23x75. The complete matrices are `A_com2=(A2prime | I)` and `B_msg=(Bprime | 0)`; identity and zero blocks are implicit.

Set `commitment_encoding="blrs-explicit-crs-v1"`. Encode the public setup as ASCII `BLRSCR01` (8 bytes), `u16le(1)`, `u64le(Q)`, `u16le(d)`, then each of the three matrices in the order above. Each matrix begins with `u32le(rows)||u32le(columns)`, followed by row-major polynomials and coefficient order 0 through 63, using the Q-residue encoding below. The coefficient payload is 1886720 bytes; the complete setup blob is 1886764 bytes. Store this shared blob once, outside signatures and ring keys.

Compute `commitment_key_digest=SHAKE256(Frame("BLRS/commitment-key/v1",Enc(CRS)),64)` and include its lowercase hexadecimal encoding in the manifest before computing proof_id. Sign and Verify validate the blob's exact dimensions, Q, d, canonical coefficients and digest before using or caching it. A new commitment key changes proof_id while preserving statement_id and B_link. Never replace a key under an existing proof_id.

This supersedes version 0.3's public AES256CTR expansion seed. The pinned implementation uses that public seed as an AES key; standard secret-key PRG security alone does not establish the uniform-CRS MLWE/MSIS premise for that family. A seeded alternative needs its own declared matrix-distribution assumption and review. Explicit uniform sampling removes this transfer gap, assuming honest setup and the stated random-source contract; it does not establish a trustless cryptocurrency setup procedure.

Conceptually, with a single short randomness vector rho:

```text
C_A = A_com1*P + A_com2*rho mod Q
C_B = B_msg*rho + M mod Q.
```

Initially publish `C_A` and only the message row committing to b. After deriving `Phi_0`, publish the three rows committing to h_1. Then derive `Phi_1`, publish h_2's three rows, derive `Phi_2`, publish h_3's three rows, derive `Phi_3`, and publish h_4's three rows. Publish four rows committing to independently sampled y3, derive the ternary range matrix R, and publish z3=y3+R*Y after ordinary rejection. Finally run the generic quadratic/evaluation proof against this exact accumulated commitment and its retained openings. Internal beta3/beta4 range signs are absent.

The same rho is used for these disjoint message rows. Do not publish zero-message stand-ins for future rows and later replace them: subtraction would reveal h. Applying a generic high-level prover that creates a fresh commitment after the projections is also incorrect.

Computational binding of the initial Ajtai commitment must fix both P and rho under the **relaxed extracted-opening** MSIS bound. Each disclosed message group is then fixed before its next challenge. Hiding and Extended-MLWE analysis must include every published pad row and backend auxiliary using rho, not only the initial prefix.

The commitment rounding parameter remains `D=0` in both implemented wire encodings. Lossless bit/entropy packing changes only the representation of these exact values and is described below. A variant that changes D requires a distinct proof profile, an explicit retained low-part/hint layout and recomputed extraction bounds.

## Transcript and randomness

All outer hashes use SHAKE256 with explicit domain labels. The pinned backend uses SHAKE128 internally; the manifest must declare that internal suite and every adapter change. An outer SHAKE256 digest does not upgrade the backend's internal hashes. Any SHAKE256 backend adaptation needs its own revision, test vectors and security analysis. `Frame(label,data)` is `u32le(label_length) || ASCII(label) || u64le(data_length) || data`. Integers and polynomial vectors use the canonical encodings defined below. Field challenge derivation reads little-endian 16-bit XOF words and rejects words at least p, rather than reducing them modulo p.

Define 64-byte identifiers:

```text
statement_id = SHAKE256(Frame("BLRS/statement/v1", canonical_statement_parameters),64)
proof_id     = SHAKE256(Frame("BLRS/proof/v1", complete_proof_manifest),64)
ring_id      = SHAKE256(Frame("BLRS/ring/v1", statement_id || u32le(N) || Enc(L)),64).
```

Encode `canonical_statement_parameters` exactly as `u32le(p) || u16le(d) || u16le(secret_width) || Enc(A_key) || Enc(B_link) || u64le(context_length) || context`. Each matrix has two rows and secret_width columns of degree-d polynomials, encoded row-major, then polynomial coefficient order, using canonical uint16 field elements. Matrix lengths follow from these dimensions; context is an arbitrary public byte string.

Encode `complete_proof_manifest` as canonical ASCII JSON: unique object keys at every nesting level sorted by their ASCII bytes, no whitespace, decimal integers with no leading zeros or negative zero, array order preserved, and literal `true`/`false` for booleans. Floats and null are forbidden. Keys and string values contain printable ASCII excluding quote and backslash; emit those characters literally, with no escape sequences. Bytes are lowercase hexadecimal strings; exact rational parameters are objects with integer `numerator` and positive integer `denominator`. No values are rounded through floating point. The manifest must include `spec_version`, `statement_id`, `ring_length`, `radices`, `ell`, `backend_revision`, `adapter_revision`, `internal_hash_suite`, `commitment_encoding`, `commitment_key_digest`, and every numeric, layout and sampler field required below. It must completely describe the backend's generated parameters and compiled-constraint layout, without defaults inherited from a machine's installation. The research candidate generates its fixed canonical schema in [src/candidate.cpp](src/candidate.cpp); it does not accept arbitrary external manifests. Core and wire selection, response bounds, sampler resource caps and an implementation digest are included in proof_id. Production review of this complete profile remains required.

Full-signature test-vector digests are published alongside the manifest, outside the bytes hashed for proof_id, to avoid a self-referential identifier. Proof-profile changes preserve A and B when the statement parameters are unchanged.

The initial transcript is the concatenation, in this order, of `Frame(label,value)` for the following pairs:

```text
"BLRS/version/v1",      u16le(1)
"BLRS/statement-id/v1", statement_id
"BLRS/proof-id/v1",     proof_id
"BLRS/ring-id/v1",      ring_id
"BLRS/message/v1",      msg
"BLRS/tag/v1",          Enc(u)
"BLRS/CA/v1",           Enc(C_A)
"BLRS/Cb/v1",           Enc(C_b).
```

For j=0,1,2,3, derive Phi_j from the SHAKE256 XOF stream of `Frame("BLRS/fold/j/v1",prefix)`, replacing j with its single decimal digit. Fill Phi in row-major order with the unbiased field samples. Then append `Frame("BLRS/h-commit/k/v1",Enc(C_hk))`, replacing k with j+1, for the three commitment rows of h_(j+1). Enc of a commitment vector is polynomial-major, then coefficient-major, using the Q-residue encoding below. Each fold consumes its own XOF stream from the complete current prefix.

After h_4's commitment, append `Frame("BLRS/range-mask/v1",Enc(C_y3))` for the four y3 commitment rows. Derive R from the SHAKE256 XOF of `Frame("BLRS/range/v1",prefix)`, in row-major order over 256x1536 entries. Consume XOF bytes in order, least significant bit first; each successive pair (a,b) of uniform bits gives entry a-b. Append `Frame("BLRS/range-response/v1",Enc(z3))`, where z3 is exactly 256 signed little-endian int64 coefficients. The verifier enforces the explicit infinity cap and the compiled openings before acceptance.

Then derive `constraint_digest=SHAKE256(Frame("BLRS/compiled/v1",compiled_constraint_bytes),64)` and seed the base proof with `SHAKE256(Frame("BLRS/base/v1",prefix)||Frame("BLRS/constraints/v1",constraint_digest),32)`. The adapter's versioned schema must fix compiled_constraint_bytes, including all matrix dimensions, coefficient order, constants and proof-ring residues. A 32-byte backend digest is a property of the pinned API, not a claim that the full protocol reaches 128 quantum bits. No signing counter, index, sign or witness data is an explicit public transcript field.

Every new proof attempt uses a fresh sign, fresh rho and fresh Gaussian masks from a cryptographic random source. On a rejection restart, discard the entire previous attempt, including its commitments and projections. A benchmark may impose an attempt limit, but it must return failure on exhaustion and report the observed abort rate. It must not reuse a rejected prefix to save timing work. Deterministic PRNGs are confined to labelled test vectors and algebra checks.

The pinned low-level prover contains internal retry loops that retain commitment state. The adapter must expose a single-attempt rejection result and propagate it to this whole-attempt restart policy; calling the existing prover unchanged does not provide that contract.

## Base proof adapter and numerical profile

The implementation starting point is [LaZer commit 3330e487228f633eceb322807b13a596b516770f](https://github.com/lazer-crypto/lazer/tree/3330e487228f633eceb322807b13a596b516770f), using low-level ABDLOP and generic LNP quadratic/evaluation functions with a custom ordinary range wrapper. The stock tbox is not the selected layout. The research adapter generates and selects ordinary and optimized bimodal main-message profiles, each with its own proof_id. The optimized signed-message rejection algorithm follows BLOOM Section 3.2.

The numerical candidates use `k_sis=20`, `k_mlwe=52`, `m2=95`, `lambda=10`, `D=0`, `gamma=512`. Exact Gaussian scales are core `2031616/5` (ordinary) or `126976/5` (bimodal), randomness `253952/5`, and range `2031616/5`. Rejection constants are `(4,2,4)` or `(2,2,4)`. The range infinity cap is 9751757, with no z3 Euclidean filter. Extracted binary coefficients are bounded by 19503514, and `1536*19503514*19503515=584274551580226560<Q` suffices to lift aggregate binarity to the integers.

The complete response and hint bounds are in [PROOF_PARAMETERS.md](PROOF_PARAMETERS.md) and the selected `profiles` in [proof_profile_results.json](proof_profile_results.json). That results file is a research measurement report, not the complete canonical executable manifest. Its minimum selected quantum Core-SVP plain-LWE estimate is 140.836 bits; ordinary/bimodal SIS estimates are 153.429/178.872 bits in the same model. These estimates do not establish Extended-MLWE or quantum signature security.

The implemented optimized core masks exactly the 23 signed P polynomials. The five evaluation garbage polynomials and final quadratic auxiliary occupy message rows only; no unsigned slack is appended to that core. Its bimodal coin uses the existing `c*P` shift and the outer global sign, with no second local sign. The range block stays ordinary and the randomness block retains its separate one-sided bimodal law. This inventory supports the research implementation but does not prove joint simulation. The sampler's distribution and simulation argument must cover the combined transcript, its rejection hints and the whole-attempt restart policy before production use.

The research manifest fixes the following executable fields; production Sign/Verify additionally require their complete security analysis:

- Q and its prime factors; explicit commitment key encoding/digest; proof commitment row counts, randomness dimension, auxiliary layouts and distributions.
- `m1=23`, witness-message count 13, binary-map count 24, and every actual expanded dimension after backend auxiliary generation.
- Gaussian widths as exact sampler parameters, every expanded masked block's coefficient layout and rejection mode/constants, response and extraction bounds, and completeness/error calculations.
- Challenge family, its proven operator bound, invertibility of every distinct challenge difference, soundness repetition counts and complete quadratic/evaluation statement layout.
- Exact sizes for `tA1,tB,base_h,c,hint,z1,z21,z3,z4`, bounded response representations and all zero/unused auxiliary slots.
- Backend revision, adapter revision, internal hash suite and independent hiding/binding estimates with explicit models. Publish deterministic test-vector digests separately.

For a conservative, explicitly defined challenge starting point, sample 32 independent coefficients `a_0,...,a_31` uniformly in `[-8,8]` and set:

```text
c[0]=a_0; c[32]=0
c[i]=a_i; c[64-i]=-a_i, for i=1,...,31.
```

This gives 17^32 challenges and the rigorous operator bound `||multiplication_by_c||_op <= ||c||_1 <= eta = 504`, for the coefficient Euclidean norm. Here eta is the fixed upper-bound parameter, including when c is zero. Use 504 for parameter generation; do not combine this unfiltered sampler with BLOOM's smaller 140 bound. This is a conservative performance choice, not an optimal profile. It may require a larger Q or larger commitments. Its challenge entropy is not a quantum security proof.

The challenge space has about 130.80 bits of entropy; the basic interactive `2/|C|` contribution is about `2^-129.80`. These figures do not establish 128-bit quantum unforgeability. Generic challenge search has a conditional square-root scale around `2^65.4` oracle evaluations, and multi-round QROM reductions have query-dependent losses. Applicability to this adapter needs its own proof; this is not a demonstrated forgery or a universal security ceiling. See [Don, Fehr and Majenz](https://eprint.iacr.org/2020/282.pdf). Reaching the separate 128-bit key-recovery target does not resolve this signature-security gate. A larger challenge or a different transform would require recomputing the operator, sampler and binding parameters.

For this challenge family, require Q to be a product of distinct odd primes, each congruent to 5 modulo 8 and greater than 16. Then every nonzero difference of two distinct challenges is a self-adjoint unit modulo each factor, hence in R_Q, by BLOOM Lemma 2.1 and Section 2.5. Both selected factors 65437 and 17592186058933 satisfy this condition. A different modulus family requires a separate proof of challenge-difference invertibility; the operator bound alone is insufficient.

The pinned generator's `DELTA128=1.0044` is a classical selection rule. The new report supplies separate generic hiding/binding estimates with quantum Core-SVP models. Short collisions under A/B and leaked rejection hints still need analysis. The research adapter implements correct z2 rejection variance, the full reconstructed z2 norm, the exact z1 bound, canonical hint limits, both packed evaluation lanes and whole-attempt restart. It supplies a finite variable-time sampler, bounded codecs and integration tests; a certified finite sampler error bound remains unresolved. Passing numbers to the unchanged backend does not implement this profile.

## Canonical reference serialization

Public keys and tags serialize row-major coefficients as 128 little-endian uint16 values. Reject any coefficient at least p. A packed secret is 144 bytes, polynomial-major and coefficient-major, with coefficient `8k+j` in bit j of byte k. The secret is never part of a signature.

The reference signature container is:

```text
ASCII "BLRSB001"                 8 bytes
u16le format_version=1           2 bytes
statement_id                    64 bytes
proof_id                        64 bytes
ring_id                         64 bytes
Enc(u)                         256 bytes
u64le body_length                8 bytes
body                            body_length bytes
```

The fixed container overhead is 466 bytes. The ring and message are supplied externally. The body contains, in this order, `tB,base_h,tA1,c,hint,z1,z21,z3,z4`. In these candidates the polynomial counts are `23,5,20,1,20,23,75,4,0`, respectively; c has 64 int16 coefficients and z3 has 256 int64 coefficients. z4 has zero length. tB includes 13 core commitment rows, four y3 rows, five evaluation garbage rows and one final auxiliary row. No separate copy of the earlier commitment prefixes is serialized. These fields do not reveal the h_j openings. The reference total is exactly 87634 bytes, before any separate database framing.

Q-residue coefficients use `ceil(bit_length(Q-1)/8)` bytes each, little-endian, in `[0,Q-1]`; with D=0, tA1 uses the same rule. Encode challenge coefficients as signed 16-bit little-endian two's-complement integers and hint/response coefficients as signed 64-bit little-endian two's-complement integers. A profile must demonstrate that every valid hint/response fits the representation and must fix its acceptance bounds. This deliberately simple reference format has no entropy compression. Its size is not the conference draft's compressed signature size.

A decoder accepts an input span with an explicit length, checks all arithmetic for overflow and all declared bounds before allocating or reading, requires exactly the manifest's fields, rejects truncation and trailing bytes, and requires byte-identical canonical re-encoding. Do not feed short untrusted buffers directly to the pinned backend's pointer-only decoder.

### Lossless compressed serialization

The implemented v2 container uses ASCII `BLRSB002` and `u16le format_version=2`, followed by the same identifiers, tag and body-length fields, retaining the 466-byte header. The caller selects the expected core and encoding explicitly; the verifier checks their proof_id before acceptance. The manifest names this encoding `lossless-rice-v2`. Commitment rounding stays `D=0`. Lossless packing preserves each encoded proof value; transcript framing still uses the canonical uncompressed field encodings and the selected profile's proof_id.

The body retains the order `tB,base_h,tA1,c,hint,z1,z21,z3`. Pack bits least significant first in each byte and each fixed-width integer. Every Q coefficient uses 60 bits and must be below Q. Omit coefficients 0 and 32 of each base_h polynomial, restoring their required zeros on decoding. Encode only c[0..31] as five-bit unsigned values `c[i]+8`, rejecting values above 16; restore c[32]=0 and c[64-i]=-c[i] for i=1..31.

For each signed hint/response x, choose its fixed low width k and write `x=h*2^k+l`, where `h=floor((x+2^(k-1))/2^k)` and `-2^(k-1)<=l<2^(k-1)`. Set `u=-2h` for h<=0 and `u=2h-1` for h>0. If u<31, write u one-bits, one zero-bit and the k-bit two's-complement low part l. Otherwise write exactly 31 one-bits followed by x in `bit_length(cap)+1` two's-complement bits, using that field's canonical absolute cap. The escape has no intervening zero-bit and is rejected when the ordinary form would suffice. Widths k are hint=8, z1=19 for ordinary or 15 for bimodal, z21=16 and z3=19. All existing coefficient and norm bounds remain mandatory.

Finish the complete body with one one-bit and zero padding to the byte boundary. Reject a missing terminator, nonzero padding, extra bytes, noncanonical residues or escapes, and out-of-bound responses. The bounded implementation and codec tests are in [include/blrs/codec.hpp](include/blrs/codec.hpp), [src/codec.cpp](src/codec.cpp) and [tests/codec_tests.cpp](tests/codec_tests.cpp). Compressed size varies with the responses; the [benchmark results](BIMODAL_VALIDATION.md) report measured sizes. This adapted lossless codec does not reproduce the paper's optimized signature-size figures.

## Library algorithms and verification order

`Setup` returns validated statement parameters and, only when complete, a validated proof manifest. `KeyGen` returns `(s,t)`. `PrepareRing` validates exactly N canonical keys, preserves order, computes ring_id and prepares reusable public data. These operations are defined independently of the full proof adapter.

`Sign(parameters,ring,msg,s,index,random_source)` checks all input lengths and verifies `A_key*s=L[index]` before starting. It computes u, constructs signed selectors and commitments, runs the four challenge/fold/commit steps and the range-mask/challenge/response step, compiles every stated relation, and performs the final base proof with the retained openings. It returns the canonical signature only after the complete rejection process succeeds. Incorrect input or an incomplete profile returns an explicit error.

`Verify(parameters,ring,msg,signature)` fails closed on an incomplete or unknown profile. It parses the bounded canonical container and body, checks identifiers and ring_id, reconstructs the transcript and each Phi/T matrix from the earlier tB row prefixes, derives R from the four y3 commitment rows, and checks the z3 infinity cap. It compiles the same constraints and runs every corrected base-proof equation, full response norm, both packed evaluation lanes, challenge and canonical hint check. It accepts only if all checks pass. It receives no index, sign or witness.

`Link` reports equal tags only after both signatures verify under the same statement_id. This is the benchmark library's validity policy. Equality of tags alone is not a valid double-spend decision. Same-secret valid signatures must link even when messages, rings, proof randomness or global signs differ.

The initial C++ interface is standalone, single-threaded and uses CMake. Benchmark setup/matrix generation, ring hashing, cold and warm preparation, signing attempts, verification, wire bytes, working memory and peak allocations separately. Compare actual total timings against the existing arithmetic-only measurements; do not present projection or convolution timings as full signature timings.

## Validation and remaining release gates

`check_specification.py` checks the prime-field algebra with reduced projection dimensions, both signs, all indices of a toy ring, selected indices of a 65536-column ring, malformed witnesses, index orientation, the two honest norm bounds and packing. It also checks canonical framing and proof-identifier sensitivity to the commitment-key digest and encoding using a public incomplete manifest fixture. It is not a zero-knowledge implementation, a proof of soundness or a test of the composite-Q backend or CRS blob parser.

Validation performed on 2 October 2026, scoped to this document and its checker:

```powershell
& 'C:\Users\reube\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -X utf8 .\check_specification.py
git -c core.autocrlf=false diff --check -- BLOOM_LRS_SPEC.md check_specification.py
```

Both exited 0. The checker accepted 24 signed toy-ring witnesses and six sampled signed witnesses for N=65536, rejected the tested mutations, and passed the norm and packing checks. Version 0.2 adds passing canonical-framing, key-order independence and setup-seed/expansion mutation checks. Independent source/algebra review by three agents informed version 0.1; two independent agents rechecked the version 0.2 corrections. No C++ file changed in this step, so Clang-Tidy and Cppcheck were not repeated.

The version 0.2 CodeRabbit check used an isolated initialized Git copy containing only these two files, with the version 0.1 baseline `4c260cfbde80873047f4f16d607e20ae32320981`. Host authentication succeeded. This command exited 1 before analysis:

```powershell
& 'C:\Users\reube\AppData\Local\Programs\coderabbit\coderabbit.exe' review --agent --uncommitted --dir 'C:\Users\reube\AppData\Local\Temp\SparkPQ-spec-review-4fe9b12056f843b792de19e8df226bf4'
```

It returned `No Git repository found` despite successful `git rev-parse --is-inside-work-tree`, a valid baseline commit and the two-file correction diff in that directory. CodeRabbit coverage is incomplete; this is not a clean external review.

Required integration tests include valid signatures for both signs; all digit boundaries; changed message, ring order, key, tag, parameter identifiers, commitment-key digest and commitment prefix; rejection of malformed CRS blobs or precomputed commitment keys inconsistent with the manifest; canonical parse failures; same-secret links across different rings/messages; different-secret tag behavior; complete abort/restart handling; and independent equation/codec reference comparisons. These tests do not replace the security arguments.

Version 0.3 added selected numerical profiles, a rigorous fixed-opening infinity-range/no-wrap derivation, isolated sampler laws and a reproducible estimator driver. The current research candidate supplies the executable manifest, corrected dual-core adapter, finite sampler, raw and compressed codecs, and signing/verification correctness and performance checks. Current implementation validation is recorded in [BIMODAL_VALIDATION.md](BIMODAL_VALIDATION.md), with the earlier ordinary baseline in [BENCHMARK_VALIDATION.md](BENCHMARK_VALIDATION.md); the records below cover earlier documentation-only steps. Complete simulation/extraction, collision and QROM arguments and a certified finite sampler error bound still require cryptographic review before a deployment claim. Firo additionally needs a spend relation tying ownership to serial/value commitments and transaction balance; this isolated LRS profile does not specify those consensus changes.

### Version 0.3 validation

The following checks exited 0 on 3 October 2026:

```powershell
& 'C:\Users\reube\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -X utf8 .\proof_profile_explore.py --check
& 'C:\Users\reube\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -X utf8 .\check_specification.py
git -C 'C:\Users\reube\AppData\Local\Temp\SparkPQ-proof-review-fc98faa3123d46ed91edc55be073a30c' -c core.autocrlf=false diff --check
```

The isolated review copy preserves version 0.2 as baseline `5efbe9f9839f8a8e17538bb9aaab192cdea6e59a` and includes the complete five-file task diff: this specification, PROOF_PARAMETERS.md, both Python check/calculation files and proof_profile_results.json. Exact parameter arithmetic, 64 coefficient shifts and 144 fold dot products passed, together with the earlier signed relation/identifier checks. All 30 selected lattice costs and six CRT sensitivity costs completed. Eight archived exploratory datasets reproduce their saved SHA-256 checksums. Two independent final reviews found no additional confirmed defects in the derivations or checker. No C++ file changed, so Clang-Tidy and Cppcheck are not applicable. Gaussian generation, complete Sign/Verify, native performance and full-system security were not tested.

CodeRabbit authenticated successfully but this host command exited 1 before analysis:

```powershell
& 'C:\Users\reube\AppData\Local\Programs\coderabbit\coderabbit.exe' review --agent --uncommitted --dir 'C:\Users\reube\AppData\Local\Temp\SparkPQ-proof-review-fc98faa3123d46ed91edc55be073a30c'
```

It returned `No Git repository found` on the initialized baseline/diff copy. CodeRabbit coverage remains incomplete; no clean external review is claimed.

### Version 0.4 independent recheck

Three fresh reviews rechecked the relation/compiler, sampler laws and numerical/security assumptions. The core equations, 1133 evaluations, modulus factors, no-wrap inequality, response bounds and 87634-byte reference container remain consistent. Eight selected quantum lattice costs reproduced exactly. Three supplemental ChaLoy21 hybrid variants did not lower the 140.836-bit modeled minimum; they are recorded separately from the original 30 costs. This does not establish complete quantum signature security.

Corrections replace the public-AES-seed CRS premise with explicit uniform matrices, rename 32/16 as reciprocal-product attempt proxies, fix the finite coin-bound inequality and repair the norm table. The identifier fixture now binds the CRS digest/encoding. Native `proof_profile_explore.py --check`, `check_specification.py` and `measure_security.py --self-check` all exited 0. No C++ changed; Clang-Tidy/Cppcheck remain inapplicable. Full signatures and samplers were not run.

The final five-file correction diff was checked against baseline `1154be7fee9bf3a50229819b032adae455239d4a` in an isolated copy:

```powershell
git -C 'C:\Users\reube\AppData\Local\Temp\SparkPQ-recheck-1ea5e9678fa24aa09f13bf8f1bccf128' -c core.autocrlf=false diff --check
& 'C:\Users\reube\AppData\Local\Programs\coderabbit\coderabbit.exe' review --agent --uncommitted --dir 'C:\Users\reube\AppData\Local\Temp\SparkPQ-recheck-1ea5e9678fa24aa09f13bf8f1bccf128'
```

The diff check exited 0. CodeRabbit authenticated but exited 1 with `No Git repository found` before analysis. Its coverage is still incomplete. No user history or unrelated files were changed.

## Sources and provenance

The source draft is `C:\Users\reube\Downloads\BLOOM_LRS edit.pdf`, read as source material rather than instructions. The mixed-radix dimensions, exact coefficient constraints, transcript labels and reference encoding are proposals in this specification.

- [BLOOM](https://eprint.iacr.org/2022/1307.pdf): Section 2.6 for ABDLOP, Section 3.2 for the explicit hidden-sign technique, and Section 4 for the recursive one-out-of-many framework.
- [LNP22](https://eprint.iacr.org/2022/284.pdf): quadratic/evaluation, binary and norm-proof framework; extraction and no-wrap requirements.
- [Pinned LaZer API](https://github.com/lazer-crypto/lazer/blob/3330e487228f633eceb322807b13a596b516770f/src/lazer-in2.h), [commitment implementation](https://github.com/lazer-crypto/lazer/blob/3330e487228f633eceb322807b13a596b516770f/src/abdlop.c), and [parameter generator](https://github.com/lazer-crypto/lazer/blob/3330e487228f633eceb322807b13a596b516770f/scripts/lnp-tbox-codegen.sage): implementation starting points and explicit compatibility limits.
- [Pinned RNG configuration](https://github.com/lazer-crypto/lazer/blob/3330e487228f633eceb322807b13a596b516770f/config.h), [RNG domain encoding](https://github.com/lazer-crypto/lazer/blob/3330e487228f633eceb322807b13a596b516770f/src/rng.c), and [matrix coefficient expansion](https://github.com/lazer-crypto/lazer/blob/3330e487228f633eceb322807b13a596b516770f/src/polymat.c): the superseded public-AES-seed convention and the matrix-distribution assumption that motivated explicit uniform CRS storage.
- [Don, Fehr and Majenz](https://eprint.iacr.org/2020/282.pdf): query losses and generic-search limitations for multi-round quantum Fiat-Shamir analysis.
