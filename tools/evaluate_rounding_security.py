#!/usr/bin/env python3
"""Fixed-Q rounding arithmetic and pinned heuristic SIS estimates, not a security proof.

Use ordinary Python with --check, or Sage Python with ESTIMATOR OUTPUT.
All emitted sizes are arithmetic counts/lower bounds, not new signature measurements.
"""

import argparse
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from proof_profile_explore import ESTIMATOR_COMMIT, prime64

Q, P, Q2 = 1151179879138398721, 65437, 17592186058933
D_RING, ROWS, M1, M2, ETA = 64, 20, 23, 95, 504
SIGMA1, SIGMA2 = Fraction(126976, 5), Fraction(253952, 5)
FACTORS = ((2, 9), (3, 2), (5, 1), (13, 1), (1103, 1), (3484511087, 1))


def gammas():
    values = [1]
    for prime, exponent in FACTORS:
        values = [value * prime**power for value in values for power in range(exponent + 1)]
    return sorted(value for value in values if value % 2 == 0)


def parameters(rounding, gamma):
    if not 0 <= rounding <= 30 or gamma <= 0 or gamma % 2 or (Q - 1) % gamma:
        raise ValueError("requires 0 <= D <= 30 and positive even gamma | Q-1")
    # B_half = sigma2 sqrt(12160) + (eta*2^D+gamma)/2 sqrt(1280).
    coefficient = Fraction(ETA * 2**rounding + gamma, 2)
    base = SIGMA2**2 * (2 * M2 * D_RING) + coefficient**2 * (ROWS * D_RING)
    cross = 2 * SIGMA2 * coefficient
    radicand = (2 * M2 * D_RING) * (ROWS * D_RING)
    with localcontext() as ctx:
        ctx.prec = 100
        dec = lambda v: Decimal(v.numerator) / Decimal(v.denominator)
        half_square = dec(base) + dec(cross) * Decimal(radicand).sqrt()
        half_floor = int(half_square)
        beta_square = 16 * ETA**2 * (8 * dec(SIGMA1)**2 * M1 * D_RING + 4 * half_square)
        beta_ceil = int(beta_square.sqrt()) + 1
    # Certify both algebraic integer bounds using only rational arithmetic.
    assert half_floor >= base
    assert ((half_floor - base) / cross)**2 <= radicand
    assert ((half_floor + 1 - base) / cross)**2 > radicand
    beta_base = 16 * ETA**2 * (8 * SIGMA1**2 * M1 * D_RING + 4 * base)
    beta_cross = 16 * ETA**2 * 4 * cross
    assert (beta_ceil - 1)**2 > beta_base
    assert (((beta_ceil - 1)**2 - beta_base) / beta_cross)**2 < radicand
    assert ((beta_ceil**2 - beta_base) / beta_cross)**2 >= radicand
    # Native power2round retains the positive half as low part at an exact tie.
    rounded_max = (Q - 2 + 2**(rounding - 1)) // 2**rounding if rounding else Q - 1
    bits = rounded_max.bit_length()
    assert bits == 60 - rounding
    return {
        "D": rounding, "gamma": gamma, "m": (Q - 1) // gamma,
        "generator_efficiency_rule": gamma > 2**(rounding + 8),
        "B_half_squared_floor": half_floor, "MSIS_beta_ceil": beta_ceil,
        "beta_lt_Q": beta_ceil < Q, "beta_lt_q2": beta_ceil < Q2,
        "rounded_tA_bits_per_coefficient": bits,
        "rounded_tA_maximum": rounded_max,
        "tA_bytes": ROWS * D_RING * bits // 8,
        "tA_gross_savings_bytes": ROWS * D_RING * rounding // 8,
        "hint_count": ROWS * D_RING,
        "hint_minimum_bytes_with_current_unary_family": ROWS * D_RING // 8,
        "hint_canonical_absolute_cap": ((Q - 1) // gamma) // 2,
    }


def self_check():
    factors = 1
    for prime, exponent in FACTORS:
        assert prime64(prime)
        factors *= prime**exponent
    assert factors == Q - 1 and len(gammas()) == 432
    baseline = parameters(0, 512)
    assert baseline["MSIS_beta_ceil"] == 23326878867
    assert baseline["B_half_squared_floor"] == 31572639091752
    assert baseline["tA_bytes"] == 9600
    assert parameters(8, 66180)["tA_gross_savings_bytes"] == 1280
    for rounding in range(1, 10):
        scale = 2**rounding
        for value in (scale // 2 - 1, scale // 2, scale // 2 + 1, Q - 1):
            low = value % scale
            if low > scale // 2:
                low -= scale
            assert (value - low) // scale == (value + scale // 2 - 1) // scale
    assert not parameters(1, 512)["generator_efficiency_rule"]
    assert parameters(0, 512)["generator_efficiency_rule"]
    for rounding, gamma in ((-1, 512), (31, 512), (0, 0), (0, 513), (0, 1024)):
        try:
            parameters(rounding, gamma)
        except ValueError:
            continue
        raise AssertionError("invalid profile accepted")


def save(path, report):
    path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("estimator", type=Path, nargs="?")
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    self_check()
    if args.check:
        print("Fixed-Q factors, exact baseline bounds, rounding widths and invalid-profile checks passed.")
        return
    if not args.estimator or not args.output:
        parser.error("ESTIMATOR and fresh OUTPUT are required")
    if args.output.exists():
        parser.error("output exists; use a fresh filename")
    commit = subprocess.check_output(["git", "-C", str(args.estimator), "rev-parse", "HEAD"], text=True).strip()
    if commit != ESTIMATOR_COMMIT:
        parser.error("estimator revision differs from pin")
    sys.path.insert(0, str(args.estimator.resolve()))
    from estimator import SIS
    from estimator.reduction import ADPS16, ChaLoy21
    from sage.all import log, oo
    from sage.env import SAGE_VERSION

    models = {"ADPS16_classical": ADPS16(mode="classical"),
              "ChaLoy21_quantum_core": ChaLoy21(),
              "ADPS16_quantum_core": ADPS16(mode="quantum")}
    report = {
        "status": "fixed_Q_numerical_screen_not_full_quantum_security",
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "estimator_commit": commit, "sage_version": SAGE_VERSION,
        "fixed": {"Q": Q, "p": P, "q2": Q2, "secret_width": 18, "d": D_RING,
                  "k_sis": ROWS, "m1": M1, "m2": M2, "eta": ETA,
                  "sigma1": str(SIGMA1), "sigma2": str(SIGMA2)},
        "Q_minus_one_factors": FACTORS, "even_divisor_count": len(gammas()),
        "assumptions": [
            "B2=2*sigma2*sqrt(2*m2*d)+(eta*2^D+gamma)*sqrt(k_sis*d), including conservative D=0 term.",
            "Native rejection on c*s2 occurs before subtracting c*tA2 and w0; isolated M2 condition is unchanged.",
            "SIS estimates flatten the module; they do not establish hint/Extended-MLWE or QROM security.",
            "Width-18 key-recovery problem and plain-LWE dimensions are held fixed, not re-estimated.",
            "Security thresholds constrain only the minimum of the two selected quantum Core-SVP SIS estimates.",
            "Theorem arithmetic domain: positive even gamma divides Q-1; D ranges 0..30 in the exhaustive arithmetic grid.",
            "The optional gamma > 2^(D+8) generator efficiency rule is not treated as a theorem requirement.",
            "Size fields count commitment bits and an unattainable-in-general all-zero hint lower bound.",
        ], "selected": [], "thresholds": [],
    }
    cache = {}

    def cost(beta, model_name, modulus=Q, multiplier=1):
        key = (beta, model_name, modulus, multiplier)
        if key in cache:
            return cache[key]
        length = (beta + multiplier - 1) // multiplier
        params = SIS.Parameters(n=ROWS * D_RING, m=(M1 + M2) * D_RING,
                                q=modulus, length_bound=length, norm=2)
        result = SIS.lattice(params, red_cost_model=models[model_name])
        operations = result.get("rop", oo)
        bits = float(log(operations, 2)) if operations != oo and operations > 0 else None
        row = {"model": model_name, "modulus": modulus, "length_bound": length,
               "log2_rop": bits, "raw": repr(result)}
        cache[key] = row
        return row

    def quantum_min(beta):
        values = [cost(beta, name)["log2_rop"] for name in models if "quantum" in name]
        return min(values) if all(value is not None for value in values) else None

    candidates = [parameters(0, 512)]
    for rounding in (8, 10, 11, 12, 13, 14, 15):
        candidates.append(parameters(rounding, next(g for g in gammas() if g > 2**(rounding + 8))))
    candidates.extend(parameters(rounding, 2) for rounding in (12, 13, 14))
    candidates.extend(parameters(rounding, gamma) for rounding, gamma in
                      ((0, 176480), (10, 458848), (11, 1588320), (12, 573560), (13, 2294240)))
    for row in candidates:
        beta = row["MSIS_beta_ceil"]
        row["SIS"] = [cost(beta, name) for name in models]
        row["CRT_large_factor_lift"] = [cost(beta, name, Q2, P) for name in models]
        row["quantum_core_minimum"] = quantum_min(beta)
        report["selected"].append(row)
        save(args.output, report)
        print(f"D={row['D']} gamma={row['gamma']} beta={beta} quantum={row['quantum_core_minimum']}", flush=True)
    assert abs(report["selected"][0]["quantum_core_minimum"] - 178.872) < 1e-9

    # Monotone binding-bound budget: a small binary search replaces thousands
    # of equivalent SIS optimizer calls across the complete divisor grid.
    for target in (128, 140, 153):
        low, high = parameters(0, 512)["MSIS_beta_ceil"], Q2
        assert quantum_min(low) >= target and quantum_min(high) < target
        while high - low > 1:
            middle = (low + high) // 2
            if quantum_min(middle) >= target:
                low = middle
            else:
                high = middle
        feasible = []
        for rounding in range(0, 31):
            for gamma in gammas():
                row = parameters(rounding, gamma)
                if row["MSIS_beta_ceil"] <= low:
                    feasible.append(row)
        max_d = max(row["D"] for row in feasible)
        frontier = []
        for rounding in range(max_d + 1):
            same_d = [row for row in feasible if row["D"] == rounding]
            smallest, largest = min(same_d, key=lambda row: row["gamma"]), max(same_d, key=lambda row: row["gamma"])
            frontier.append({"D": rounding, "smallest_gamma": smallest["gamma"],
                             "largest_gamma": largest["gamma"],
                             "largest_gamma_binding_ceiling": largest["MSIS_beta_ceil"],
                             "largest_gamma_B_half_squared_floor": largest["B_half_squared_floor"],
                             "tA_gross_savings_bytes": smallest["tA_gross_savings_bytes"],
                             "smallest_gamma_quantum_core_minimum": quantum_min(smallest["MSIS_beta_ceil"]),
                             "largest_gamma_quantum_core_minimum": quantum_min(largest["MSIS_beta_ceil"]),
                             "largest_gamma_generator_efficiency_rule": largest["generator_efficiency_rule"]})
        efficient = [row for row in feasible if row["generator_efficiency_rule"]]
        result = {"minimum_quantum_core_bits": target, "maximum_binding_ceiling": low,
                  "cost_at_ceiling": quantum_min(low), "cost_after_ceiling": quantum_min(high),
                  "feasible_profile_count": len(feasible), "maximum_D": max_d, "frontier": frontier,
                  "generator_efficiency_subset_maximum_D": max(row["D"] for row in efficient),
                  "generator_efficiency_subset_profile_count": len(efficient)}
        report["thresholds"].append(result)
        save(args.output, report)
        print(f"threshold={target} beta<={low} maxD={max_d} feasible={len(feasible)}", flush=True)
    report["SIS_optimizer_calls"] = len(cache)
    save(args.output, report)


if __name__ == "__main__":
    main()
