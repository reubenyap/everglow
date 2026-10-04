#!/usr/bin/env python3
"""Reproduce BLOOM-LRS proof sizing and classical/quantum Core-SVP estimates.

Run under Sage Python with the pinned lattice-estimator checkout. This is
parameter arithmetic and heuristic cryptanalytic estimation, not a prover,
not sampler validation, and not a full-signature security assessment.
The range control uses a pointwise matrix norm bound and a generic quadratic
wrapper without internal range-proof sign variables. That adapter has not
yet been implemented or proved.
"""

import argparse
import datetime
from fractions import Fraction
import json
import math
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

ESTIMATOR_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"
LAZER_COMMIT = "3330e487228f633eceb322807b13a596b516770f"


def prime64(n):
    if n >= 2**64:
        raise ValueError("prime64 requires an integer below 2^64")
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    exponent, odd = 0, n-1
    while odd % 2 == 0:
        exponent, odd = exponent+1, odd//2
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % n == 0:
            continue
        value = pow(base % n, odd, n)
        if value in (1, n-1):
            continue
        for _ in range(exponent-1):
            value = value*value % n
            if value == n-1:
                break
        else:
            return False
    return True


def self_check():
    p, q2, Q = 65437, 17592186058933, 1151179879138398721
    assert Q == p*q2 and prime64(p) and prime64(q2)
    assert prime64(73) and not prime64(341550071728321)
    assert p % 8 == q2 % 8 == 5 and Q % 512 == 1
    assert Q.bit_length() == 60 and (Q-1).bit_length() == 60
    sigma_b, sigma_rho, sigma_range = (Fraction(31, 20)*2**k for k in (14, 15, 18))
    assert sigma_b == Fraction(126976, 5)
    assert sigma_rho == Fraction(253952, 5)
    assert sigma_range == Fraction(2031616, 5)
    T1_squared = 504**2 * 1157
    assert Fraction(T1_squared, 2*sigma_b**2) < Fraction(1, 2)  # 1/2 < ln(2)
    assert 20*504*35/sigma_range + Fraction(T1_squared, 2*sigma_range**2) < Fraction(4, 3)  # 4/3 < ln(4)
    assert Fraction(504**2 * 95 * 64, 2*sigma_rho**2) < Fraction(1, 2)
    T3 = 16*1467
    assert 20*T3/sigma_range + Fraction(T3**2, 2*sigma_range**2) < Fraction(4, 3)
    L3 = math.ceil(24*sigma_range)
    assert L3 == 9751757
    assert 24*64*(2*L3)*(2*L3+1) == 584274551580226560 < Q
    # Certify algebraic floors and ceilings without floating point. Bound_half
    # equals sigma_rho*sqrt(12160)+508*sqrt(1280).
    radicand = 12160*1280
    base = sigma_rho**2*12160 + 508**2*1280
    coefficient = 2*sigma_rho*508
    Bhalf_squared_floor = 31572639091752
    assert Bhalf_squared_floor > base
    assert ((Bhalf_squared_floor-base)/coefficient)**2 <= radicand
    assert ((Bhalf_squared_floor+1-base)/coefficient)**2 > radicand
    for sigma1, beta in ((sigma_b, 23326878867), (sigma_range, 91733338857)):
        A = 16*504**2*(8*sigma1**2*23*64+4*base)
        B = 16*504**2*4*coefficient
        assert (beta-1)**2 > A
        assert (((beta-1)**2-A)/B)**2 < radicand
        assert ((beta**2-A)/B)**2 >= radicand
        assert beta < q2
    assert math.ceil(Fraction(23326878867, p)) == 356479
    assert math.ceil(Fraction(91733338857, p)) == 1401858
    assert math.floor(sigma_b**2*2*23*64) == 1898633242869
    assert math.floor(sigma_range**2*2*23*64) == 486050110174658
    hint_cap = (Q-1)//512//2
    assert hint_cap == 1124199100721092 < 2**63
    assert math.isqrt(Bhalf_squared_floor) == 5618953 < 2**63
    assert 20+52+23 == 95 and 17+5+1 == 23 and 95-20 == 75
    # tB, base_h, tA1, challenge, hint, z1, z21, z3; z4 is absent.
    body = (23+5+20)*64*8 + 64*2 + (20+23+75)*64*8 + 256*8
    assert 466+body == 87634
    assert (20*23 + 20*75 + 23*75)*64*8 == 1886720
    assert 8+2+8+2+3*(4+4) == 44
    assert sum(144*n*2 for n in (8192,1024,128,16)) == 2695680
    assert 18*128*65536 + 18*144*(8192+1024+128) == 175214592
    assert 504//2 + 512//2 == 508 and 2**(-1)*8*64 < 512
    print("Exact rational norm/rejection bounds, deterministic prime checks, dimensions, and 87634-byte reference container passed.")


def save(path, data):
    path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n", encoding="utf-8", newline="\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("estimator", type=Path, nargs="?")
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--phase", choices=("screen", "full", "quantum"), default="quantum")
    parser.add_argument("--q2-min-bits", type=int, default=44)
    parser.add_argument("--commit-rows", type=int, nargs="+", default=[20])
    parser.add_argument("--residual-rows", type=int, nargs="+", default=[52])
    parser.add_argument("--message-mode", choices=("bimodal", "ordinary"), default="ordinary")
    args = parser.parse_args()
    if args.check:
        self_check()
        return
    if args.estimator is None or args.output is None:
        parser.error("estimator and fresh output paths are required unless --check is used")
    if not 1 <= args.q2_min_bits <= 47:
        parser.error("q2-min-bits must lie in [1,47] for the 64-bit research profile")
    if any(value <= 0 for value in args.commit_rows + args.residual_rows):
        parser.error("commitment and residual row counts must be positive")
    if args.output.exists():
        parser.error("output exists; choose a fresh output to preserve measurements")
    commit = subprocess.check_output(["git", "-C", str(args.estimator), "rev-parse", "HEAD"], text=True).strip()
    if commit != ESTIMATOR_COMMIT:
        parser.error("estimator revision differs from the pinned revision")
    sys.path.insert(0, str(args.estimator.resolve()))
    from estimator import LWE, ND, RC, SIS
    from estimator.reduction import ADPS16, ChaLoy21
    from sage.all import Integer, RealField, inverse_mod, is_prime, log, oo
    from sage.env import SAGE_VERSION
    field = RealField(256)
    mp = SimpleNamespace(mpf=field, sqrt=lambda v: field(v).sqrt(),
                         log=lambda v, b=None: field(v).log() if b is None else field(v).log()/field(b).log(),
                         power=lambda b, e: field(b)**field(e),
                         floor=lambda v: field(v).floor(), ceil=lambda v: field(v).ceil())
    p, d, eta, m1, l, nbin, gamma = 65437, 64, 504, 23, 13, 24, 512
    candidate = 2**args.q2_min_bits
    q2 = candidate + (int(inverse_mod(p, gamma)) - candidate) % gamma
    while not is_prime(Integer(q2)):
        q2 += gamma
    q = p * q2
    lam = 2 * math.ceil(128 / (2 * math.log2(p)))
    input_message = l + 256//d
    lext = lam//2 + 1
    masked_message_rows = input_message + lext
    assert p % 8 == q2 % 8 == 5 and q2 != p and q % gamma == 1
    assert lam == 10 and input_message == 17 and lext == 6 and masked_message_rows == 23
    sigma1 = mp.mpf(31) / 20 * 2**(14 if args.message_mode == "bimodal" else 18)
    sigma2 = mp.mpf(31) / 20 * 2**15
    sigma3 = mp.mpf(31) / 20 * 2**18
    T1 = eta * mp.sqrt(1157)
    T3 = mp.mpf(16 * 1467)
    M1 = 2 if args.message_mode == "bimodal" else 4
    M2, M3 = 2, 4
    L3 = int(mp.ceil(24*sigma3))
    integer_binary_no_wrap = nbin*d*(2*L3)*(2*L3+1)
    raw = {
        "status": "numerical_candidate_not_soundness_or_sampler_validated",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "estimator_commit": commit, "lazer_commit": LAZER_COMMIT,
        "sage_version": SAGE_VERSION,
        "inputs": {"p": p, "d": d, "q2": q2, "Q": q, "Q_bits": q.bit_length(),
                   "m1": m1, "l": l, "nbin": nbin, "Z": 0, "nex": nbin,
                   "alpha_squared": 1157, "quad_eval_input_message_rows": input_message,
                   "lambda": lam, "quad_eval_lext": lext, "masked_message_rows": masked_message_rows,
                   "D": 0, "gamma": gamma,
                   "eta": eta, "nu": 1, "challenge_cardinality": str(17**32),
                   "message_mode": args.message_mode},
        "samplers": {"sigma1_rational": {"numerator": 31*2**(14 if args.message_mode == "bimodal" else 18), "denominator": 20},
                     "sigma2_rational": {"numerator": 31*2**15, "denominator": 20},
                     "sigma3_rational": {"numerator": 31*2**18, "denominator": 20},
                     "sigma1": str(sigma1), "sigma2": str(sigma2),
                     "sigma3": str(sigma3),
                     "M1": M1, "M2": M2, "M3": M3,
                     "T1": str(T1), "T3_pointwise": str(T3),
                     "message_log_rejection_ratio_bound": str(T1*T1/(2*sigma1*sigma1) + (20*T1/sigma1 if args.message_mode == "ordinary" else 0)),
                     "range3_log_rejection_ratio_bound": str(20*T3/sigma3+T3*T3/(2*sigma3*sigma3)),
                     "reciprocal_product_attempt_proxy": M1*M2*M3},
        "range_extraction_gates": {
                     "new_response_infinity_cap_L3": L3,
                     "new_extracted_binary_infinity_cap": 2*L3,
                     "new_integer_binary_no_wrap_required_Q_gt": integer_binary_no_wrap,
                     "new_integer_binary_no_wrap_pass": bool(q > integer_binary_no_wrap)},
        "assumptions": [
            "Classical plain-LWE/SIS flattening is heuristic; no module-specific analysis.",
            "Custom quad-eval wrapper uses 17 input message rows and 6 auxiliary rows, 23 total masked rows.",
            "Finite MLWE samples equal (k_sis+23)*64; residual dimension equals k_mlwe*64.",
            "Signed message uses global bimodal rejection; ordinary control uses a 20-sigma clipped tail.",
            "The standalone range control uses ordinary rejection with no internal beta signs.",
            "Range3 uses deterministic trinary-matrix norm bound 16*1467.",
            "Native sampler law and the modified tbox reduction are unvalidated proof obligations.",
            "No complete-profile quantum security assessment.",
            "The selected CRS uses explicit independent uniform matrices; public AES seed expansion is superseded.",
        ], "arithmetic": [], "estimates": [], "crt_sis_sensitivity": []}
    assert raw["samplers"]["message_log_rejection_ratio_bound"]
    assert mp.mpf(raw["samplers"]["message_log_rejection_ratio_bound"]) < mp.log(M1)
    assert mp.mpf(raw["samplers"]["range3_log_rejection_ratio_bound"]) < mp.log(M3)
    save(args.output, raw)
    for r in args.commit_rows:
        for k in args.residual_rows:
            m2 = k + r + masked_message_rows
            T2 = eta*mp.sqrt(m2*d)
            bound1 = 2*sigma1*mp.sqrt(2*m1*d)
            bound_half = sigma2*mp.sqrt(2*m2*d) + eta*mp.mpf("0.5")*mp.sqrt(r*d) + gamma*mp.sqrt(r*d)/2
            bound2 = 2*bound_half
            beta = 4*eta*mp.sqrt(bound1**2+bound2**2)
            delta = mp.power(2, mp.log(beta, 2)**2/(4*r*d*mp.log(q, 2)))
            arow = {"k_sis": r, "k_mlwe": k, "m2": m2,
                    "masked_rows": r+masked_message_rows, "sigma2_gamma": str(sigma2/T2),
                    "rho_log_rejection_ratio_bound": str(T2*T2/(2*sigma2*sigma2)),
                    "M2_is_sufficient": bool(T2*T2/(2*sigma2*sigma2) < mp.log(M2)),
                    "B1": str(bound1), "B2": str(bound2), "B_half": str(bound_half),
                    "verifier_Bz1_squared_floor": int(mp.floor(sigma1*sigma1*2*m1*d)),
                    "verifier_z1_per_coefficient_abs_upper": math.isqrt(int(mp.floor(sigma1*sigma1*2*m1*d))),
                    "verifier_hint_per_coefficient_abs_upper": (q-1)//gamma//2,
                    "B_half_squared_floor": int(mp.floor(bound_half**2)),
                    "MSIS_beta": str(beta), "MSIS_beta_ceil": int(mp.ceil(beta)),
                    "legacy_delta_msis": str(delta), "legacy_delta_lt_1_0044": bool(delta < mp.mpf("1.0044")),
                    "MSIS_beta_lt_Q": bool(beta < q)}
            raw["arithmetic"].append(arow)
            save(args.output, raw)
            models = [("ADPS16_classical", ADPS16(mode="classical"))]
            if args.phase == "full":
                models += [("MATZOV_classical", RC.MATZOV)]
            elif args.phase == "quantum":
                models += [("ChaLoy21_quantum_core", ChaLoy21()),
                           ("ADPS16_quantum_core", ADPS16(mode="quantum"))]
            sisparams = SIS.Parameters(n=r*d, m=(m1+m2)*d, q=q, length_bound=int(mp.ceil(beta)), norm=2)
            lweparams = LWE.Parameters(n=k*d, m=(r+masked_message_rows)*d, q=q, Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1))
            tasks = [("SIS_lattice", SIS.lattice, sisparams, {}),
                     ("LWE_primal_usvp", LWE.primal_usvp, lweparams, {"red_shape_model": "gsa"})]
            if args.phase in ("full", "quantum"):
                tasks += [("LWE_primal_bdd", LWE.primal_bdd, lweparams, {"red_shape_model": "gsa"}),
                          ("LWE_primal_hybrid", LWE.primal_hybrid, lweparams,
                           {"red_shape_model": "gsa", "mitm": False, "babai": False}),
                          ("LWE_dual", LWE.dual, lweparams, {})]
            for modelname, model in models:
                for name, estimate, params, options in tasks:
                    row = {"k_sis": r, "k_mlwe": k, "model": modelname,
                           "algorithm": name, "input_repr": repr(params), "options": options,
                           "status": "running"}
                    raw["estimates"].append(row)
                    save(args.output, raw)
                    print(f"START r={r} k={k} {modelname} {name}", flush=True)
                    started = time.perf_counter()
                    try:
                        cost = estimate(params, red_cost_model=model, **options)
                        row["raw_repr"] = repr(cost)
                        row["components"] = {str(key): str(value) for key, value in cost.items()}
                        value = cost.get("rop", oo)
                        row["log2_rop"] = float(log(value, 2)) if value != oo and value > 0 else None
                        row["status"] = "ok" if row["log2_rop"] is not None else "nonfinite"
                    except Exception as error:
                        row.update(status="error", error_type=type(error).__name__, error=str(error))
                    row["elapsed_seconds"] = time.perf_counter()-started
                    save(args.output, raw)
                    print(f"DONE r={r} k={k} {name}: {row['status']} {row.get('log2_rop')}", flush=True)
            for modelname, model in models:
                lifted = SIS.Parameters(n=r*d, m=(m1+m2)*d, q=q2,
                                        length_bound=int(mp.ceil(beta/p)), norm=2)
                row = {"k_sis": r, "k_mlwe": k, "model": modelname,
                       "algorithm": "SIS_lattice_large_CRT_factor_lift",
                       "input_repr": repr(lifted), "lift_multiplier": p,
                       "bound_ceil_beta_over_p": int(mp.ceil(beta/p)),
                       "small_CRT_factor_lift_excluded_by_q2_gt_beta": bool(q2 > beta),
                       "status": "running"}
                raw["crt_sis_sensitivity"].append(row)
                save(args.output, raw)
                print(f"START CRT r={r} k={k} {modelname}", flush=True)
                started = time.perf_counter()
                try:
                    cost = SIS.lattice(lifted, red_cost_model=model)
                    row["raw_repr"] = repr(cost)
                    row["components"] = {str(key): str(value) for key, value in cost.items()}
                    value = cost.get("rop", oo)
                    row["log2_rop"] = float(log(value, 2)) if value != oo and value > 0 else None
                    row["status"] = "ok" if row["log2_rop"] is not None else "nonfinite_model_limit"
                except Exception as error:
                    row.update(status="error", error_type=type(error).__name__, error=str(error))
                row["elapsed_seconds"] = time.perf_counter()-started
                save(args.output, raw)
                print(f"DONE CRT {modelname}: {row['status']} {row.get('log2_rop')}", flush=True)
    raw["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save(args.output, raw)


if __name__ == "__main__":
    main()
