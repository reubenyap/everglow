#!/usr/bin/env python3
"""Model the stacked BLOOM-LRS key observations with official lattice-estimator.

Run with Sage's Python. No lattice attack, signing, or proof generation is run.
The module-structured equations are flattened heuristically to plain LWE;
quantum reduction costs do not quantum-optimize primal hybrid guessing.
The optional quantum-search phase uses the official quantum exhaustive-search
solver with dual hybrid. Its result can be distinguishing or partial recovery.
MATZOV dual is excluded: it defaults to n samples, not our 256.
No phase certifies 128-bit security of the construction.
"""

import argparse
import datetime
from functools import partial
import json
import math
from pathlib import Path
import subprocess
import sys
import time
import traceback


ESTIMATOR_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"


def inputs(width):
    if not 16 <= width <= 24:
        raise ValueError("scheme width must be between 16 and 24")
    return {"n": (width - 4) * 64, "q": 65437, "m": 256}


def self_check():
    assert inputs(16) == {"n": 768, "q": 65437, "m": 256}
    assert inputs(20) == {"n": 1024, "q": 65437, "m": 256}
    assert inputs(24) == {"n": 1280, "q": 65437, "m": 256}
    for width in (4, 15, 25):
        try:
            inputs(width)
        except ValueError:
            continue
        raise AssertionError("invalid width accepted")


def save(output, report):
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n",
                         encoding="utf-8")
    temporary.replace(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("estimator", nargs="?", type=Path)
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--phase", choices=("screen", "full", "sensitivity", "quantum-search"),
                        default="screen")
    parser.add_argument("--width", nargs="+", type=int)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    self_check()
    if args.self_check:
        print("Input self-check passed; scheme width and sample count are distinct.")
        return
    if args.estimator is None or args.output is None:
        parser.error("estimator checkout and output JSON paths are required")
    if args.phase != "screen" and not args.width:
        parser.error(f"{args.phase} phase requires explicit --width values")
    widths = sorted(set(args.width or range(16, 25)))
    for width in widths:
        try:
            inputs(width)
        except ValueError as error:
            parser.error(str(error))
    estimator = args.estimator.resolve()
    output = args.output.resolve()
    if output.exists():
        parser.error("output already exists; use a fresh path to preserve measurements")
    commit = subprocess.check_output(["git", "-C", str(estimator), "rev-parse", "HEAD"],
                                     text=True).strip()
    if commit != ESTIMATOR_COMMIT:
        parser.error(f"expected estimator {ESTIMATOR_COMMIT}, found {commit}")
    sys.path.insert(0, str(estimator))
    from estimator import LWE, ND
    from estimator.lwe_dual import DH
    from estimator.lwe_guess import exhaustive_search
    from estimator.reduction import ADPS16, ChaLoy21
    from sage.all import log, oo
    from sage.env import SAGE_VERSION

    report = {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "estimator_commit": commit,
        "sage_version": SAGE_VERSION,
        "python_version": sys.version,
        "phase": args.phase,
        "widths": widths,
        "assumptions": [
            "Fixed public A,B each have two ring rows; degree 64; one distinct Bs tag.",
            "Invertible four-column ring block permits binary-secret/binary-error systematization.",
            "Plain-LWE flattening is heuristic and does not model module-specific cryptanalysis.",
            "Finite sample count is 256, independently of scheme width.",
            "GSA and quantum Core-SVP costs are heuristics, not measured quantum hardware costs.",
            "Primal hybrid guessing and probability handling retain the official classical/MITM model.",
            "MITM with SVP hybrid is a sensitivity check flagged overly optimistic by the official suite.",
            "MATZOV dual is excluded because its default sample count is n at this revision.",
            "No proof soundness, Module-SIS, multi-target, or complete LRS security assessment.",
        ],
        "results": [],
    }
    save(output, report)
    models = [("ChaLoy21_quantum_core", ChaLoy21()),
              ("ADPS16_quantum_core", ADPS16(mode="quantum"))]
    tasks = [("primal_usvp", LWE.primal_usvp, {})]
    if args.phase == "full":
        tasks += [("primal_bdd", LWE.primal_bdd, {}),
                  ("primal_hybrid", LWE.primal_hybrid, {"mitm": False, "babai": False}),
                  ("primal_mitm_hybrid", LWE.primal_hybrid, {"mitm": True, "babai": True})]
    if args.phase == "sensitivity":
        tasks = []
    if args.phase in ("full", "sensitivity"):
        tasks += [("primal_mitm_svp_hybrid", LWE.primal_hybrid,
                   {"mitm": True, "babai": False}),
                  ("primal_babai_hybrid", LWE.primal_hybrid,
                   {"mitm": False, "babai": True})]
    if args.phase == "quantum-search":
        report["assumptions"] += [
            "DH uses exhaustive_search(quantum=True), a heuristic square-root search cost.",
            "DH caps original input samples at 256; derived short-vector samples are separately costed.",
            "DH beta optimization is bounded by max(min(m-zeta,max_beta),48) at this revision.",
            "DH at zeta=0 distinguishes; at positive zeta it costs the searched subvector only.",
            "Quantum gate costs, oracle construction and remaining-secret reconstruction are not explicitly costed.",
        ]

        def quantum_dual_hybrid(params, **options):
            return DH(solver=partial(exhaustive_search, quantum=True),
                      params=params, **options)

        tasks = [("dual_hybrid_quantum_search", quantum_dual_hybrid,
                  {"success_probability": 0.99, "opt_step": 8, "fft": False})]
    for width in widths:
        params = LWE.Parameters(**inputs(width), Xs=ND.Binary, Xe=ND.Binary)
        assert params.n == (width - 4) * 64 and params.m == 256
        assert params.Xs.bounds == (0, 1) and params.Xe.bounds == (0, 1)
        for model_name, model in models:
            for name, estimate, options in tasks:
                row = {"scheme_width": width, "input": inputs(width),
                       "input_repr": repr(params), "model": model_name,
                       "algorithm": name, "options": options,
                       "shape_model": None if args.phase == "quantum-search" else "gsa",
                       "status": "running"}
                if args.phase == "quantum-search":
                    row["solver"] = {"name": "estimator.lwe_guess.exhaustive_search",
                                     "quantum": True}
                report["results"].append(row)
                save(output, report)
                print(f"Starting width={width} {model_name} {name}", flush=True)
                started = time.perf_counter()
                try:
                    call_options = {"red_cost_model": model, **options}
                    if args.phase != "quantum-search":
                        call_options["red_shape_model"] = "gsa"
                    cost = estimate(params, **call_options)
                    row["raw_repr"] = repr(cost)
                    row["components"] = {str(key): str(value) for key, value in cost.items()}
                    row["log2_components"] = {}
                    for key in ("rop", "red", "svp", "guess", "mem"):
                        value = cost.get(key)
                        if value is not None and value != oo and value > 0:
                            bits = float(log(value, 2))
                            if math.isfinite(bits):
                                row["log2_components"][key] = bits
                    row["status"] = "ok" if "rop" in row["log2_components"] else "nonfinite"
                    if args.phase == "quantum-search" and row["status"] == "ok":
                        if not 1 <= cost["m"] <= params.m:
                            raise ValueError("DH exceeded the original finite sample cap")
                        row["original_samples_used"] = int(cost["m"])
                        row["searched_coordinates"] = int(cost["zeta"])
                        if cost["zeta"] == 0:
                            row["interpretation"] = "Distinguisher; not key recovery."
                        elif cost["zeta"] < params.n:
                            row["interpretation"] = (
                                "Subvector search; remaining-secret recovery is not explicitly costed.")
                        else:
                            row["interpretation"] = "Full-secret heuristic quantum exhaustive search."
                except Exception as error:
                    row.update(status="error", error_type=type(error).__name__,
                               error=str(error), traceback=traceback.format_exc())
                row["elapsed_seconds"] = time.perf_counter() - started
                save(output, report)
                print(f"Finished width={width} {model_name} {name}: "
                      f"{row['status']} {row.get('log2_components', {})}", flush=True)
    if args.phase == "screen":
        passing = []
        for width in widths:
            rows = [row for row in report["results"] if row["scheme_width"] == width]
            if len(rows) == len(models) and all(row["status"] == "ok" and
                    row["log2_components"]["rop"] >= 128 for row in rows):
                passing.append(width)
        report["first_screen_width_at_least_128"] = min(passing) if passing else None
    report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save(output, report)
    if any(row["status"] != "ok" for row in report["results"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
