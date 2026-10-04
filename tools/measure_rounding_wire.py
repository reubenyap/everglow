"""Exact wire-size accounting on verified raw rounding experiment proofs.

This models a new encoding; it does not turn an experimental proof into a
signature accepted by the production codec. Width zero is a new, lossless
Rice option. Other fields retain their existing widths and escape rule.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from check_candidate_artifacts import BitReader, decode_compressed, decode_raw, validate_body


def coefficient_bits(value, width, cap):
    if not 0 <= width <= 20 or abs(value) > cap:
        raise ValueError("invalid coefficient or width")
    high = (value + (1 << width) // 2) // (1 << width)
    unary = -2 * high if high <= 0 else 2 * high - 1
    return 31 + cap.bit_length() + 1 if unary >= 31 else unary + 1 + width


def measure(values, manifest, width):
    d = manifest["D"]
    if not 0 <= d < 60:
        raise ValueError("unsupported rounding")
    validate_body(values, manifest)
    cap = manifest["Q"] - 1 if d == 0 else (manifest["Q"] + (1 << (d-1)) - 2) >> d
    if any(value > cap for value in values["tA1"]):
        raise ValueError("noncanonical rounded commitment")
    if ((manifest["Q"] - 1) // manifest["gamma"]) % 2 == 0:
        if -manifest["hint_abs_max"] in values["hint"]:
            raise ValueError("noncanonical even-modulus hint")
    assert cap < 1 << (60-d)
    bits = {"tB": 1472*60, "base_h": 310*60, "tA1": 1280*(60-d), "c": 32*5}
    bimodal = manifest["sampler"]["modes"][0] == "bimodal"
    for name, low, cap in (("hint", width, manifest["hint_abs_max"]),
                           ("z1", 15 if bimodal else 19, manifest["z1_abs_max"]),
                           ("z21", 16, manifest["z21_abs_max"]),
                           ("z3", 19, manifest["range"]["infinity_cap"])):
        bits[name] = sum(coefficient_bits(value, low, cap) for value in values[name])
    return {"signature_bytes": 466 + (sum(bits.values()) + 1 + 7)//8,
            "field_bits": bits, "hint_low_bits": width}


def self_check():
    # Independent bit construction/reader check, including width zero,
    # signs, escape boundaries, and nonzero low bits.
    cap = 100000
    for width in range(12):
        for value in (-cap, -1025, -32, -16, -15, -1, 0, 1, 15, 16, 32, 1025, cap):
            high = (value + (1 << width)//2) // (1 << width)
            unary = -2*high if high <= 0 else 2*high-1
            bits = [1] * min(unary, 31)
            if unary >= 31:
                bits += [(value >> i) & 1 for i in range(cap.bit_length()+1)]
            else:
                bits += [0] + [((value-high*(1 << width)) >> i) & 1 for i in range(width)]
            assert len(bits) == coefficient_bits(value, width, cap)
            data = bytearray((len(bits)+7)//8)
            for i, bit in enumerate(bits):
                data[i//8] |= bit << (i%8)
            reader = BitReader(bytes(data))
            if width:
                decoded = reader.coefficient(width, cap, 31)
            else:
                count = 0
                while count < 31 and reader.integer(1):
                    count += 1
                decoded = reader.signed_integer(cap.bit_length()+1) if count == 31 else ((count+1)//2 if count%2 else -count//2)
            assert decoded == value and reader.position == len(bits)
    prefix = ROOT / "benchmark_bimodal_compressed.json"
    manifest = json.loads(Path(str(prefix)+".manifest.json").read_text())
    signature = Path(str(prefix)+".signature.bin").read_bytes()
    values = decode_compressed(signature[466:], manifest)
    assert measure(values, manifest, 8)["signature_bytes"] == len(signature) == 39442
    print("Signed coding boundary checks and exact 39442-byte baseline reproduction passed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prefixes", nargs="*", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        self_check()
    if not args.prefixes:
        if args.check:
            return
        parser.error("provide raw experiment prefixes")
    if args.output is None or args.output.exists():
        parser.error("a fresh --output path is required")
    rows = []
    for prefix in args.prefixes:
        manifest_bytes = Path(str(prefix)+".manifest.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        files = sorted(prefix.parent.glob(prefix.name+".run*.signature.bin"))
        if not files:
            files = [Path(str(prefix)+".signature.bin")]
        samples = []
        for path in files:
            signature = path.read_bytes()
            if signature[:10] != b"BLRSB001\x01\x00" or len(signature) != 87634:
                raise ValueError("expected fixed raw experiment proof")
            values = decode_raw(signature[466:])
            samples.append({"file": str(path), "sha256": hashlib.sha256(signature).hexdigest(),
                "hints": {"nonzero": sum(value != 0 for value in values["hint"]),
                          "absolute_max": max(map(abs, values["hint"])),
                          "histogram": dict(sorted(Counter(values["hint"]).items()))},
                "encodings": [measure(values, manifest, width) for width in range(17)]})
        means = [statistics.mean(sample["encodings"][width]["signature_bytes"] for sample in samples)
                 for width in range(17)]
        best = min(range(17), key=means.__getitem__)
        supported = min(range(1,17), key=means.__getitem__)
        sizes = [sample["encodings"][best]["signature_bytes"] for sample in samples]
        rows.append({"prefix": str(prefix), "D": manifest["D"], "gamma": manifest["gamma"],
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "sample_count": len(samples), "best_fixed_hint_low_bits": best,
            "best_current_codec_width": supported, "current_codec_mean_bytes": means[supported],
            "mean_bytes": means[best], "median_bytes": statistics.median(sizes),
            "minimum_bytes": min(sizes), "maximum_bytes": max(sizes), "samples": samples})
    args.output.write_text(json.dumps({"status": "exact_accounting_of_new_encoding_on_raw_proofs",
        "security_certified": False, "profiles": rows}, indent=2)+"\n")
    for row in rows:
        print({key: value for key, value in row.items() if key != "samples"})


if __name__ == "__main__":
    main()
