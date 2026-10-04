"""Build isolated raw-wire D/gamma experiments without changing the candidate.

Run under the existing Linux/WSL toolchain. Each output directory must be new.
Saved raw proofs can be sized independently with hypothetical compact codecs.
"""
import argparse
from decimal import Decimal, localcontext
import difflib
import hashlib
import json
from math import isqrt
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
Q = 1151179879138398721
IDENTITY_FILES = (
    'src/candidate.cpp', 'src/relation.cpp', 'src/transcript.cpp', 'src/sampler.cpp',
    'src/codec.cpp', 'backend/backend.cpp', 'backend/proof_params.h', 'backend/lazer.patch',
    'include/blrs/candidate.hpp', 'include/blrs/relation.hpp', 'include/blrs/transcript.hpp',
    'include/blrs/codec.hpp', 'include/blrs/random.hpp', 'include/blrs/sampler.hpp',
    'backend/backend.hpp', 'backend/blrs_callbacks.h',
)


def parameters(d, gamma):
    if not (0 <= d < 60 and gamma > 0 and gamma % 2 == 0 and (Q-1) % gamma == 0):
        raise ValueError('D must be in [0,60), gamma a positive even divisor of Q-1')
    with localcontext() as context:
        context.prec = 100
        half = Decimal(253952) / 5 * Decimal(12160).sqrt()
        half += (Decimal(504) * Decimal(2)**(d-1) + Decimal(gamma)/2) * Decimal(1280).sqrt()
        bsq = int(half*half)
    if 6080 * bsq >= 2**128 or bsq >= 2**64:
        raise ValueError('profile exceeds the existing fixed-width verifier bounds')
    m = (Q-1)//gamma
    ta1_max = Q-1 if d == 0 else (Q-2 + (1 << (d-1))) >> d
    return {'D': d, 'gamma': gamma, 'm': m, 'Bsq': bsq, 'z21_abs_max': isqrt(bsq),
            'hint_abs_max': m//2, 'hint_min': -((m-1)//2), 'tA1_max': ta1_max,
            'compact_tA1_bits': 60-d,
            'lazer_codegen_efficiency_condition': (1 << d) * 8 * 64 < 2 * gamma}


def replace(text, old, new, count=1):
    if text.count(old) != count:
        raise ValueError(f'expected {count} occurrences of {old!r}, got {text.count(old)}')
    return text.replace(old, new)


def patch_copy(copy, profile):
    d, gamma, bsq = (profile[key] for key in ('D', 'gamma', 'Bsq'))
    generator = copy/'backend/generate_params.py'
    code = generator.read_text()
    code = replace(code, 'gamma, rows, m1, m2, large = 512, 20, 23, 95, 17',
                   f'D = {d}\n    gamma, rows, m1, m2, large = {gamma}, 20, 23, 95, 17')
    code = replace(code, 'Decimal(504) / 2', 'Decimal(504) * Decimal(2)**(D-1)')
    code = replace(code, 'assert bsq == 31572639091752', f'assert bsq == {bsq}')
    code = replace(code, '"pow2D": 1', '"pow2D": 2**D')
    code = replace(code, '"pow2Dby2": 0', '"pow2Dby2": 0 if D == 0 else 2**(D-1)')
    code = replace(code, 'blrs_pow2Dby2, 0, {m%2}', 'blrs_pow2Dby2, {D}, {m%2}')
    generator.write_text(code)
    generated = runpy.run_path(str(generator))['generate']()
    (copy/'backend/proof_params.h').write_text(generated)
    bounds = {'31572639091752': str(bsq), '5618954': str(profile['z21_abs_max']+1),
              '5618953': str(profile['z21_abs_max']), '1124199100721092': str(profile['hint_abs_max'])}
    for name in ('backend/backend.cpp', 'src/codec.cpp', 'src/candidate.cpp',
                 'src/benchmark.cpp', 'tests/candidate_tests.cpp'):
        path = copy/name
        code = path.read_text()
        for old, new in bounds.items():
            code = code.replace(old, new)
        if name == 'src/candidate.cpp':
            code = replace(code, r'\"D\":0', rf'\"D\":{d}')
            code = replace(code, r'\"gamma\":512', rf'\"gamma\":{gamma}')
            code = replace(code, 'blrs-research-dual-core-exact-v2', 'blrs-rounding-experiment-v1')
        if name == 'src/codec.cpp':
            code = replace(code, 'if (x >= proof_modulus) throw std::invalid_argument("noncanonical tA1");',
                           f'if (x > {profile["tA1_max"]}ULL) throw std::invalid_argument("noncanonical tA1");')
            if profile['m'] % 2 == 0:
                code = replace(code, 'bounded(x, hint_cap);',
                               'bounded(x, hint_cap);\n    for (const auto& poly : base.hint) for (const auto x : poly)\n'
                               '        if (x == -hint_cap) throw std::invalid_argument("noncanonical hint endpoint");')
        if name == 'backend/backend.cpp' and profile['m'] % 2 == 0:
            code = replace(code, 'if(proof.c[32]!=0) return false;',
                           f'for(const auto& poly:proof.hint) for(auto x:poly) if(x == -{profile["hint_abs_max"]}LL) return false;\n'
                           '    if(proof.c[32]!=0) return false;')
        if name == 'src/benchmark.cpp':
            code = replace(code, 'if (!output.empty() && run == 0) {',
                           'if (!output.empty()) {\n'
                           '                    save(output+".run"+std::to_string(run+1)+".signature.bin",encoded);\n'
                           '                }\n                if (!output.empty() && run == 0) {')
        path.write_text(code)


def source_hashes(root):
    return {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in IDENTITY_FILES}


def command(arguments, cwd, log):
    with log.open('x') as output:
        output.write(json.dumps(arguments)+'\n')
        output.flush()
        completed = subprocess.run(arguments, cwd=cwd, stdout=output, stderr=subprocess.STDOUT)
    if completed.returncode:
        raise RuntimeError(f'{arguments[0]} returned {completed.returncode}; see {log}')


def verify_saved_runs(copy, core, output, destination, runs):
    verified = []
    for number in range(1, runs+1):
        prefix = copy/f'verify-run{number}'
        for suffix in ('.crs.bin', '.statement.bin', '.ring.bin', '.message.bin', '.signature.bin'):
            source = Path(str(output)+(f'.run{number}.signature.bin' if suffix == '.signature.bin' else suffix))
            Path(str(prefix)+suffix).symlink_to(source)
        command([str(copy/'build/blrs_bench'), '--core', core, '--encoding', 'raw', '--verify-fixture', str(prefix)],
                copy, destination/f'fresh_verify_run{number}.log')
        proof = Path(str(output)+f'.run{number}.signature.bin')
        verified.append({'path': str(proof), 'sha256': hashlib.sha256(proof.read_bytes()).hexdigest()})
    return verified


def experiment(profile, args, destination):
    destination.mkdir()
    cache = Path.home()/'.cache/blrs-rounding-experiments'
    cache.mkdir(parents=True, exist_ok=True)
    copy = Path(tempfile.mkdtemp(prefix=f'D{profile["D"]}-g{profile["gamma"]}-', dir=cache))
    before = source_hashes(ROOT)
    for name in ('src', 'backend', 'include', 'tests', 'tools'):
        shutil.copytree(ROOT/name, copy/name, ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(ROOT/'CMakeLists.txt', copy/'CMakeLists.txt')
    (copy/'vendor').mkdir()
    (copy/'vendor/lazer').symlink_to(ROOT/'vendor/lazer', target_is_directory=True)
    patch_copy(copy, profile)
    changed = []
    for path in sorted(copy.rglob('*')):
        if path.is_file() and not path.is_symlink() and 'vendor' not in path.relative_to(copy).parts:
            relative = path.relative_to(copy)
            original = ROOT/relative
            if original.is_file() and original.read_bytes() != path.read_bytes():
                changed.extend(difflib.unified_diff(original.read_text().splitlines(True), path.read_text().splitlines(True),
                                                   fromfile=str(relative), tofile=str(relative)))
    (destination/'source.patch').write_text(''.join(changed))
    evidence = {'parameters': profile, 'source_copy': str(copy), 'vendor_symlink': str(ROOT/'vendor/lazer'),
                'source_hashes_before': before, 'experimental_source_hashes': source_hashes(copy),
                'raw_wire_only': True, 'runs': args.runs, 'core': args.core,
                'fixed_profile_codec_tests': ('included' if (profile['D'], profile['gamma']) == (0, 512) else
                    'skipped: existing codec size/digest fixtures are D=0/gamma=512-specific')}
    (destination/'experiment.json').write_text(json.dumps(evidence, indent=2)+'\n')
    command(['cmake', '-S', '.', '-B', 'build', '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
             f'-DCMAKE_PREFIX_PATH={args.dependency_prefix}'], copy, destination/'configure.log')
    command(['cmake', '--build', 'build', '-j4'], copy, destination/'build.log')
    tests = ['ctest', '--test-dir', 'build', '--output-on-failure']
    if (profile['D'], profile['gamma']) != (0, 512):
        tests.extend(['-R', '^(relation|sampler|candidate)$'])
    command(tests, copy, destination/'tests.log')
    output = destination/'benchmark.json'
    bench = [str(copy/'build/blrs_bench'), '--core', args.core, '--encoding', 'raw', '--runs', str(args.runs),
             '--attempt-limit', str(args.attempt_limit), '--output', str(output)]
    if args.integration_tests:
        bench.append('--integration-tests')
    command(bench, copy, destination/'benchmark.log')
    evidence['fresh_verified_proofs'] = verify_saved_runs(copy, args.core, output, destination, args.runs)
    after = source_hashes(ROOT)
    if before != after:
        raise RuntimeError('production identity sources changed during the isolated experiment')
    evidence['source_hashes_after'] = after
    evidence['commands_passed'] = ['configure', 'build', 'relation/sampler/candidate tests', 'raw sign/verify', 'fresh verification']
    evidence['integration_tests'] = args.integration_tests
    (destination/'experiment.json').write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps({'completed': str(destination), 'parameters': profile}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidates', nargs='+', default=['0:512'], help='D:gamma pairs')
    parser.add_argument('--runs', type=int, default=1)
    parser.add_argument('--results', type=Path)
    parser.add_argument('--core', choices=('bimodal', 'ordinary'), default='bimodal')
    parser.add_argument('--attempt-limit', type=int, default=512)
    parser.add_argument('--integration-tests', action='store_true')
    parser.add_argument('--dependency-prefix', default='/home/reuben/.cache/spark-pq-measure-20261002/sage-env')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        baseline = parameters(0, 512)
        assert baseline['Bsq'] == 31572639091752 and baseline['z21_abs_max'] == 5618953
        assert baseline['hint_abs_max'] == 1124199100721092 and baseline['tA1_max'] == Q-1
        assert not parameters(1, 512)['lazer_codegen_efficiency_condition']
        for invalid in ((-1, 512), (0, 0), (60, 512), (0, 513)):
            try:
                parameters(*invalid)
            except ValueError:
                continue
            raise AssertionError(f'accepted invalid profile {invalid}')
        assert replace('abc', 'b', 'd') == 'adc'
        print('parameter and patch guards passed')
        return
    if args.runs < 1 or args.attempt_limit < 1 or args.results is None:
        parser.error('positive runs/attempt-limit and --results are required')
    profiles = [parameters(*map(int, item.split(':'))) for item in args.candidates]
    result = args.results.resolve()
    result.relative_to((ROOT/'analysis').resolve())
    result.mkdir(exist_ok=False)
    for profile in profiles:
        experiment(profile, args, result/f'D{profile["D"]}-g{profile["gamma"]}')


if __name__ == '__main__':
    main()
