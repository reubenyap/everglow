"""Build the pinned LaZer archive on Linux/WSL, using existing GMP/MPFR."""
import argparse
from pathlib import Path
import shlex
import subprocess
import sys
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dependency-prefix', type=Path,
                        help='Existing GMP/MPFR include and lib prefix')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Run this build helper inside Linux or WSL')
    workspace = Path(__file__).resolve().parents[1]
    source = workspace / 'vendor' / 'lazer'
    if not (source / 'src' / 'lnp-quad.c').is_file():
        parser.error('Pinned vendor/lazer source is missing')

    def run(command, cwd=source):
        print(shlex.join(map(str, command)), flush=True)
        subprocess.run(list(map(str, command)), cwd=cwd, check=True)

    run([sys.executable, workspace / 'backend' / 'generate_params.py'], workspace)
    third_party = source / 'third_party'
    for name in ('Falcon-impl-20211101', 'hexl-development'):
        target = third_party / name
        if not target.exists():
            with zipfile.ZipFile(third_party / (name+'.zip')) as archive:
                for entry in archive.infolist():
                    resolved = (third_party / entry.filename).resolve()
                    if not resolved.is_relative_to(third_party.resolve()):
                        raise ValueError('Archive path leaves the dependency directory')
                archive.extractall(third_party)
            if name.startswith('Falcon'):
                with (source / 'src' / 'falcon.patch').open('rb') as patch:
                    subprocess.run(['patch', '-p1'], cwd=target, stdin=patch, check=True)
    hexl = third_party / 'hexl-development'
    run(['cmake', '-S', hexl, '-B', hexl/'build', '-DHEXL_BENCHMARK=OFF',
         '-DHEXL_TESTING=OFF', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5'])
    run(['cmake', '--build', hexl/'build', '-j4'])
    cppflags = f'-DNDEBUG -I{shlex.quote(str(workspace / "backend"))}'
    if args.dependency_prefix:
        cppflags += f' -I{shlex.quote(str(args.dependency_prefix / "include"))}'
    run(['make', '-j4', 'liblazer.a', 'CPPFLAGS='+cppflags])


if __name__ == '__main__':
    main()
