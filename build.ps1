param(
    [string]$Distribution = 'Ubuntu-26.04',
    [string]$DependencyPrefix = '/home/reuben/.cache/spark-pq-measure-20261002/sage-env',
    [switch]$Benchmark,
    [int]$Runs = 3,
    [ValidateSet('bimodal','ordinary')][string]$Core = 'bimodal',
    [ValidateSet('compressed','raw')][string]$Encoding = 'compressed'
)
$ErrorActionPreference = 'Stop'
if ($Runs -lt 1) { throw 'Runs must be positive' }

function Invoke-WslBuild([string[]]$Arguments) {
    & wsl.exe -d $Distribution --cd $PSScriptRoot -- @Arguments
    if ($LASTEXITCODE -ne 0) { throw "WSL command failed with exit code $LASTEXITCODE" }
}

$backendArguments = @('python3', 'tools/build_lazer.py')
if ($DependencyPrefix) { $backendArguments += @('--dependency-prefix', $DependencyPrefix) }
Invoke-WslBuild $backendArguments
$configureArguments = @('cmake', '-S', '.', '-B', 'build', '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release')
if ($DependencyPrefix) { $configureArguments += "-DCMAKE_PREFIX_PATH=$DependencyPrefix" }
Invoke-WslBuild $configureArguments
Invoke-WslBuild @('cmake', '--build', 'build', '-j4')
Invoke-WslBuild @('ctest', '--test-dir', 'build', '--output-on-failure')
if ($Benchmark) {
    Invoke-WslBuild @('./build/blrs_bench', '--runs', "$Runs", '--core', $Core, '--encoding', $Encoding, '--output', 'benchmark_local.json')
}
