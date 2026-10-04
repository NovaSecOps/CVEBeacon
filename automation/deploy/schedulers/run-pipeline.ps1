# One-shot reference action; this script does not register a scheduled task.
param(
    [string]$RunnerExecutable = 'C:\Program Files\CVEBeacon\venv\Scripts\cvebeacon-auto.exe',
    [string]$RunnerConfiguration = 'C:\ProgramData\CVEBeacon\automation.toml'
)
$ErrorActionPreference = 'Stop'
if ($RunnerExecutable -notmatch '^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+[\\/])' -or
    $RunnerConfiguration -notmatch '^(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+[\\/])') {
    throw 'Use administrator-controlled absolute executable and configuration paths'
}
& $RunnerExecutable --config $RunnerConfiguration run
exit $LASTEXITCODE
