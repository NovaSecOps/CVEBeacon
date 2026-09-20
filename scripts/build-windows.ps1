param([string]$OutputDirectory = (Join-Path $PSScriptRoot "..\dist"),
      [string]$WorkDirectory = (Join-Path $PSScriptRoot "..\build"))
$ErrorActionPreference = "Stop"
$Python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$WorkDirectory = [IO.Path]::GetFullPath($WorkDirectory)
foreach ($Mode in @("onedir", "onefile")) {
    & $Python -m PyInstaller --noconfirm --clean "--$Mode" --name cvebeacon --collect-data cvebeacon --distpath $OutputDirectory --workpath (Join-Path $WorkDirectory $Mode) --specpath $WorkDirectory --paths (Join-Path $PSScriptRoot "..\src") (Join-Path $PSScriptRoot "cvebeacon_entry.py")
    if ($LASTEXITCODE -ne 0) { throw "Executable build failed ($Mode)." }
    $Executable = if ($Mode -eq "onedir") { Join-Path $OutputDirectory "cvebeacon\cvebeacon.exe" } else { Join-Path $OutputDirectory "cvebeacon.exe" }
    & $Executable --help
    if ($LASTEXITCODE -ne 0) { throw "Executable smoke test failed ($Mode)." }
}
foreach ($LicenseFile in @("LICENSE", "NOTICE")) {
    $Source = Join-Path $PSScriptRoot "..\$LicenseFile"
    Copy-Item -LiteralPath $Source -Destination (Join-Path $OutputDirectory $LicenseFile)
    Copy-Item -LiteralPath $Source -Destination (Join-Path $OutputDirectory "cvebeacon\$LicenseFile")
}
