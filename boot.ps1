<#
.SYNOPSIS
    Start Harpo, and your local model through Ollama, with one command.
.DESCRIPTION
    First run (a few minutes): creates .venv, installs the gateway, asks which provider to use and its key (stored in
    .harpo\.env, readable only by you), finds phi3 in Ollama, pins its digest and loads it, starts the gateway, runs
    the self-test and opens the console with your gateway key on the clipboard. Later runs take seconds.

    Double-click boot.cmd, or run:   powershell -NoProfile -ExecutionPolicy Bypass -File .\boot.ps1
    Works with Windows PowerShell 5.1 and PowerShell 7.
.EXAMPLE
    .\boot.cmd -Provider anthropic
.EXAMPLE
    .\boot.cmd -SlmModel phi3:mini -Strict
#>
[CmdletBinding()]
param(
    [string]$Provider = "",
    [string]$SlmModel = "phi3:latest",
    [switch]$NoSlm,
    [switch]$Strict,
    [switch]$Pull,
    [switch]$Reconfigure,
    [switch]$NoBrowser,
    [int]$Port = 0
)
$ErrorActionPreference = "Stop"
# This process only. boot.cmd already starts PowerShell with -ExecutionPolicy Bypass, which a blocked .ps1 needs.
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch { }
Set-Location -LiteralPath $PSScriptRoot
$onWindows = ($PSVersionTable.PSEdition -eq "Desktop") -or ($IsWindows -eq $true)

function Find-Python {
    $tries = New-Object System.Collections.ArrayList
    if ($onWindows -and (Get-Command py -ErrorAction SilentlyContinue)) {
        [void]$tries.Add(@("py", "-3.13"))
        [void]$tries.Add(@("py", "-3.12"))
    }
    foreach ($name in @("python3.13", "python3.12", "python3", "python")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        # Skip the Microsoft Store alias: it opens the Store instead of running Python.
        if ($cmd -and ("$($cmd.Source)" -notmatch "WindowsApps")) { [void]$tries.Add(@($cmd.Source)) }
    }
    foreach ($t in $tries) {
        $exe = $t[0]
        $pre = @($t | Select-Object -Skip 1)
        try { $out = & $exe @pre -c "import sys; print(int(sys.version_info >= (3, 12)))" 2>$null } catch { continue }
        if ("$out".Trim() -eq "1") { return ,$t }
    }
    return $null
}

New-Item -ItemType Directory -Force -Path ".harpo" | Out-Null
if ($onWindows) { $venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe" } else { $venvPy = Join-Path $PSScriptRoot ".venv/bin/python" }
if (-not (Test-Path -LiteralPath $venvPy)) {
    $py = Find-Python
    if ($null -eq $py) {
        Write-Host "  Python 3.12 or newer is required."
        Write-Host "  Install it with:  winget install Python.Python.3.12   (or from https://www.python.org/downloads/)"
        exit 1
    }
    Write-Host "  First run: creating .venv (a private Python environment for the gateway)"
    $exe = $py[0]
    $pre = @($py | Select-Object -Skip 1)
    & $exe @pre -m venv .venv
    if ($LASTEXITCODE -ne 0) { Write-Host "  Could not create .venv"; exit 1 }
}
$stampFile = Join-Path ".harpo" "install.stamp"
$stamp = (Get-FileHash -Algorithm SHA256 -LiteralPath "pyproject.toml").Hash
$installed = ""
if (Test-Path -LiteralPath $stampFile) { $installed = (Get-Content -LiteralPath $stampFile -Raw).Trim() }
if ($installed -ne $stamp) {
    Write-Host "  Installing Harpo into .venv (first run: 2-4 minutes)"
    & $venvPy -m pip install --disable-pip-version-check -q .
    if ($LASTEXITCODE -ne 0) { Write-Host "  Installation failed: see the messages above."; exit 1 }
    Set-Content -LiteralPath $stampFile -Value $stamp -Encoding ascii
}

$upArgs = @("-m", "harpo_redact", "up", "--slm-model", $SlmModel)
if ($Provider) { $upArgs += @("--provider", $Provider) }
if ($NoSlm) { $upArgs += "--no-slm" }
if ($Strict) { $upArgs += "--strict" }
if ($Pull) { $upArgs += "--pull" }
if ($Reconfigure) { $upArgs += "--reconfigure" }
if ($NoBrowser) { $upArgs += "--no-browser" }
if ($Port -gt 0) { $upArgs += @("--port", "$Port") }
& $venvPy @upArgs
exit $LASTEXITCODE
