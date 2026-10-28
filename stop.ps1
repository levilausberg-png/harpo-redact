<#
.SYNOPSIS
    Stop what boot.ps1 started: the gateway, the local model in memory, and Ollama if boot started it.
.DESCRIPTION
    Double-click stop.cmd, or run:   powershell -NoProfile -ExecutionPolicy Bypass -File .\stop.ps1
    An Ollama that was already running before boot is left running.
.EXAMPLE
    .\stop.cmd -KeepModel
#>
[CmdletBinding()]
param([switch]$KeepOllama, [switch]$KeepModel)
$ErrorActionPreference = "Stop"
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch { }
Set-Location -LiteralPath $PSScriptRoot
$onWindows = ($PSVersionTable.PSEdition -eq "Desktop") -or ($IsWindows -eq $true)
if ($onWindows) { $venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe" } else { $venvPy = Join-Path $PSScriptRoot ".venv/bin/python" }
if (-not (Test-Path -LiteralPath $venvPy)) { Write-Host "  Nothing to stop: boot has not run in this folder."; exit 0 }
$downArgs = @("-m", "harpo_redact", "down")
if ($KeepOllama) { $downArgs += "--keep-ollama" }
if ($KeepModel) { $downArgs += "--keep-model" }
& $venvPy @downArgs
exit $LASTEXITCODE
