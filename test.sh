#!/usr/bin/env bash
# Analyzer (PS 5.1 syntax) + Pester 5 in Docker. Extra args = test name filter.
# Modules are fetched on the host (the Docker VM may have no outbound network)
# and cached in ~/.cache/junk-test-modules, mounted into the container.
set -euo pipefail
cd "$(dirname "$0")"
IMAGE=mcr.microsoft.com/powershell:7.4-ubuntu-22.04
MODS="${JUNK_MODULE_CACHE:-$HOME/.cache/junk-test-modules}"
fetch() { # name version
  [ -f "$MODS/$1/$2/$1.psd1" ] && return 0
  local tmp; tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/m.zip" "https://www.powershellgallery.com/api/v2/package/$1/$2"
  mkdir -p "$MODS/$1/$2"
  unzip -q -o "$tmp/m.zip" -d "$MODS/$1/$2"
  rm -rf "$tmp"
}
fetch Pester 5.7.1
fetch PSScriptAnalyzer 1.25.0
# Non-root so chmod 000 fixtures really block reads; HOME must be writable for pwsh.
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD":/src:ro -v "$MODS":/mods:ro -e PSModulePath=/mods -e JUNK_FILTER="$*" "$IMAGE" pwsh -NoProfile -Command '
$ErrorActionPreference = "Stop"
Import-Module /mods/Pester/5.7.1/Pester.psd1
Import-Module /mods/PSScriptAnalyzer/1.25.0/PSScriptAnalyzer.psd1
$found = @(Invoke-ScriptAnalyzer -Path /src -Recurse -Settings /src/PSScriptAnalyzerSettings.psd1)
if ($found.Count) { $found | Format-List RuleName, ScriptName, Line, Message | Out-String | Write-Host }
$cfg = New-PesterConfiguration
$cfg.Run.Path = "/src/tests"
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = "Detailed"
if ($env:JUNK_FILTER) { $cfg.Filter.FullName = "*$($env:JUNK_FILTER)*" }
$r = Invoke-Pester -Configuration $cfg
Write-Host "RESULT: analyzer findings=$($found.Count) pester passed=$($r.PassedCount) failed=$($r.FailedCount)"
if ($found.Count -or $r.FailedCount -or $r.Result -ne "Passed") { exit 1 }
'
