# Complete stopped-installation backup through a verified external media runtime.
# Stop SAW, PostgreSQL and OpenSearch with saw-ctl first. This script never stops services.
[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\SAW",
    [Parameter(Mandatory=$true)][string]$BundleDir,
    [Parameter(Mandatory=$true)][string]$RecoveryPoint
)
$ErrorActionPreference = 'Stop'
# The updater verifies all media before extracting its standalone interpreter.
# Running the installed interpreter would correctly fail the stopped-process check.
& (Join-Path $BundleDir 'update.ps1') -Action backup -InstallRoot $InstallRoot -BundleDir $BundleDir -RecoveryPoint $RecoveryPoint
if ($LASTEXITCODE -ne 0) {
    throw 'Complete backup did not finish; preserve the destination and inspect the non-secret error'
}
Write-Host 'Keep a verified copy on separate storage. Existing recovery points are never deleted automatically.'
