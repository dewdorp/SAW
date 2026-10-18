[CmdletBinding()]
param([string]$BundleDir='',[string]$InstallRoot='C:\SAW',[string]$RecoveryPoint='',[string]$BaselineBundleDir='')
$ErrorActionPreference='Stop'
if(-not $BundleDir){$BundleDir=$PSScriptRoot}
$env:PSModulePath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
try{
    Import-Module (Join-Path $BundleDir 'update-ui.psm1') -Force -ErrorAction Stop
    $view=New-SawUpdateWindow -BundleDir $BundleDir -InstallRoot $InstallRoot -RecoveryPoint $RecoveryPoint -BaselineBundleDir $BaselineBundleDir
    [Windows.Forms.Application]::Run($view.Form)
    $view.Form.Dispose()
}catch{
    Add-Type -AssemblyName System.Windows.Forms
    $null=[Windows.Forms.MessageBox]::Show(
        '업데이트 창을 열지 못했습니다. 매체 폴더 전체와 Windows PowerShell 5.1을 확인하세요. 오류 원문이나 비밀값은 표시하지 않습니다.',
        'SAW 업데이트',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}
