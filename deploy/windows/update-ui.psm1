function Get-SawUpdateAppUrl {
    param([string]$Value)
    try {
        if([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 2048 -or $Value -match '[\x00-\x20]'){return ''}
        $uri=[Uri]::new($Value,[UriKind]::Absolute)
        if($uri.Scheme -cne 'https' -or $uri.Host.ToLowerInvariant() -notin @('localhost','127.0.0.1') -or $uri.Port -lt 1 -or
            $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/'){return ''}
        return $uri.AbsoluteUri
    }catch{return ''}
}
function Get-SawRetainedInstallationPath {
    param([string]$Value,[string]$InstallRoot)
    try {
        $path=Get-SawUpdateLocalPath $Value
        $root=Get-SawUpdateLocalPath $InstallRoot
        if(-not [IO.Directory]::Exists($path) -or [IO.Path]::GetFileName($path) -notmatch '^\.saw-k-[a-f0-9]{12}$'){return ''}
        if(-not [IO.Path]::GetDirectoryName($path).Equals([IO.Path]::GetDirectoryName($root),[StringComparison]::OrdinalIgnoreCase)){return ''}
        return $path
    }catch{return ''}
}
function New-SawRecordStartInfo {
    param($Context)
    $path=Get-SawUpdateLocalPath $Context.StateDir
    if(-not $Context.OwnedStateDirs.Contains($path) -or -not [IO.Directory]::Exists($path) -or
        [IO.Path]::GetFileName($path) -notmatch '^SAW-update-state-[a-f0-9]{32}$'){throw 'Unowned record path'}
    $acl=[IO.Directory]::GetAccessControl($path)
    $current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $current){throw 'Record access changed'}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @($current,'S-1-5-18')){throw 'Record access changed'}
    }
    $si=[Diagnostics.ProcessStartInfo]::new();$si.FileName=Join-Path $env:SystemRoot 'explorer.exe'
    $si.Arguments='"'+$path+'"';$si.UseShellExecute=$false
    return $si
}
$script:SawUpdateFixedMessages = @{
    'validate'='설치와 새 매체를 확인하고 있습니다.'
    'stop'='계정과 자료를 보존하기 위해 서버를 중지하고 있습니다.'
    'plan'='복구 공간과 중지 상태를 확인하고 있습니다.'
    'apply'='전체 복구본을 만들고 새 프로그램을 적용하고 있습니다.'
    'restore'='보관한 시점으로 전체 설치를 복구하고 있습니다.'
    'start'='데이터베이스, 검색, 웹 서버를 시작하고 있습니다.'
    'health'='저장소와 HTTPS 응답을 확인하고 있습니다.'
    'administrator_required'='관리자 권한으로 다시 검사해야 합니다. 아직 설치 내용을 검증하지 않았습니다.'
    'ready'='확인이 끝났습니다. 작업 내용을 확인한 뒤 진행하세요.'
    'completed'='기동 확인이 끝났습니다. 브라우저에서 로그인과 자료를 확인하세요.'
    'failed'='작업이 완료되지 않았습니다. 설치와 복구 폴더를 그대로 보관하세요.'
    'maintenance_confirmation_required'='진행 중인 작업을 저장하고 점검 중 사용을 중지한다는 항목을 확인하세요.'
    'recovery_confirmation_required'='복구 시점 이후의 계정과 자료 변경이 별도 보관된다는 항목을 확인하세요.'
    'recovery_path_required'='설치와 별도로 보관할 복구 폴더를 선택하세요.'
    'recovery_headroom_insufficient'='전체 복구를 위한 추가 공간이 부족합니다. 서버는 중지 상태이며 공간을 확보한 뒤 다시 검사하세요.'
    'foreign_service'='다른 설치의 서비스가 확인됐습니다. 선택한 설치 폴더와 서비스 등록을 관리자에게 확인하세요.'
    'process_identity_unverified'='실행 중인 프로세스가 이 설치 소유인지 확인하지 못했습니다. 다른 프로그램을 종료하지 않았습니다.'
    'runtime_upgrade_unsupported'='이 매체는 실행 환경까지 변경합니다. 지원되는 별도 업그레이드 절차가 필요합니다.'
    'installation_mode_unverified'='완료된 설치 방식이 확인되지 않습니다. 설치 폴더와 기존 설치 상태를 확인하세요.'
    'snapshot_identity_unverified'='이 복구본은 선택한 설치 경로와 일치하지 않습니다. 해당 설치의 복구본을 선택하세요.'
    'snapshot_verification_failed'='복구본 파일이나 권한 검증에 실패했습니다. 복구본을 수정하지 말고 보관하세요.'
    'service_configuration_unverified'='서비스 설정 경로가 확인되지 않습니다. 기존 설정을 보존하고 관리자에게 확인하세요.'
    'tracking_changed'='실행 추적 정보가 작업 중 달라졌습니다. 다른 제어 작업을 끝낸 뒤 다시 검사하세요.'
    'flush_failed'='검색 저장소의 안전한 저장을 확인하지 못했습니다. 저장소는 강제 종료하지 않았습니다.'
    'stop_failed'='전체 중지를 확인하지 못했습니다. 파일 적용을 진행하지 않았습니다.'
    'start_failed'='서버 기동을 확인하지 못했습니다. 복구본을 보관하고 기동 상태를 확인하세요.'
    'health_failed'='저장소 또는 HTTPS 검증에 실패했습니다. 로그인과 운영 준비가 완료된 상태가 아닙니다.'
    'baseline_required'='구형 설치를 확인하려면 원래 설치에 사용한 매체 폴더를 선택하세요.'
    'source_changed'='설치된 프로그램이 배포본과 다릅니다. 변경 파일을 보존하고 원래 매체를 확인하세요.'
    'unsafe_access'='설치 접근 권한을 확인하지 못했습니다. 권한을 자동 변경하지 않았으니 관리자에게 확인하세요.'
    'unsafe_owner'='설치 파일 소유자를 확인하지 못했습니다. 관리자에게 소유권을 확인하세요.'
    'still_running'='설치에 연결된 프로세스나 포트가 아직 사용 중입니다. 다른 제어 작업을 끝내고 다시 검사하세요.'
    'maintenance_busy'='같은 설치의 다른 설치·업데이트 작업이 진행 중입니다. 해당 작업이 끝난 뒤 다시 시도하세요.'
    'insufficient_space'='작업 공간이 부족합니다. 설치와 복구본을 지우지 말고 별도 공간을 확보하세요.'
    'unsupported_configuration'='외부 저장소 또는 변경된 구성이 확인됐습니다. 자동 업데이트 지원 범위를 확인하세요.'
    'unsafe_paths'='설치·매체·복구·작업 폴더를 서로 겹치지 않는 로컬 경로로 선택하세요.'
    'unsupported_shell_path'='이 설치 경로에는 자동 기동에서 지원하지 않는 문자가 있습니다. 기존 설치를 옮기거나 수정하지 마세요.'
}
function ConvertTo-SawPsLiteral {
    param([AllowEmptyString()][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}
function Get-SawUpdateLocalPath {
    param([Parameter(Mandatory=$true)][string]$Path,[switch]$AllowFile)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -match '[\x00-\x1f]') { throw 'Invalid local path' }
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.StartsWith('\\')) { throw 'Absolute local path required' }
    $absolute=[IO.Path]::GetFullPath($Path).TrimEnd('\','/')
    if ($absolute -eq [IO.Path]::GetPathRoot($absolute).TrimEnd('\')) { throw 'Drive root refused' }
    $part=$absolute
    while ($part) {
        if (Test-Path -LiteralPath $part) {
            $item=Get-Item -LiteralPath $part -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse path refused' }
            if ($part -eq $absolute -and -not $AllowFile -and -not $item.PSIsContainer) { throw 'Directory required' }
        }
        $next=[IO.Path]::GetDirectoryName($part)
        if ($next -eq $part) { break }
        $part=$next
    }
    return $absolute
}
function Test-SawUpdatePathsSeparate {
    param([string]$First,[string]$Second)
    $a=Get-SawUpdateLocalPath $First
    $b=Get-SawUpdateLocalPath $Second
    return -not ($a.Equals($b,[StringComparison]::OrdinalIgnoreCase) -or
        $a.StartsWith($b+'\',[StringComparison]::OrdinalIgnoreCase) -or
        $b.StartsWith($a+'\',[StringComparison]::OrdinalIgnoreCase))
}
function Test-SawUpdateAction {
    param([ValidateSet('inspect','apply','restore','start')][string]$Action,
        [string]$InstallRoot,[string]$RecoveryPoint,[bool]$Maintenance=$false,
        [bool]$RecoveryAcknowledged=$false,[bool]$Busy=$false,[string]$BundleDir='')
    if ($Busy) { return '작업이 진행 중입니다. 완료될 때까지 기다려 주세요.' }
    try {
        $null=Get-SawUpdateLocalPath $InstallRoot
        if ($BundleDir -and -not (Test-SawUpdatePathsSeparate $InstallRoot $BundleDir)) {
            return '새 매체와 기존 설치는 서로 다른 폴더여야 합니다.'
        }
    } catch { return '기존 설치의 올바른 로컬 절대 경로를 선택하세요.' }
    if ($Action -in @('apply','restore')) {
        if (-not $Maintenance) { return '접속과 분석 작업을 정리했다는 확인이 필요합니다.' }
        try {
            $null=Get-SawUpdateLocalPath $RecoveryPoint
            if (-not (Test-SawUpdatePathsSeparate $InstallRoot $RecoveryPoint)) { return '복구본은 기존 설치 밖의 별도 폴더를 선택하세요.' }
            if ($BundleDir -and -not (Test-SawUpdatePathsSeparate $BundleDir $RecoveryPoint)) { return '복구본은 새 매체 밖의 별도 폴더를 선택하세요.' }
        } catch { return '복구본의 올바른 로컬 절대 경로를 입력하세요.' }
    }
    if ($Action -eq 'restore' -and -not $RecoveryAcknowledged) { return '업데이트 이후 기록이 자동 병합되지 않는다는 복구 확인이 필요합니다.' }
    return ''
}
function Read-SawUpdateState {
    param([string]$StatePath,[string]$Action,[string]$InstallRoot)
    try {
        $null=Get-SawUpdateLocalPath $StatePath -AllowFile
        $file=Get-Item -LiteralPath $StatePath -Force -ErrorAction Stop
        if ($file.PSIsContainer -or $file.Length -lt 2 -or $file.Length -gt 65536) { return $null }
        $value=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($StatePath,[Text.UTF8Encoding]::new($false,$true))) -ErrorAction Stop
        if ($value -isnot [pscustomobject] -or $value -is [array]) { return $null }
        foreach ($name in @('schema','action','status','phase','install_root')) {
            if ($value.$name -isnot [string] -or [string]::IsNullOrWhiteSpace($value.$name)) { return $null }
        }
        if ($value.schema -cne 'saw.desktop-update/1' -or $value.action -cne $Action) { return $null }
        if ($value.status -cnotin @('working','ready','completed','failed')) { return $null }
        if ($value.phase.Length -gt 80 -or $value.phase -notmatch '^[a-z0-9_-]+$') { return $null }
        $expected=Get-SawUpdateLocalPath $InstallRoot
        $actual=Get-SawUpdateLocalPath $value.install_root
        if (-not $expected.Equals($actual,[StringComparison]::OrdinalIgnoreCase)) { return $null }
        if ($value.PSObject.Properties.Name -contains 'mode') {
            if ($value.mode -cnotin @('service','noadmin')) { return $null }
        }
        if ($value.PSObject.Properties.Name -contains 'requires_admin') {
            if ($value.requires_admin -isnot [bool]) { return $null }
            if ($value.requires_admin -and $value.mode -cne 'service') { return $null }
        }
        if ($value.PSObject.Properties.Name -contains 'code') {
            if ($value.code -isnot [string] -or $value.code.Length -gt 100 -or $value.code -notmatch '^[a-z0-9_-]*$') { return $null }
        }
        return $value
    } catch { return $null }
}
function Get-SawUpdateSafeMessage {
    param($State,[bool]$Accepted=$false)
    if ($State -and $State.mode -ceq 'service' -and $State.requires_admin -eq $true) {
        return '서비스 경로를 확인했습니다. 파일·기동 검증은 아직 끝나지 않았습니다. 관리자 권한으로 다시 열어 점검하세요.'
    }
    if (-not $Accepted) {
        if ($State -and $State.code -and $State.code -notin @('ready','completed','failed','validate','stop','plan','apply','restore','start','health') -and $script:SawUpdateFixedMessages.ContainsKey($State.code)) {
            return $script:SawUpdateFixedMessages[$State.code] + ' 설치와 복구본을 보존하세요. 자동 재시도·자동 복구는 하지 않습니다.'
        }
        return '작업을 완료하지 못했습니다. 설치와 복구본을 그대로 보존하세요. 자동 재시도·자동 복구는 하지 않았습니다.'
    }
    if ($State.action -ceq 'inspect') { return '설치 경로와 설치 방식을 확인했습니다. 여유 공간은 업데이트·복구 작업에서 전체 중지 후 다시 검사합니다.' }
    if ($State.action -ceq 'restore') { return '이전 시점 복구와 기동 확인이 끝났습니다. 기존 계정·MFA·조사·원문·노트를 확인하세요. 이후 기록은 자동 병합되지 않습니다.' }
    return '기동 확인이 끝났습니다. 기존 계정·MFA·조사·원문·노트와 분석 흐름을 확인한 뒤 분석가 접속을 다시 여세요.'
}
function Get-SawUpdateResult {
    param([string]$StatePath,[ValidateSet('inspect','apply','restore','start')][string]$Action,[string]$InstallRoot,[int]$ExitCode)
    $state=Read-SawUpdateState -StatePath $StatePath -Action $Action -InstallRoot $InstallRoot
    $expected=if ($Action -eq 'inspect') { 'ready' } else { 'completed' }
    $accepted=($ExitCode -eq 0 -and $null -ne $state -and $state.status -ceq $expected -and -not ($Action -ne 'inspect' -and $state.requires_admin -eq $true))
    return [pscustomobject]@{
        accepted=[bool]$accepted
        message=Get-SawUpdateSafeMessage -State $state -Accepted $accepted
        code=if($state -and $state.code){$state.code}else{'result_not_confirmed'}
        mode=if($state){$state.mode}else{$null}
        requires_admin=[bool]($state -and $state.requires_admin -eq $true)
        state=$state
    }
}
function New-SawWorkerStartInfo {
    param([string]$WorkerPath,[ValidateSet('inspect','apply','restore','start')][string]$Action,
        [string]$InstallRoot,[string]$BundleDir,[string]$StateDir,[string]$BaselineBundleDir='',[string]$RecoveryPoint='',
        [switch]$MaintenanceConfirmed,[switch]$ConfirmPointInTimeRecovery)
    $source='$ErrorActionPreference=''Stop''; & '+(ConvertTo-SawPsLiteral $WorkerPath)
    $values=[ordered]@{Action=$Action;InstallRoot=$InstallRoot;BundleDir=$BundleDir;StateDir=$StateDir}
    if($BaselineBundleDir){$values.BaselineBundleDir=$BaselineBundleDir}
    if($RecoveryPoint){$values.RecoveryPoint=$RecoveryPoint}
    foreach($key in $values.Keys){$source+=' -'+$key+' '+(ConvertTo-SawPsLiteral ([string]$values[$key]))}
    if($MaintenanceConfirmed){$source+=' -MaintenanceConfirmed'}
    if($ConfirmPointInTimeRecovery){$source+=' -ConfirmPointInTimeRecovery'}
    $source+='; if ($LASTEXITCODE -is [int]) { exit $LASTEXITCODE }'
    $si=[Diagnostics.ProcessStartInfo]::new()
    $si.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $si.Arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
    $si.UseShellExecute=$false;$si.CreateNoWindow=$true;$si.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden;$si.WorkingDirectory=$StateDir
    return $si
}
function New-SawUpdateStateDirectory {
    param([string]$BasePath='',[string[]]$ExcludedPaths=@())
    if(-not $BasePath){$BasePath=[IO.Path]::GetTempPath()}
    $base=Get-SawUpdateLocalPath $BasePath
    if(-not [IO.Directory]::Exists($base)){throw 'State parent is missing'}
    $path=Join-Path $base ('SAW-update-state-'+[guid]::NewGuid().ToString('N'))
    foreach($excluded in $ExcludedPaths){
        if($excluded -and -not (Test-SawUpdatePathsSeparate $path $excluded)){throw 'State directory must be separate'}
    }
    if(Test-Path -LiteralPath $path){throw 'State path already exists'}
    $current=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($current);$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @($current,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){
        $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    $null=[IO.Directory]::CreateDirectory($path,$acl)
    return $path
}
function Get-SawUpdateCompletion {
    param($Process,[string]$StatePath,[string]$Action,[string]$InstallRoot)
    if(-not $Process.HasExited){return [pscustomobject]@{finished=$false;result=$null}}
    $Process.WaitForExit()
    $result=Get-SawUpdateResult -StatePath $StatePath -Action $Action -InstallRoot $InstallRoot -ExitCode $Process.ExitCode
    return [pscustomobject]@{finished=$true;result=$result}
}
function Get-SawUpdatePhaseText {
    param([string]$Phase)
    $labels=@{verify_media='새 매체의 모든 파일을 확인하는 중';bootstrap='검증된 실행기를 준비하는 중';
        validate='기존 설치와 실행 경로를 확인하는 중';inspect='설치와 저장소를 점검하는 중';preflight='설치 조건과 여유 공간을 점검하는 중';plan='복구 공간과 중지 상태를 확인하는 중';
        stop='앱·검색·DB를 안전하게 중지하는 중';stopping='앱·검색·DB를 안전하게 중지하는 중';snapshot='전체 복구본을 만들고 확인하는 중';
        apply='새 프로그램을 적용하는 중';applying='복구본을 만들고 새 프로그램을 적용하는 중';restore='이전 시점 전체를 복구하는 중';
        restoring='이전 시점 전체를 복구하는 중';start='저장소와 앱을 시작하는 중';starting='저장소와 앱을 시작하는 중';
        health='인증서·DB·검색·앱의 실제 응답을 확인하는 중';complete='최종 결과를 확인하는 중'}
    if($labels.ContainsKey($Phase)){return $labels[$Phase]}
    return '작업 중입니다. 전체 복사·검증에는 시간이 걸릴 수 있습니다.'
}
function Set-SawUpdateUiBusy {
    param($Context,[bool]$Busy)
    $Context.Busy=$Busy
    foreach($control in $Context.InputControls){$control.Enabled=-not $Busy}
    $Context.Progress.Visible=$Busy;$Context.InspectButton.Enabled=-not $Busy
    $Context.StartButton.Enabled=-not $Busy -and -not $Context.RequiresAdmin
    $Context.ApplyButton.Enabled=-not $Busy -and $Context.Maintenance.Checked -and -not $Context.RequiresAdmin
    $Context.RestoreButton.Enabled=-not $Busy -and $Context.Maintenance.Checked -and $Context.RecoveryAck.Checked -and -not $Context.RequiresAdmin
    $Context.AdminButton.Visible=$Context.LastMode -ceq 'service' -and $Context.RequiresAdmin
    $Context.AdminButton.Enabled=-not $Busy -and $Context.AdminButton.Visible
    $Context.OpenButton.Enabled=-not $Busy -and -not [string]::IsNullOrEmpty($Context.AppUrl)
    $Context.RecordsButton.Enabled=-not $Busy -and -not [string]::IsNullOrEmpty($Context.StateDir) -and $Context.OwnedStateDirs.Contains($Context.StateDir)
}
function Start-SawUpdateUiAction {
    param($Context,[ValidateSet('inspect','apply','restore','start')][string]$Action)
    $gate=@{Action=$Action;InstallRoot=$Context.InstallRoot.Text;BundleDir=$Context.BundleDir.Text;RecoveryPoint=$Context.RecoveryPoint.Text;Maintenance=$Context.Maintenance.Checked;RecoveryAcknowledged=$Context.RecoveryAck.Checked;Busy=$Context.Busy}
    $reason=Test-SawUpdateAction @gate
    if($reason){$Context.Status.Text=$reason;return $false}
    if($Action -ne 'inspect' -and $Context.RequiresAdmin){$Context.Status.Text='서비스 설치는 관리자 권한으로 다시 열어 점검한 후 진행하세요.';return $false}
    try{
        $excludes=@($Context.InstallRoot.Text,$Context.BundleDir.Text,$Context.RecoveryPoint.Text,$Context.Baseline.Text)|Where-Object{-not [string]::IsNullOrWhiteSpace($_)}
        $stateDir=New-SawUpdateStateDirectory -ExcludedPaths $excludes
        $arguments=@{WorkerPath=(Join-Path $Context.BundleDir.Text 'update-worker.ps1');Action=$Action;InstallRoot=$Context.InstallRoot.Text;BundleDir=$Context.BundleDir.Text;
            StateDir=$stateDir;BaselineBundleDir=$Context.Baseline.Text;RecoveryPoint=$Context.RecoveryPoint.Text;MaintenanceConfirmed=$Context.Maintenance.Checked;ConfirmPointInTimeRecovery=$Context.RecoveryAck.Checked}
        $si=New-SawWorkerStartInfo @arguments
        $Context.StateDir=$stateDir;$null=$Context.OwnedStateDirs.Add($stateDir);$Context.LastResult=$null;$Context.AppUrl='';$Context.ActiveAction=$Action;$Context.ExpectedRoot=$Context.InstallRoot.Text;$Context.StartedAt=[DateTime]::UtcNow
        $Context.WorkerProcess=[Diagnostics.Process]::Start($si)
        Set-SawUpdateUiBusy $Context $true
        $Context.Status.Text="작업을 시작했습니다. 창을 열어 둔 채 기다려 주세요.`r`n작업 기록 폴더: $stateDir"
        $Context.Timer.Start();return $true
    }catch{
        $Context.LastResult=[pscustomobject]@{accepted=$false;code='ui_worker_start_failed';state=$null}
        $Context.Status.Text='작업 실행기를 시작하지 못했습니다. 설치와 작업 기록을 그대로 보존하고 경로·권한을 확인하세요.'
        Set-SawUpdateUiBusy $Context $false;return $false
    }
}
function Update-SawUpdateUiProgress {
    param($Context)
    if(-not $Context.WorkerProcess){$Context.Timer.Stop();return}
    $elapsed=[DateTime]::UtcNow-$Context.StartedAt;$Context.Elapsed.Text='경과 시간 '+$elapsed.ToString('hh\:mm\:ss')
    $statePath=Join-Path $Context.StateDir 'state.json'
    $state=Read-SawUpdateState -StatePath $statePath -Action $Context.ActiveAction -InstallRoot $Context.ExpectedRoot
    if($state -and -not $Context.WorkerProcess.HasExited){$Context.Status.Text=(Get-SawUpdatePhaseText $state.phase)+"`r`n완료 전에는 서버를 별도로 시작하거나 창을 닫지 마세요.`r`n작업 기록 폴더: "+$Context.StateDir}
    try{
        $completion=Get-SawUpdateCompletion -Process $Context.WorkerProcess -StatePath $statePath -Action $Context.ActiveAction -InstallRoot $Context.ExpectedRoot
        if(-not $completion.finished){return}
        $Context.Timer.Stop();$Context.WorkerProcess.Dispose();$Context.WorkerProcess=$null
        $result=$completion.result;$Context.LastMode=$result.mode;$Context.RequiresAdmin=$result.requires_admin;$Context.LastResult=$result
        $summary=$result.message
        $Context.AppUrl=''
        if($result.accepted -and -not $result.requires_admin -and $result.state){
            $Context.AppUrl=Get-SawUpdateAppUrl ([string]$result.state.app_url)
            if($Context.AppUrl){$summary+=[Environment]::NewLine+'로컬 접속: '+$Context.AppUrl}
            elseif($result.state.app_url){$summary+=[Environment]::NewLine+'브라우저는 기존 접속 주소로 여세요. 자동 열기는 로컬 HTTPS 주소만 지원합니다.'}
        }
        if($result.state -and $result.state.retained_installation){
            $retained=Get-SawRetainedInstallationPath -Value $result.state.retained_installation -InstallRoot $Context.ExpectedRoot
            if($retained){$summary+=[Environment]::NewLine+'업데이트 이후 설치 보존: '+$retained+[Environment]::NewLine+'보존 폴더에서 직접 서버를 시작하지 마세요.'}
        }
        if($result.mode -ceq 'noadmin'){$summary+="`r`n사용자 프로세스 설치: 지금 로그인한 원래 Windows 계정으로 계속 진행하세요."}
        if($result.mode -ceq 'service'){$summary+="`r`nWindows 서비스 설치"}
        if($result.state -and $result.state.plan){
            $plan=$result.state.plan
            $requiredKey='required_free_bytes'
            if($plan.PSObject.Properties.Name -contains 'required_with_restore_headroom_bytes'){$requiredKey='required_with_restore_headroom_bytes'}
            foreach($key in @('snapshot_bytes',$requiredKey,'free_bytes')){
                $value=$plan.$key
                if($value -is [long] -or $value -is [int] -or $value -is [decimal] -or $value -is [double]){
                    if($value -ge 0){
                        $title=@{snapshot_bytes='기존 설치 크기';required_free_bytes='필요 여유 공간';required_with_restore_headroom_bytes='필요 여유 공간(복구 포함)';free_bytes='검사 시 여유 공간'}[$key]
                        $summary+="`r`n"+$title+': '+([double]$value/1GB).ToString('N2')+' GiB'
                    }
                }
            }
        }
        $summary+="`r`n작업 기록 폴더: "+$Context.StateDir
        if(-not $result.accepted){$summary+="`r`n오류 코드: "+$result.code}
        $Context.Status.Text=$summary;Set-SawUpdateUiBusy $Context $false
    }catch{
        # Keep the process alive; never kill an uncertain worker.
        $Context.Status.Text='작업 상태를 확인하지 못했습니다. 창을 열어 두고 작업 기록을 보존하세요. 실행 중인 작업은 강제 종료하지 않습니다.'
    }
}
function New-SawElevatedUiStartInfo {
    param([string]$Mode,[bool]$RequiresAdmin,[string]$UiPath,[string]$BundleDir,[string]$InstallRoot,[string]$RecoveryPoint,[string]$BaselineBundleDir)
    if($Mode -cne 'service' -or -not $RequiresAdmin){throw 'Service elevation not authorized by inspection'}
    $source='& '+(ConvertTo-SawPsLiteral $UiPath)
    foreach($item in @(@('BundleDir',$BundleDir),@('InstallRoot',$InstallRoot),@('RecoveryPoint',$RecoveryPoint),@('BaselineBundleDir',$BaselineBundleDir))){
        if($item[1]){$source+=' -'+$item[0]+' '+(ConvertTo-SawPsLiteral $item[1])}
    }
    $si=[Diagnostics.ProcessStartInfo]::new();$si.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $si.Arguments='-NoLogo -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
    $si.UseShellExecute=$true;$si.Verb='runas';$si.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    return $si
}
function New-SawUpdateWindow {
    param([Parameter(Mandatory=$true)][string]$BundleDir,[string]$InstallRoot='C:\SAW',[string]$RecoveryPoint='',[string]$BaselineBundleDir='')
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $form=[Windows.Forms.Form]::new();$form.Text='SAW 기존 설치 업데이트 · 계정과 분석 자료 유지'
    $area=[Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $width=[Math]::Min(1040,[Math]::Max(320,$area.Width-40))
    $height=[Math]::Min(850,[Math]::Max(420,$area.Height-40))
    $form.Size=[Drawing.Size]::new($width,$height)
    $form.MinimumSize=[Drawing.Size]::new([Math]::Min(950,$width),[Math]::Min(680,$height))
    $form.StartPosition='CenterScreen';$form.Font=[Drawing.Font]::new('Malgun Gothic',9);$form.AutoScaleMode='Font'
    $form.BackColor=[Drawing.Color]::FromArgb(242,246,250)
    $panel=[Windows.Forms.TableLayoutPanel]::new();$panel.Dock='Fill';$panel.Padding=[Windows.Forms.Padding]::new(22);$panel.ColumnCount=1;$panel.RowCount=13
    foreach($height in @(56,48,48,48,48,48,48,45,48,40,24,28)){$null=$panel.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute',$height))}
    $null=$panel.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent',100));$form.Controls.Add($panel)
    $heading=[Windows.Forms.Label]::new();$heading.Text='기존 SAW를 안전하게 업데이트합니다'
    $heading.Font=[Drawing.Font]::new('Malgun Gothic',18,[Drawing.FontStyle]::Bold);$heading.Dock='Fill';$heading.ForeColor=[Drawing.Color]::FromArgb(21,54,85)
    $panel.Controls.Add($heading,0,0)
    $intro=[Windows.Forms.Label]::new();$intro.Dock='Fill'
    $intro.Text="기존 계정·MFA·조사·분석 자료와 설정을 유지합니다. 새 매체를 기존 설치 위에 덮어쓰지 마세요.`r`n먼저 설치 점검 → 분석가 작업 정리 → 업데이트 시작 순서로 진행합니다."
    $panel.Controls.Add($intro,0,1)
    $inputs=[Collections.Generic.List[Windows.Forms.Control]]::new();$pathControls=@{}
    $specs=@(@('InstallRoot','기존 설치 폴더',$InstallRoot,$true),@('BundleDir','새 매체 폴더',$BundleDir,$false),
        @('RecoveryPoint','복구본 폴더',$RecoveryPoint,$true),@('Baseline','원래 매체 (선택)',$BaselineBundleDir,$true))
    if(-not $RecoveryPoint){$specs[2][2]=Join-Path ([IO.Path]::GetDirectoryName($InstallRoot)) ('SAW-r-'+[DateTime]::Now.ToString('yyyyMMdd-HHmmss'))}
    for($i=0;$i -lt $specs.Count;$i++){
        $spec=$specs[$i];$isRecovery=$spec[0] -eq 'RecoveryPoint'
        $row=[Windows.Forms.TableLayoutPanel]::new();$row.Dock='Fill';$row.ColumnCount=3;$row.RowCount=1
        $null=$row.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent',100))
        $null=$row.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Absolute',145))
        $null=$row.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent',100))
        $buttonWidth=if($isRecovery){220}else{110}
        $null=$row.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Absolute',$buttonWidth))
        $label=[Windows.Forms.Label]::new();$label.Text=$spec[1];$label.Dock='Fill';$label.TextAlign='MiddleLeft'
        $box=[Windows.Forms.TextBox]::new();$box.Text=$spec[2];$box.Dock='Fill';$box.Margin=[Windows.Forms.Padding]::new(0,8,8,3);$box.ReadOnly=-not $spec[3]
        $browse=[Windows.Forms.Button]::new();$browse.Text=if($isRecovery){'새 위치'}else{'폴더 선택'}
        $browse.Enabled=[bool]$spec[3];$browse.Margin=[Windows.Forms.Padding]::new(0,5,5,6)
        $browse.Size=[Drawing.Size]::new(105,32)
        $chooser=[Windows.Forms.FlowLayoutPanel]::new();$chooser.Dock='Fill';$chooser.WrapContents=$false;$chooser.Controls.Add($browse)
        $row.Controls.Add($label,0,0);$row.Controls.Add($box,1,0);$row.Controls.Add($chooser,2,0);$panel.Controls.Add($row,0,$i+2)
        $pathControls[$spec[0]]=$box
        if($spec[3]){$inputs.Add($box);$inputs.Add($browse)}
        $targetBox=$box;$owner=$form
        $browse.Add_Click({
            $dialog=[Windows.Forms.FolderBrowserDialog]::new()
            $dialog.Description=if($isRecovery){'새 복구본을 둘 상위 폴더를 선택하세요. 아직 없는 새 폴더 이름이 붙습니다.'}else{'실제 설치 또는 원래 설치 매체 폴더를 선택하세요.'}
            $dialog.ShowNewFolderButton=$false
            if([IO.Directory]::Exists($targetBox.Text)){$dialog.SelectedPath=$targetBox.Text}
            try{
                if($dialog.ShowDialog($owner) -eq [Windows.Forms.DialogResult]::OK){
                    $targetBox.Text=if($isRecovery){Join-Path $dialog.SelectedPath ('SAW-r-'+[DateTime]::Now.ToString('yyyyMMdd-HHmmss'))}else{$dialog.SelectedPath}
                }
            }finally{$dialog.Dispose()}
        }.GetNewClosure())
        if($isRecovery){
            $existing=[Windows.Forms.Button]::new();$existing.Text='복구본 선택';$existing.Size=[Drawing.Size]::new(105,32);$existing.Margin=[Windows.Forms.Padding]::new(0,5,0,6)
            $chooser.Controls.Add($existing);$inputs.Add($existing)
            $existing.Add_Click({
                $dialog=[Windows.Forms.FolderBrowserDialog]::new();$dialog.Description='이전 상태로 복구할 때 사용할 기존 복구본 폴더를 선택하세요.'
                $dialog.ShowNewFolderButton=$false
                try{if($dialog.ShowDialog($owner) -eq [Windows.Forms.DialogResult]::OK){$targetBox.Text=$dialog.SelectedPath}}finally{$dialog.Dispose()}
            }.GetNewClosure())
        }
    }
    $maintenance=[Windows.Forms.CheckBox]::new();$maintenance.Dock='Fill'
    $maintenance.Text='분석가 접속을 정리했고 업로드·분석 작업이 끝났습니다. 앱·검색·DB를 잠시 중지하는 데 동의합니다.'
    $panel.Controls.Add($maintenance,0,6);$inputs.Add($maintenance)
    $ack=[Windows.Forms.CheckBox]::new();$ack.Dock='Fill'
    $ack.Text='[복구할 때만] 업데이트 이후의 기록은 자동 병합되지 않으며, 이전 시점의 계정·자료로 돌아감을 확인했습니다.'
    $panel.Controls.Add($ack,0,7);$inputs.Add($ack)
    $actions=[Windows.Forms.FlowLayoutPanel]::new();$actions.Dock='Fill';$actions.WrapContents=$false;$buttons=@{}
    foreach($item in @(@('InspectButton','설치 점검',115),@('ApplyButton','업데이트 시작',145),@('RestoreButton','이전 상태로 복구',160),@('StartButton','설치본 다시 시작',150),@('AdminButton','관리자 권한으로 다시 열기',215))){
        $button=[Windows.Forms.Button]::new();$button.Text=$item[1];$button.Size=[Drawing.Size]::new($item[2],35)
        $button.Margin=[Windows.Forms.Padding]::new(0,3,8,3);$actions.Controls.Add($button);$buttons[$item[0]]=$button
    }
    $panel.Controls.Add($actions,0,8)
    $links=[Windows.Forms.FlowLayoutPanel]::new();$links.Dock='Fill'
    $open=[Windows.Forms.Button]::new();$open.Text='SAW 열기';$open.Size=[Drawing.Size]::new(115,32)
    $records=[Windows.Forms.Button]::new();$records.Text='기록 폴더';$records.Size=[Drawing.Size]::new(115,32)
    $links.Controls.Add($open);$links.Controls.Add($records);$panel.Controls.Add($links,0,9)
    $progress=[Windows.Forms.ProgressBar]::new();$progress.Dock='Fill';$progress.Style='Marquee';$progress.MarqueeAnimationSpeed=28;$progress.Visible=$false
    $panel.Controls.Add($progress,0,10)
    $elapsed=[Windows.Forms.Label]::new();$elapsed.Text='준비됨 · 파일 검증과 전체 복사는 시간이 걸릴 수 있습니다.';$elapsed.Dock='Fill';$panel.Controls.Add($elapsed,0,11)
    $status=[Windows.Forms.TextBox]::new();$status.Multiline=$true;$status.ReadOnly=$true;$status.ScrollBars='Vertical';$status.Dock='Fill';$status.BackColor=[Drawing.Color]::White
    $status.Text="설치 점검을 누르면 설치 방식과 경로를 확인합니다.`r`n사용자 프로세스(-NoAdmin) 설치는 원래 실행하던 Windows 계정을 유지하세요.`r`n업데이트: 같은 드라이브의 아직 없는 새 복구본 폴더 / 복구: 기존 복구본 폴더를 선택합니다.`r`n이 창은 비밀번호를 묻거나 계정을 초기화하지 않습니다."
    $panel.Controls.Add($status,0,12)
    $timer=[Windows.Forms.Timer]::new();$timer.Interval=500
    $context=[pscustomobject]@{
        Form=$form;InstallRoot=$pathControls.InstallRoot;BundleDir=$pathControls.BundleDir;RecoveryPoint=$pathControls.RecoveryPoint;Baseline=$pathControls.Baseline
        Maintenance=$maintenance;RecoveryAck=$ack;InspectButton=$buttons.InspectButton;ApplyButton=$buttons.ApplyButton;RestoreButton=$buttons.RestoreButton
        StartButton=$buttons.StartButton;AdminButton=$buttons.AdminButton;Progress=$progress;Elapsed=$elapsed;Status=$status;Timer=$timer;InputControls=$inputs
        OpenButton=$open;RecordsButton=$records;AppUrl='';OwnedStateDirs=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Busy=$false;WorkerProcess=$null;StateDir='';ActiveAction='';ExpectedRoot='';StartedAt=[DateTime]::UtcNow;LastMode='';RequiresAdmin=$false;LastResult=$null
    }
    foreach($item in @(@($context.InspectButton,'inspect'),@($context.ApplyButton,'apply'),@($context.RestoreButton,'restore'),@($context.StartButton,'start'))){
        $button=$item[0];$action=$item[1];$ctx=$context
        $button.Add_Click({$null=Start-SawUpdateUiAction -Context $ctx -Action $action}.GetNewClosure())
    }
    $ctx=$context
    $maintenance.Add_CheckedChanged({Set-SawUpdateUiBusy $ctx $ctx.Busy}.GetNewClosure())
    $ack.Add_CheckedChanged({Set-SawUpdateUiBusy $ctx $ctx.Busy}.GetNewClosure())
    $pathControls.InstallRoot.Add_TextChanged({
        if(-not $ctx.Busy){
            $ctx.LastMode='';$ctx.RequiresAdmin=$false;$ctx.LastResult=$null;$ctx.AppUrl=''
            try{$parent=[IO.Path]::GetDirectoryName((Get-SawUpdateLocalPath $ctx.InstallRoot.Text));$ctx.RecoveryPoint.Text=Join-Path $parent ('SAW-r-'+[DateTime]::Now.ToString('yyyyMMdd-HHmmss'))}catch{}
            Set-SawUpdateUiBusy $ctx $false
        }
    }.GetNewClosure())
    $timer.Add_Tick({try{Update-SawUpdateUiProgress $ctx}catch{$ctx.Status.Text='작업 상태를 읽지 못했습니다. 창을 유지하고 작업 기록을 보존하세요. 실행 중인 작업은 종료하지 않습니다.'}}.GetNewClosure())
    $context.OpenButton.Add_Click({
        if($ctx.Busy){return}
        $url=Get-SawUpdateAppUrl $ctx.AppUrl
        if(-not $url){$ctx.Status.Text='로컬 HTTPS 접속 주소를 확인하지 못했습니다. 기존 접속 주소를 직접 사용하세요.';return}
        try{$si=[Diagnostics.ProcessStartInfo]::new($url);$si.UseShellExecute=$true;$null=[Diagnostics.Process]::Start($si)}
        catch{$ctx.Status.Text='브라우저를 열지 못했습니다. 기존 접속 주소를 직접 사용하세요.'}
    }.GetNewClosure())
    $context.RecordsButton.Add_Click({
        if($ctx.Busy){return}
        try{$si=New-SawRecordStartInfo $ctx;$null=[Diagnostics.Process]::Start($si)}
        catch{$ctx.Status.Text='이 창이 만든 보호된 기록 폴더를 확인하지 못해 열지 않았습니다.'}
    }.GetNewClosure())
    $context.AdminButton.Add_Click({
        if($ctx.Busy -or $ctx.LastMode -cne 'service' -or -not $ctx.RequiresAdmin){return}
        try{
            $elevate=@{Mode=$ctx.LastMode;RequiresAdmin=$ctx.RequiresAdmin;UiPath=(Join-Path $ctx.BundleDir.Text 'update-ui.ps1');BundleDir=$ctx.BundleDir.Text;
                InstallRoot=$ctx.InstallRoot.Text;RecoveryPoint=$ctx.RecoveryPoint.Text;BaselineBundleDir=$ctx.Baseline.Text}
            $si=New-SawElevatedUiStartInfo @elevate
            $null=[Diagnostics.Process]::Start($si);$ctx.Form.Close()
        }catch{$ctx.Status.Text='관리자 창을 열지 않았습니다. 현재 설치는 변경하지 않았으며, 점검 결과를 보존합니다.'}
    }.GetNewClosure())
    $form.Add_FormClosing({
        param($sender,$eventArgs)
        if($ctx.Busy){$eventArgs.Cancel=$true;$ctx.Status.Text="작업이 진행 중이어서 창을 닫지 않았습니다. 완료될 때까지 기다려 주세요.`r`n작업 기록 폴더: "+$ctx.StateDir}
    }.GetNewClosure())
    $form.Add_FormClosed({$ctx.Timer.Stop();$ctx.Timer.Dispose()}.GetNewClosure())
    Set-SawUpdateUiBusy $context $false
    return [pscustomobject]@{Form=$form;Context=$context}
}
Export-ModuleMember -Function Get-SawUpdateAppUrl,Get-SawRetainedInstallationPath,New-SawRecordStartInfo,ConvertTo-SawPsLiteral,Get-SawUpdateLocalPath,Test-SawUpdatePathsSeparate,Test-SawUpdateAction,Read-SawUpdateState,Get-SawUpdateResult,New-SawWorkerStartInfo,New-SawUpdateStateDirectory,Get-SawUpdateCompletion,Get-SawUpdateSafeMessage,Get-SawUpdatePhaseText,Set-SawUpdateUiBusy,Start-SawUpdateUiAction,Update-SawUpdateUiProgress,New-SawElevatedUiStartInfo,New-SawUpdateWindow
