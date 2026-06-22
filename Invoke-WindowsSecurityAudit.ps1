<#
.SYNOPSIS
Creates a read-only Windows security health report.
#>
[CmdletBinding()]
param([string]$OutputRoot="$env:PUBLIC\Documents\WindowsSecurityAudits")

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$runPath=Join-Path $OutputRoot ("Audit_{0}_{1}" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd_HHmmss'))
$results=New-Object System.Collections.Generic.List[object]

function Add-Check {
    param([string]$Category,[string]$Check,[string]$Status,[string]$Details)
    $script:results.Add([pscustomobject]@{Category=$Category;Check=$Check;Status=$Status;Details=$Details})
}

function Try-Check {
    param([scriptblock]$Action,[string]$Category,[string]$Check)
    try { & $Action } catch { Add-Check $Category $Check 'Unknown' $_.Exception.Message }
}

try {
    if($env:OS -ne 'Windows_NT'){throw 'Windows is required.'}
    New-Item $runPath -ItemType Directory -Force|Out-Null

    Try-Check {
        if(Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue){
            $d=Get-MpComputerStatus
            Add-Check 'Defender' 'Antivirus enabled' $(if($d.AntivirusEnabled){'Pass'}else{'Fail'}) ([string]$d.AntivirusEnabled)
            Add-Check 'Defender' 'Real-time protection' $(if($d.RealTimeProtectionEnabled){'Pass'}else{'Fail'}) ([string]$d.RealTimeProtectionEnabled)
            Add-Check 'Defender' 'Signature age' $(if($d.AntivirusSignatureAge -le 3){'Pass'}else{'Warning'}) ("$($d.AntivirusSignatureAge) day(s)")
        } else { Add-Check 'Defender' 'Status' 'Unknown' 'Defender cmdlets unavailable' }
    } 'Defender' 'Status'

    Try-Check {
        foreach($p in Get-NetFirewallProfile){
            Add-Check 'Firewall' ("$($p.Name) profile") $(if($p.Enabled){'Pass'}else{'Fail'}) ("Enabled=$($p.Enabled)")
        }
    } 'Firewall' 'Profiles'

    Try-Check {
        if(Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue){
            foreach($v in Get-BitLockerVolume){
                Add-Check 'Encryption' ("BitLocker $($v.MountPoint)") $(if($v.ProtectionStatus -eq 'On'){'Pass'}else{'Warning'}) ("Protection=$($v.ProtectionStatus); Method=$($v.EncryptionMethod)")
            }
        } else { Add-Check 'Encryption' 'BitLocker' 'Unknown' 'Cmdlet unavailable' }
    } 'Encryption' 'BitLocker'

    Try-Check {
        if(Get-Command Get-Tpm -ErrorAction SilentlyContinue){
            $t=Get-Tpm
            Add-Check 'Platform' 'TPM ready' $(if($t.TpmReady){'Pass'}else{'Warning'}) ("Present=$($t.TpmPresent); Ready=$($t.TpmReady)")
        }
    } 'Platform' 'TPM'

    Try-Check {
        $enabled=Confirm-SecureBootUEFI
        Add-Check 'Platform' 'Secure Boot' $(if($enabled){'Pass'}else{'Warning'}) ([string]$enabled)
    } 'Platform' 'Secure Boot'

    Try-Check {
        $f=Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        Add-Check 'Hardening' 'SMB1 disabled' $(if($f.State -eq 'Disabled'){'Pass'}else{'Fail'}) ([string]$f.State)
    } 'Hardening' 'SMB1'

    Try-Check {
        $u=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA
        Add-Check 'Hardening' 'UAC enabled' $(if($u.EnableLUA -eq 1){'Pass'}else{'Fail'}) ([string]$u.EnableLUA)
    } 'Hardening' 'UAC'

    Try-Check {
        $r=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
        Add-Check 'Remote access' 'Remote Desktop' $(if($r.fDenyTSConnections -eq 1){'Pass'}else{'Warning'}) $(if($r.fDenyTSConnections -eq 1){'Disabled'}else{'Enabled'})
    } 'Remote access' 'Remote Desktop'

    $pending=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    Add-Check 'Maintenance' 'No pending restart' $(if($pending){'Warning'}else{'Pass'}) ([string]$pending)

    $results|Export-Csv (Join-Path $runPath 'SecurityAudit.csv') -NoTypeInformation -Encoding UTF8
    $results|ConvertTo-Json -Depth 3|Out-File (Join-Path $runPath 'SecurityAudit.json') -Encoding UTF8
    $results|ConvertTo-Html -Title 'Windows Security Audit' -PreContent "<h1>Windows Security Audit</h1><p>$env:COMPUTERNAME - $(Get-Date)</p>"|Out-File (Join-Path $runPath 'SecurityAudit.html') -Encoding UTF8

    $fails=@($results|Where-Object Status -eq 'Fail').Count
    Write-Host "[OK] Audit complete: $runPath" -ForegroundColor Green
    if($fails -gt 0){exit 2}else{exit 0}
}
catch{Write-Error $_.Exception.Message;exit 1}
