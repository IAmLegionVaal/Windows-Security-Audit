#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot = "$env:PUBLIC\Documents\WindowsSecurityAudits"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$runPath = Join-Path $OutputRoot ("Audit_{0}_{1}" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd_HHmmss'))
$script:Results = New-Object System.Collections.Generic.List[object]

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-Check {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('Pass','Warning','Fail','Unknown')][string]$Status,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Details
    )

    $script:Results.Add([pscustomobject]@{
        CheckedAt = Get-Date
        Category = $Category
        Check = $Check
        Status = $Status
        Details = $Details
    })
}

function Invoke-AuditCheck {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    try {
        & $Action
    }
    catch {
        Add-Check -Category $Category -Check $Check -Status Unknown -Details $_.Exception.Message
    }
}

function Get-PendingRestartState {
    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $windowsUpdate = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $pendingRename = $false

    try {
        $value = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
            -Name PendingFileRenameOperations -ErrorAction Stop
        $pendingRename = $null -ne $value.PendingFileRenameOperations
    }
    catch {
        $pendingRename = $false
    }

    [pscustomobject]@{
        ComponentBasedServicing = $cbs
        WindowsUpdate = $windowsUpdate
        PendingFileRename = $pendingRename
        Pending = ($cbs -or $windowsUpdate -or $pendingRename)
    }
}

try {
    if ($env:OS -ne 'Windows_NT') {
        throw 'Windows is required.'
    }
    if (-not (Test-IsAdministrator)) {
        throw 'Run the security audit from an elevated PowerShell session.'
    }

    New-Item -Path $runPath -ItemType Directory -Force | Out-Null

    Invoke-AuditCheck -Category Defender -Check 'Microsoft Defender status' -Action {
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
            Add-Check Defender 'Microsoft Defender status' Unknown 'Defender cmdlets are unavailable.'
            return
        }

        $defender = Get-MpComputerStatus -ErrorAction Stop
        Add-Check Defender 'Antivirus enabled' $(if ($defender.AntivirusEnabled) { 'Pass' } else { 'Warning' }) ([string]$defender.AntivirusEnabled)
        Add-Check Defender 'Real-time protection' $(if ($defender.RealTimeProtectionEnabled) { 'Pass' } else { 'Warning' }) ([string]$defender.RealTimeProtectionEnabled)

        if ($null -eq $defender.AntivirusSignatureAge) {
            Add-Check Defender 'Signature age' Unknown 'Signature age was not returned.'
        }
        else {
            Add-Check Defender 'Signature age' $(if ($defender.AntivirusSignatureAge -le 3) { 'Pass' } else { 'Warning' }) "$($defender.AntivirusSignatureAge) day(s)"
        }
    }

    Invoke-AuditCheck -Category Firewall -Check 'Firewall profiles' -Action {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        if ($profiles.Count -eq 0) {
            Add-Check Firewall 'Firewall profiles' Unknown 'No firewall profiles were returned.'
            return
        }

        foreach ($profile in $profiles) {
            Add-Check Firewall "$($profile.Name) profile" $(if ($profile.Enabled) { 'Pass' } else { 'Fail' }) "Enabled=$($profile.Enabled)"
        }
    }

    Invoke-AuditCheck -Category Encryption -Check BitLocker -Action {
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
            Add-Check Encryption BitLocker Unknown 'BitLocker cmdlets are unavailable.'
            return
        }

        $volumes = @(Get-BitLockerVolume -ErrorAction Stop)
        if ($volumes.Count -eq 0) {
            Add-Check Encryption BitLocker Unknown 'No BitLocker volumes were returned.'
            return
        }

        foreach ($volume in $volumes) {
            $status = if ($volume.ProtectionStatus -eq 'On') { 'Pass' } else { 'Warning' }
            Add-Check Encryption "BitLocker $($volume.MountPoint)" $status "Protection=$($volume.ProtectionStatus); Method=$($volume.EncryptionMethod)"
        }
    }

    Invoke-AuditCheck -Category Platform -Check TPM -Action {
        if (-not (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) {
            Add-Check Platform TPM Unknown 'Get-Tpm is unavailable on this edition or platform.'
            return
        }

        $tpm = Get-Tpm -ErrorAction Stop
        if (-not $tpm.TpmPresent) {
            Add-Check Platform 'TPM present' Warning 'No TPM was detected.'
        }
        else {
            Add-Check Platform 'TPM present' Pass 'TPM detected.'
            Add-Check Platform 'TPM ready' $(if ($tpm.TpmReady) { 'Pass' } else { 'Warning' }) "Ready=$($tpm.TpmReady)"
        }
    }

    Invoke-AuditCheck -Category Platform -Check 'Secure Boot' -Action {
        if (-not (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
            Add-Check Platform 'Secure Boot' Unknown 'Secure Boot cmdlet is unavailable.'
            return
        }

        $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
        Add-Check Platform 'Secure Boot' $(if ($enabled) { 'Pass' } else { 'Warning' }) ([string]$enabled)
    }

    Invoke-AuditCheck -Category Hardening -Check SMB1 -Action {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        $disabled = [string]$feature.State -like 'Disabled*'
        Add-Check Hardening 'SMB1 disabled' $(if ($disabled) { 'Pass' } else { 'Fail' }) ([string]$feature.State)
    }

    Invoke-AuditCheck -Category Hardening -Check UAC -Action {
        $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction Stop
        Add-Check Hardening 'UAC enabled' $(if ($uac.EnableLUA -eq 1) { 'Pass' } else { 'Fail' }) ([string]$uac.EnableLUA)
    }

    Invoke-AuditCheck -Category 'Remote access' -Check 'Remote Desktop' -Action {
        $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
        $details = if ($rdp.fDenyTSConnections -eq 1) { 'Disabled' } else { 'Enabled; validate approved access controls.' }
        Add-Check 'Remote access' 'Remote Desktop' $(if ($rdp.fDenyTSConnections -eq 1) { 'Pass' } else { 'Warning' }) $details
    }

    Invoke-AuditCheck -Category Maintenance -Check 'Pending restart' -Action {
        $restart = Get-PendingRestartState
        Add-Check Maintenance 'No pending restart' $(if ($restart.Pending) { 'Warning' } else { 'Pass' }) `
            "CBS=$($restart.ComponentBasedServicing); WindowsUpdate=$($restart.WindowsUpdate); PendingFileRename=$($restart.PendingFileRename)"
    }

    $csvPath = Join-Path $runPath 'SecurityAudit.csv'
    $jsonPath = Join-Path $runPath 'SecurityAudit.json'
    $htmlPath = Join-Path $runPath 'SecurityAudit.html'

    $script:Results | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
    $script:Results | ConvertTo-Json -Depth 4 | Out-File $jsonPath -Encoding UTF8
    $script:Results | ConvertTo-Html -Title 'Windows Security Audit' `
        -PreContent "<h1>Windows Security Audit</h1><p>$env:COMPUTERNAME - $(Get-Date)</p>" |
        Out-File $htmlPath -Encoding UTF8

    $reviewItems = @($script:Results | Where-Object Status -ne Pass)
    Write-Host "[OK] Audit complete: $runPath"

    if ($reviewItems.Count -gt 0) {
        Write-Warning "$($reviewItems.Count) check(s) require review."
        exit 2
    }

    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
