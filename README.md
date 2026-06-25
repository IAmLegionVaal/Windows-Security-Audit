# Windows Security Audit

Read-only PowerShell assessment for common Windows protection and hardening controls.

## One-click use

1. Download and extract the repository.
2. Double-click `Run-OneClick.bat`.
3. Approve the administrator prompt.
4. Review CSV, JSON and HTML reports under `C:\Users\Public\Documents\WindowsSecurityAudits`.

The launcher elevates because several security cmdlets and registry checks are incomplete or unavailable to a standard user. Direct non-elevated execution returns a fatal error rather than producing a misleading partial success.

## Checks

- Microsoft Defender antivirus, real-time protection and signature age
- Windows Firewall profiles
- BitLocker protection
- TPM presence and readiness
- Secure Boot
- SMB1 optional-feature state
- UAC
- Remote Desktop exposure
- Pending restart indicators, including `PendingFileRenameOperations`

Unavailable cmdlets, unsupported firmware interfaces and failed data sources are recorded as `Unknown`; they are not silently omitted.

## Usage

```powershell
.\Invoke-WindowsSecurityAudit.ps1
```

Custom output location:

```powershell
.\Invoke-WindowsSecurityAudit.ps1 -OutputRoot 'C:\Support\SecurityAudits'
```

## Status values

| Status | Meaning |
|---|---|
| `Pass` | Check met the script's baseline |
| `Warning` | Review required; may be acceptable under approved policy |
| `Fail` | Baseline is not met |
| `Unknown` | The script could not produce a trustworthy result |

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Every recorded check passed |
| `1` | Fatal execution or validation error |
| `2` | One or more checks returned Warning, Fail or Unknown |

This is a technical baseline, not a substitute for your organisation's approved policy or risk acceptance.

## Validation

A Windows GitHub Actions workflow parses every `.ps1` file with PowerShell's native parser and runs PSScriptAnalyzer with error-severity findings treated as failures.

## License

MIT License.
