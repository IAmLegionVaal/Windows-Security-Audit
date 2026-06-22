# Windows Security Audit

Read-only PowerShell health report for common Windows protection features.

> **Testing note:** This was tested by me to be working. User experience may vary.

## One-click use

1. Download and extract the repository.
2. Double-click `Run-OneClick.bat`.
3. The complete security assessment runs directly—there is no menu and no security setting is changed.
4. Review the exit code and CSV, JSON and HTML reports under `C:\Users\Public\Documents\WindowsSecurityAudits`.

Included: `Invoke-WindowsSecurityAudit.ps1`

## PowerShell usage

```powershell
.\Invoke-WindowsSecurityAudit.ps1
```

The script checks built-in antivirus, firewall profiles, BitLocker, TPM readiness, Secure Boot, SMB1, UAC, Remote Desktop exposure and pending restart state. Results use `Pass`, `Warning`, `Fail` and `Unknown`.

Exit code `0` means no failed checks, `1` means a fatal error and `2` means one or more checks failed.

Requirements differ between devices and organisations. Review the report against your approved standards.

MIT License.
