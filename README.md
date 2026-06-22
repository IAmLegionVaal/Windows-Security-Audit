# Windows Security Audit

Read-only PowerShell health report for common Windows protection features.

> **Testing note:** This was tested by me to be working. User experience may vary.

## Included

`Invoke-WindowsSecurityAudit.ps1`

## Usage

```powershell
.\Invoke-WindowsSecurityAudit.ps1
```

CSV, JSON and HTML reports are saved under:

```text
C:\Users\Public\Documents\WindowsSecurityAudits
```

The script checks built-in protection, encryption, platform and hardening status without changing settings. Results use `Pass`, `Warning`, `Fail` and `Unknown`.

Exit code `0` means no failed checks, `1` means a fatal error and `2` means one or more checks failed.

## Disclaimer

Use this project at your own risk. Requirements differ between devices and organisations. Review the report against your approved standards.

## License

MIT
