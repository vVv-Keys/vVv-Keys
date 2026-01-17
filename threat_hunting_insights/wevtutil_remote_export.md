# Wevtutil Remote Event Log Export

**Technique:** T1005 – Data from Local System / T1078 – Valid Accounts

`wevtutil.exe` is a command‑line utility for managing Windows event logs. Adversaries can abuse it to remotely query or export event logs from a host using the `/r:` switch and commands like `export-log`, `epl`, `qe`, or `query-events`. By exporting logs to a remote location, they can perform reconnaissance or attempt to cover their tracks.

## Detection rationale

Monitor process creation events and look for:

- The process image ending with `wevtutil.exe`.
- Command‑line arguments containing `/r:` or `\\remotehost`, indicating a remote target.
- Command‑line arguments including `export-log`, `epl`, `qe`, or `query-events` to request log data.

These indicators suggest that someone is exporting or querying event logs from a remote system, which is uncommon outside of administrative troubleshooting.

## Sigma rule

The [proc_creation_win_wevtutil_remote_export](https://github.com/vVv-Keys/SIGMA/blob/master/rules/windows/process_creation/proc_creation_win_wevtutil_remote_export.yml) Sigma rule detects remote event log operations via `wevtutil` by matching on the process image and specific command‑line switches.

## Hunting tips

- Determine which user or service initiated the log export and whether they have legitimate administrative reasons.
- Review the specific logs being exported; security or system logs are more sensitive than application logs.
- Cross‑reference with authentication logs to see if the action aligns with remote logon activity or lateral movement.
