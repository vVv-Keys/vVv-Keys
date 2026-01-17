# PsExec Remote Execution

**Technique:** T1569.002 – Service Execution (PsExec)

PsExec from Sysinternals is a legitimate remote administration tool that enables users to run processes on remote Windows systems via SMB. Threat actors often abuse it for lateral movement by providing administrative credentials and executing commands or binaries remotely without interactive logon.

## Detection rationale

Monitor process creation events for evidence of PsExec abuse:

- The process image matches `psexec.exe`, `PsExec.exe`, `psexec64.exe`, or `psexesvc.exe`.
- The command line includes UNC paths like `\\hostname\C$` or `\\target\ADMIN$` specifying a remote host.
- Flags such as `-s`, `-i`, `-d`, `-u`, or `-p` are present, indicating PsExec is running as a service, interacting with the desktop, or supplying credentials.

These characteristics point to PsExec being used to launch remote commands or services.

## Sigma rule

Refer to the [proc_creation_win_psexec_remote_exec](https://github.com/vVv-Keys/SIGMA/blob/master/rules/windows/process_creation/proc_creation_win_psexec_remote_exec.yml) Sigma rule. It detects remote PsExec execution by matching on executable names, UNC paths, and typical flags, and maps the activity to ATT&CK tactics `execution` and `lateral_movement`.

## Hunting tips

- Identify the source system and user context from which PsExec was launched and verify if they have legitimate administrative duties.
- Look for subsequent process launches or service installations on the remote host (e.g., creation of `psexesvc.exe`).
- Correlate with network logs to trace SMB connections and transfers, and combine with authentication logs to spot potential credential misuse.
