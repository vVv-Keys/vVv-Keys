# Suspicious at.exe Remote Scheduled Task

The Windows `at.exe` utility is a legacy command-line tool used to schedule tasks. While scheduling tasks locally is common for maintenance, `at.exe` can also be used to create or modify scheduled jobs on remote hosts by specifying the remote system name (`\\HOSTNAME`) or using the `/S` flag. Adversaries abuse this capability to execute programs remotely for lateral movement or persistence.

## Why this matters

- Remotely scheduled tasks can execute arbitrary commands or payloads on another system without direct interaction.
- `at.exe` is built into Windows, so its execution does not require external tooling and may blend with legitimate maintenance tasks.
- Many organizations no longer use `at.exe` for routine management; seeing it used to target remote hosts is highly suspicious.

## Detection rationale

Our Sigma rule (`proc_creation_win_at_remote_job.yml`) looks for process creation events where:

- The `Image` (process) ends with `\\at.exe` or `\\AT.exe`.
- The command line references a remote host via a UNC path (`\\hostname`) or uses the `/S` flag to specify the remote system.
- Common scheduling parameters such as `/create`, `/delete`, or other task commands appear.

This combination helps identify attempts to schedule tasks on remote systems using `at.exe`.

## Tactic and technique

- **MITRE ATT&CK tactic:** Lateral Movement / Persistence
- **Technique:** T1053.002 – Scheduled Task/Job: At

## Hunting tips

- Review Sysmon Event ID 1 or Windows Security 4688 events for `at.exe` executions with `/S` or `\\`.
- Correlate the remote host specified in the command line with the host executing the process; unusual pairings may indicate unauthorized access.
- Examine the scheduled task details (e.g., time, command payload) on the target system to understand the adversary’s objective.
- Investigate whether the same command or payload appears across multiple hosts; this may signal automated propagation.

## References

- [Microsoft documentation for `at` command](https://learn.microsoft.com/windows-server/administration/windows-commands/at)
- [MITRE ATT&CK T1053.002](https://attack.mitre.org/techniques/T1053/002/)
- Sigma rule: `proc_creation_win_at_remote_job.yml`
