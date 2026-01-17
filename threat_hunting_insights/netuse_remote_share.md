# Suspicious net use Remote Share Mapping

Attackers often leverage the **net use** command to map network shares on remote hosts, either to stage tools, harvest credentials, or exfiltrate data.  By mapping a drive letter to a UNC path (e.g., `\\server\share`) they gain convenient access to remote filesystems with minimal logging.  Observing unusual or unexpected net use activity can highlight potential lateral movement or data staging.

## Why this matters

* The **net use** command is built into Windows and commonly used by administrators, making it an attractive dual‑use tool.
* Mapping remote shares allows attackers to transfer payloads, collect data, or pivot further into the network.
* Attackers may supply user credentials (`/user:domain\account` and a password) or flag shares to persist across reboots (`/persistent:yes`).

## Detection rationale

Our corresponding Sigma rule (`proc_creation_win_netuse_remote_share.yml`) flags suspicious invocations of `net.exe` or `net1.exe` when the command line:

* Includes the `use` subcommand and a remote UNC path (`\\host\share`).
* Optionally contains credentials or persistence flags such as `/user:`, `/persistent:`, or an asterisk (`*`) for prompting.

This rule aligns with MITRE ATT&CK technique **T1021.002 – SMB/Windows Admin Shares**.  Investigate process creation logs where these conditions are met, especially on endpoints that rarely map network shares.

## Hunting tips

* Pivot from process creation events to network connections on port 445 (SMB) at the same timeframe to confirm share usage.
* Review the source and destination hosts involved and determine if the mapping is legitimate (e.g., authorised file servers vs. peer workstations).
* Look for **net use** commands mapping hidden shares (e.g., `\\host\c$`) or administrative shares.
* Correlate with authentication logs to see if new credentials or accounts were used.

By monitoring net use activity and applying contextual analysis, you can surface potential lateral movement and unauthorised data staging within your environment.
