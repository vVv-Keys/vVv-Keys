# Suspicious msiexec Remote Installations

**Technique:** T1218.007 – Msiexec Abuse

Microsoft’s `msiexec.exe` is a legitimate tool used to install, modify, or uninstall MSI packages. Attackers abuse it to execute payloads remotely by passing UNC or HTTP/HTTPS paths along with install switches such as `/i`, `/x`, `/package`, or `/quiet`. This allows malware deployment without dropping files to disk.

## Detection rationale

To hunt for suspicious msiexec usage, monitor process creation events where:

- The process image ends with `msiexec.exe`.
- The command line includes remote paths (e.g., `\\server\share\evil.msi`, `http://domain/payload.msi`, or `https://malicious.site/setup.msi`).
- The command line contains installation or uninstallation switches such as `/i`, `/x`, `/package`, `/q`, or `/quiet`.

These patterns suggest the tool is being used to fetch and execute a package from a remote host rather than a local installer.

## Sigma rule

See the [proc_creation_win_msiexec_remote_install](https://github.com/vVv-Keys/SIGMA/blob/master/rules/windows/process_creation/proc_creation_win_msiexec_remote_install.yml) Sigma rule for an example detection implementation. The rule matches on image names and command‑line arguments to identify remote installations and is tagged with `attack.defense_evasion` and `attack.t1218.007`.

## Hunting tips

- Correlate with network logs or proxy data to confirm whether the remote server contacted is trusted or malicious.
- Check subsequent processes launched by the installed MSI (e.g., service creation, PowerShell, rundll32).
- Tune the rule to exclude legitimate software deployment solutions used in your environment.
