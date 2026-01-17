# Suspicious Certutil Download or Encode

The Windows utility **certutil.exe** is primarily used to manage certificates, but adversaries often abuse it to download payloads from remote servers or to encode/decode files.  Using `/urlcache` options, an attacker can fetch a file via HTTP/S and drop it to disk; with `/encode` or `/decode`, they can obfuscate payloads to evade detection.

## Why this matters

* Certutil is signed and trusted by Windows, so its execution is less likely to trigger alarms.
* It supports downloading files directly from the internet, which allows attackers to stage payloads without additional tools.
* Encoding or decoding base64 content with certutil helps attackers conceal malicious scripts or binaries.

## Detection rationale

Our Sigma rule (`proc_creation_win_certutil_download_encode.yml`) looks for:

* `certutil.exe` or `certutil` process executions.
* Command lines that include `/urlcache`, `-urlcache`, `/encode`, `-encode`, `/decode`, `-decode`, or remote paths beginning with `http://`, `https://` or `\\\\`.
* Optional flags such as `/f` or `/outfile` specifying the output destination.

This detection maps to MITRE techniques **T1105 – Ingress Tool Transfer** and **T1140 – Deobfuscate/Decode Files or Information**.  Because certutil also has legitimate uses, always validate the context (e.g., which user ran the command and whether the target URL or output path is expected).

## Hunting tips

* Identify endpoints that seldom use certutil; investigations on those endpoints may yield suspicious activity.
* Search for certutil commands fetching files from atypical domains or IP addresses, and cross-reference with threat intelligence feeds.
* Monitor encoded or decoded files saved to unusual directories (e.g., `C:\\Users\\Public` or temporary locations).
* Correlate with network logs to confirm external downloads and to determine if data was subsequently executed.

Through continuous monitoring of certutil usage and by flagging anomalous download or encode operations, defenders can catch early stages of intrusions that rely on native tools.
