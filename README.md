# smber 🔍

**Authorized penetration testing tool for SMB share enumeration and sensitive file discovery.**

> ⚠️ **Legal Disclaimer:** This tool is intended for use only on systems you own or have explicit written authorization to test. Unauthorized use is illegal and unethical. Always operate within the scope of your engagement.

---

## Overview

`smber` automates the manual process of enumerating SMB shares, identifying sensitive files, and extracting credential material during authorized internal penetration tests. It connects to a target over SMB, lists accessible shares, recursively walks directory trees, flags high-value files by name and extension, and optionally reads file contents to grep for credential patterns.

---

## Features

- **Share enumeration** — lists all shares and tests READ/WRITE access per share
- **Two-tier file detection** — high-signal files (`.env`, `.kdbx`, `.pem`, `id_rsa`, `ntds.dit`, etc.) always flagged; noisy extensions (`.xml`, `.json`) only flagged when filename is suspicious (e.g. `web.config`, `appsettings.json`)
- **Credential grepping** — regex patterns for `password=`, `user:pass`, AWS keys, API tokens, connection strings
- **UTF-16 support** — correctly decodes Windows-encoded files
- **Two output modes** — `--scan` for fast recon, `--dump` for full content extraction
- **Auth flexibility** — username/password, NTLM pass-the-hash, or null sessions
- **Multi-target support** — accepts a file of hosts for subnet sweeps
- **OS path exclusion** — skips noisy Windows system paths (`System32`, `WinSxS`, etc.) on `C$`

---

## Installation

```bash
pip install impacket colorama
```

---

## Usage

```bash
python3 smber.py -t <target> -u <username> -p <password> -d <domain> [--scan | --dump]
```

### Authentication Options

```bash
# Username and password
python3 smber.py -t 192.168.1.10 -u jsmith -p 'Password1!' -d corp.local --scan

# Pass-the-hash (LM:NT or just NT)
python3 smber.py -t 192.168.1.10 -u administrator --hash aad3b435b51404ee:NTHASHHERE -d corp.local --dump

# Null session
python3 smber.py -t 192.168.1.10 --null-session --scan
```

### Output Modes

```bash
# --scan: fast recon — lists notable files, no content reading
python3 smber.py -t 192.168.1.10 -u jsmith -p 'Password1!' -d corp.local --scan

# --dump: full extraction — reads files, greps credentials, prints previews
python3 smber.py -t 192.168.1.10 -u jsmith -p 'Password1!' -d corp.local --dump
```

### Targeting Specific Shares

```bash
# Only scan specific shares
python3 smber.py -t 192.168.1.10 -u jsmith -p 'Password1!' -d corp.local --dump --shares SYSVOL TestShare

# Include admin shares (ADMIN$, IPC$, C$)
python3 smber.py -t 192.168.1.10 -u administrator -p 'Password1!' -d corp.local --dump --include-admin
```

### Multiple Targets

```bash
# Sweep a list of hosts
python3 smber.py --targets hosts.txt -u jsmith -p 'Password1!' -d corp.local --scan -o /tmp/findings.txt
```

### Save Report

```bash
python3 smber.py -t 192.168.1.10 -u jsmith -p 'Password1!' -d corp.local --dump -o report.txt
```

---

## Recommended Workflow

```bash
# Step 1 — fast recon across all shares
python3 smber.py -t 192.168.1.10 -u jsmith -p 'Password1!' -d corp.local --scan

# Step 2 — full dump on interesting shares
python3 smber.py -t 192.168.1.10 -u jsmith -p 'Password1!' -d corp.local --dump --shares TestShare NETLOGON

# Step 3 — save findings to report
python3 smber.py -t 192.168.1.10 -u jsmith -p 'Password1!' -d corp.local --dump -o /tmp/report.txt
```

---

## Example Output

### `--scan` mode
```
[*] Share: TestShare  [READ | WRITE]
[+] FOUND  \\192.168.1.10\TestShare\.env  (54 bytes)
[+] FOUND  \\192.168.1.10\TestShare\id_rsa  (1,675 bytes)
[+] FOUND  \\192.168.1.10\TestShare\web.config  (2,048 bytes)
```

### `--dump` mode
```
[*] Share: TestShare  [READ | WRITE]
[+] FOUND  \\192.168.1.10\TestShare\web.config  (2,048 bytes)
[!]   MATCH  password=Sup3rS3cr3t!
============================================================
  FILE: \\192.168.1.10\TestShare\web.config
============================================================
<connectionStrings>
  <add name="Default" connectionString="Server=db01;Password=Sup3rS3cr3t!" />
</connectionStrings>
============================================================
```

---

## Detected File Types

| Category | Examples |
|---|---|
| Secrets & keys | `.env`, `.kdbx`, `.pem`, `.pfx`, `.p12`, `id_rsa` |
| Databases | `.sql`, `.db`, `.sqlite`, `.mdb`, `.accdb` |
| Backups | `.bak`, `.backup`, `.old`, `.orig` |
| Scripts | `.ps1`, `.bat`, `.cmd`, `.vbs`, `.sh` |
| Config files | `web.config`, `appsettings.json`, `wp-config.php`, `unattend.xml` |
| Sensitive docs | `passwords.txt`, `credentials.xlsx`, `SAM`, `SYSTEM` |
| RDP/VNC | `.rdp`, `.vnc` |

---

## Credential Patterns Detected

- `password=`, `passwd=`, `pwd=` key-value pairs
- `username:password` colon-separated credential lines
- AWS access keys (`AKIA...`, `ASIA...`)
- API keys and tokens
- Connection strings

---

## Arguments

| Argument | Description |
|---|---|
| `-t`, `--target` | Single target IP or hostname |
| `--targets FILE` | File with one target per line |
| `-u`, `--username` | Username |
| `-p`, `--password` | Password |
| `-d`, `--domain` | Domain |
| `--hash` | NTLM hash (`LM:NT` or just `NT`) |
| `--null-session` | Attempt unauthenticated null session |
| `--scan` | Fast recon — list files only, no content reading |
| `--dump` | Full mode — read files, grep creds, print previews |
| `--shares` | Only enumerate specified share names |
| `--include-admin` | Also enumerate `ADMIN$`, `IPC$`, `C$` |
| `--port` | SMB port (default `445`) |
| `--max-depth` | Max directory recursion depth (default `6`) |
| `--dump-limit` | Max chars printed per file in `--dump` mode (default `2000`) |
| `-o`, `--output` | Write findings report to file |
| `-v`, `--verbose` | Enable debug logging |

---

## Dependencies

- [impacket](https://github.com/fortra/impacket)
- [colorama](https://pypi.org/project/colorama/)

---

## Legal

This tool is provided for authorized security testing and educational purposes only. The author assumes no liability for misuse. Always obtain written authorization before testing any system you do not own.
