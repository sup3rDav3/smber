#!/usr/bin/env python3
"""
SMB Sensitive File Finder
For use during authorized penetration tests only.

Usage:
    python3 smber.py -t 192.168.1.10 -u admin -p Password123
    python3 smber.py -t 192.168.1.10 -u admin -p Password123 --hash <NTLM>
    python3 smber.py -t 192.168.1.10 -u '' -p '' --null-session
    python3 smber.py --targets targets.txt -u admin -p Password123

Dependencies:
    pip install impacket colorama
"""

import argparse
import sys
import os
import re
import logging
from datetime import datetime
from pathlib import PureWindowsPath
from threading import Lock
print_lock = Lock()

try:
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.smb3structs import FILE_READ_DATA
    from impacket import smb
except ImportError:
    print("[-] impacket not found. Install with: pip install impacket")
    sys.exit(1)

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    GREEN  = Fore.GREEN
    RED    = Fore.RED
    YELLOW = Fore.YELLOW
    CYAN   = Fore.CYAN
    RESET  = Style.RESET_ALL
except ImportError:
    GREEN = RED = YELLOW = CYAN = RESET = ""

# ---------------------------------------------------------------------------
# Sensitive file patterns
# ---------------------------------------------------------------------------
SENSITIVE_EXTENSIONS = {
    # Secrets / creds / keys — always high value
    ".env", ".kdbx", ".key", ".pem", ".pfx", ".p12",
    ".rdp", ".vnc",
    # Databases
    ".sql", ".db", ".sqlite", ".mdb", ".accdb",
    # Backups — often contain creds or copies of configs
    ".bak", ".backup", ".old", ".orig",
    # Scripts — may contain hardcoded creds
    ".ps1", ".bat", ".cmd", ".vbs", ".sh",
    # Office docs — only if filenames match sensitive list below
    ".xlsx", ".xls", ".csv",
}

# High-signal extensions that are only flagged if filename also looks sensitive
NOISY_EXTENSIONS = {
    ".config", ".conf", ".cfg", ".ini",
    ".xml", ".json", ".yaml", ".yml", ".toml",
    ".log",
}

SENSITIVE_NOISY_NAMES = {
    "web.config", "appsettings.json", "applicationhost.config",
    "database.yml", "database.yaml", "db.conf", "db.config",
    "wp-config.php", "config.php", "settings.py", "local_settings.py",
    "hibernate.cfg.xml", "persistence.xml",
    "unattend.xml", "sysprep.xml", "autounattend.xml",
    "php.ini", "my.ini", "my.cnf", "postgresql.conf",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "shadow", "passwd",
}

SENSITIVE_FILENAMES = {
    # Credentials / secrets
    "passwords.txt", "password.txt", "creds.txt", "credentials.txt",
    "secrets.txt", "secret.txt", "pass.txt", "logins.txt",
    ".env", "local.env", ".env.local", ".env.production",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "shadow", "passwd",
    # Config files often containing creds
    "web.config", "applicationhost.config", "appsettings.json",
    "database.yml", "database.yaml", "db.conf",
    "wp-config.php", "config.php", "settings.py", "local_settings.py",
    "hibernate.cfg.xml", "persistence.xml",
    # Key / cert files
    "server.key", "private.key", "privkey.pem",
    # Interesting docs
    "credentials.xlsx", "passwords.xlsx", "network diagram.xlsx",
    # Backup / misc
    "ntds.dit", "sam", "system", "security",
    "unattend.xml", "sysprep.xml", "autounattend.xml",
}

# Regex patterns searched inside small text files (<= MAX_CAT_SIZE)
CONTENT_PATTERNS = [
    re.compile(r'password\s*[=:]\s*\S+', re.IGNORECASE),
    re.compile(r'passwd\s*[=:]\s*\S+', re.IGNORECASE),
    re.compile(r'pwd\s*[=:]\s*\S+', re.IGNORECASE),
    re.compile(r'connectionstring\s*[=:]', re.IGNORECASE),
    re.compile(r'(AKIA|ASIA)[A-Z0-9]{16}'),          # AWS access key
    re.compile(r'secret[_\-]?key\s*[=:]\s*\S+', re.IGNORECASE),
    re.compile(r'api[_\-]?key\s*[=:]\s*\S+', re.IGNORECASE),
    re.compile(r'token\s*[=:]\s*[A-Za-z0-9_\-\.]{20,}', re.IGNORECASE),
    # username:password format (e.g. admin:Password1!) — no $ anchor, handles \r\n
    re.compile(r'(?m)^[a-zA-Z0-9_\-\.]{2,32}:[^:\s\r\n]{6,}'),
    # user = value / user: value style
    re.compile(r'\buser(name)?\s*[=:]\s*\S+', re.IGNORECASE),
]

MAX_CAT_SIZE   = 512 * 1024   # only cat files <= 512 KB
MAX_DEPTH      = 6            # max directory recursion depth
SKIP_SHARES    = {"IPC$", "print$", "ADMIN$", "SYSVOL"}   # shares to skip by default
# High-noise OS paths to skip when scanning C$ and ADMIN$
SKIP_PATHS = {
    "windows\\system32",
    "windows\\syswow64",
    "windows\\winsxs",
    "windows\\servicing",
    "windows\\assembly",
    "windows\\microsoft.net",
    "windows\\pla",
    "windows\\schemas",
    "windows\\diagnostics",
    "windows\\logs",
    "windows\\inf",
    "windows\\prefetch",
    "program files\\windows",
    "program files (x86)\\windows",
    "programdata\\microsoft",
}

BINARY_EXTS    = {".exe", ".dll", ".bin", ".so", ".zip", ".gz", ".tar",
                  ".7z", ".rar", ".jpg", ".png", ".gif", ".bmp", ".pdf",
                  ".docx", ".doc", ".xlsx", ".xls"}  # Office: flag but never read

# ---------------------------------------------------------------------------
# Logging / output helpers
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

def info(msg):
    with print_lock: print(f"{CYAN}[*]{RESET} {msg}")
def success(msg):
    with print_lock: print(f"{GREEN}[+]{RESET} {msg}")
def warn(msg):
    with print_lock: print(f"{YELLOW}[!]{RESET} {msg}")
def error(msg):
    with print_lock: print(f"{RED}[-]{RESET} {msg}")

# ---------------------------------------------------------------------------
# SMB helpers
# ---------------------------------------------------------------------------
def connect(host: str, username: str, password: str, domain: str,
            ntlm_hash: str, port: int) -> SMBConnection | None:
    """Return an authenticated SMBConnection or None on failure."""
    lm_hash, nt_hash = "", ""
    if ntlm_hash:
        parts = ntlm_hash.split(":")
        if len(parts) == 2:
            lm_hash, nt_hash = parts
        else:
            nt_hash = parts[0]
            lm_hash = "aad3b435b51404eeaad3b435b51404ee"

    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=10)
        conn.login(username, password, domain, lm_hash, nt_hash)
        dialect = conn.getDialect()
        info(f"Connected to {host}:{port} as {domain}\\{username} (dialect {hex(dialect)})")
        return conn
    except SessionError as e:
        error(f"Authentication failed on {host}: {e}")
        return None
    except Exception as e:
        error(f"Connection error on {host}: {e}")
        return None


def list_shares(conn: SMBConnection) -> list[str]:
    """Return a list of share names."""
    shares = []
    try:
        for s in conn.listShares():
            name = s["shi1_netname"][:-1]  # strip null terminator
            shares.append(name)
    except Exception as e:
        warn(f"Could not list shares: {e}")
    return shares


def check_share_access(conn: SMBConnection, share: str) -> tuple[bool, bool]:
    """Return (readable, writable) for a share."""
    readable = writable = False
    try:
        conn.listPath(share, "*")
        readable = True
    except SessionError:
        pass
    except Exception:
        pass

    if readable:
        test_file = f"__pentest_probe_{os.getpid()}.tmp"
        try:
            fid = conn.createFile(share, test_file)
            conn.closeFile(share, fid)
            conn.deleteFiles(share, test_file)
            writable = True
        except Exception:
            pass

    return readable, writable


def list_path(conn: SMBConnection, share: str, path: str) -> list:
    """List files/dirs under path; returns impacket SharedFile objects."""
    try:
        return conn.listPath(share, path.rstrip("\\") + "\\*")
    except SessionError as e:
        if "STATUS_ACCESS_DENIED" not in str(e):
            log.debug(f"listPath {share}/{path}: {e}")
        return []
    except Exception as e:
        log.debug(f"listPath {share}/{path}: {e}")
        return []


def read_file(conn: SMBConnection, share: str, path: str, max_bytes: int) -> bytes | None:
    """Read up to max_bytes from a remote file using getFile (more reliable)."""
    import io
    buf = io.BytesIO()
    try:
        conn.getFile(share, path, buf.write)
        data = buf.getvalue()
        return data[:max_bytes]
    except SessionError as e:
        log.warning(f"readFile SessionError {share}/{path}: {e}")
        return None
    except Exception as e:
        log.warning(f"readFile Exception {share}/{path}: {type(e).__name__}: {e}")
        return None

# ---------------------------------------------------------------------------
# Core enumeration
# ---------------------------------------------------------------------------
def is_sensitive(filename: str) -> bool:
    name_lower = filename.lower()
    ext = os.path.splitext(name_lower)[1]
    # Always flag high-signal filenames
    if name_lower in SENSITIVE_FILENAMES:
        return True
    # Always flag high-signal extensions
    if ext in SENSITIVE_EXTENSIONS:
        return True
    # Only flag noisy extensions if the filename is also suspicious
    if ext in NOISY_EXTENSIONS:
        return name_lower in SENSITIVE_NOISY_NAMES
    return False


def is_binary_ext(filename: str) -> bool:
    ext = os.path.splitext(filename.lower())[1]
    return ext in BINARY_EXTS


def _process_file(conn, share, remote_path, size, unc, findings, args):
    """Read, grep, and record a single sensitive file."""
    content_preview = None
    matched_patterns = []
    clean_path = remote_path.lstrip("\\")

    # --scan: list files only, skip all content reading
    if not args.scan:
        import io
        buf = io.BytesIO()
        try:
            conn.getFile(share, clean_path, buf.write)
            raw = buf.getvalue()[:MAX_CAT_SIZE]
        except Exception as e:
            log.warning(f"read error {share}/{clean_path}: {e}")
            raw = None

        if raw:
            try:
                encoding = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
                text = raw.decode(encoding, errors="replace")
            except Exception:
                text = None

            if text:
                for pat in CONTENT_PATTERNS:
                    for m in pat.finditer(text):
                        matched_patterns.append(m.group(0)[:120])
                if args.dump:
                    content_preview = text[:args.dump_limit]
        elif args.dump:
            warn(f"  Could not read file: {clean_path}")

    findings.append({
        "host": args.target, "share": share, "path": clean_path,
        "unc": unc, "size": size,
        "patterns": matched_patterns, "preview": content_preview,
    })

    for p in matched_patterns[:10]:
        warn(f"  MATCH  {p}")

    if content_preview:
        with print_lock:
            print(f"\n{'='*60}")
            print(f"  FILE: {unc}")
            print('='*60)
            print(content_preview[:args.dump_limit])
            print('='*60 + "\n")


def walk_share(conn: SMBConnection, share: str, path: str,
               depth: int, findings: list, args):
    if depth > MAX_DEPTH:
        return

    entries = list_path(conn, share, path)
    for entry in entries:
        name = entry.get_longname()
        if name in (".", ".."):
            continue

        remote_path = path.rstrip("\\") + "\\" + name if path else name
        is_dir = entry.is_directory()

        if is_dir:
            if any(skip in remote_path.lower().replace("/", "\\") for skip in SKIP_PATHS):
                log.debug(f"Skipping OS path: {remote_path}")
                continue
            walk_share(conn, share, remote_path, depth + 1, findings, args)
            continue

        if not is_sensitive(name):
            continue

        size = entry.get_filesize()
        unc = f"\\\\{args.target}\\{share}\\{remote_path}"
        success(f"FOUND  {unc}  ({size:,} bytes)")
        _process_file(conn, share, remote_path, size, unc, findings, args)


def enumerate_host(args) -> list:
    conn = connect(args.target, args.username, args.password,
                   args.domain, args.hash, args.port)
    if not conn:
        return []

    shares = list_shares(conn)
    if not shares:
        warn("No shares enumerated (try --null-session or check credentials)")
        return []

    info(f"Shares found: {', '.join(shares)}")

    target_shares = args.shares if args.shares else shares
    findings = []

    for share in target_shares:
        if share.upper() in SKIP_SHARES and not args.include_admin:
            info(f"Skipping {share} (admin share)")
            continue

        readable, writable = check_share_access(conn, share)
        access_str = []
        if readable:  access_str.append(f"{GREEN}READ{RESET}")
        if writable:  access_str.append(f"{YELLOW}WRITE{RESET}")
        if not readable:
            info(f"Share {share}: NO ACCESS")
            continue

        print(f"\n{CYAN}{'─'*60}{RESET}")
        info(f"Share: {share}  [{' | '.join(access_str)}]")
        print(f"{CYAN}{'─'*60}{RESET}")

        walk_share(conn, share, "", 0, findings, args)

    conn.logoff()
    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def write_report(findings: list, outfile: str):
    with open(outfile, "w") as f:
        f.write(f"SMB Sensitive File Report — {datetime.now()}\n")
        f.write("=" * 70 + "\n\n")
        for i, item in enumerate(findings, 1):
            f.write(f"[{i}] {item['unc']}\n")
            f.write(f"    Size   : {item['size']:,} bytes\n")
            if item["patterns"]:
                f.write(f"    Matches: {len(item['patterns'])}\n")
                for p in item["patterns"][:10]:
                    f.write(f"      - {p}\n")
            if item["preview"]:
                f.write(f"    Preview:\n{item['preview'][:500]}\n")
            f.write("\n")
    success(f"Report written to {outfile}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="SMB Sensitive File Finder — authorized pentests only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target
    tg = p.add_mutually_exclusive_group(required=True)
    tg.add_argument("-t",  "--target",  help="Single target IP/hostname")
    tg.add_argument("--targets", metavar="FILE",
                    help="File with one target per line")

    # Auth
    p.add_argument("-u", "--username", default="",    help="Username")
    p.add_argument("-p", "--password", default="",    help="Password")
    p.add_argument("-d", "--domain",   default="",    help="Domain")
    p.add_argument("--hash",           default="",
                   help="NTLM hash (LM:NT or just NT)")
    p.add_argument("--null-session",   action="store_true",
                   help="Attempt unauthenticated null session")

    # Scope
    p.add_argument("--shares",         nargs="+",
                   help="Only enumerate these share names")
    p.add_argument("--include-admin",  action="store_true",
                   help="Also enumerate ADMIN$, IPC$, print$")
    p.add_argument("--port",           type=int, default=445,
                   help="SMB port (default 445)")
    p.add_argument("--max-depth",      type=int, default=MAX_DEPTH,
                   help=f"Max recursion depth (default {MAX_DEPTH})")

    # Output mode (mutually exclusive)
    mode_group = p.add_mutually_exclusive_group()
    mode_group.add_argument("--dump", action="store_true",
                   help="Full mode: find files, grep contents, print file previews")
    mode_group.add_argument("--scan", action="store_true",
                   help="Scan mode: find and list notable files only, no content reading")
    p.add_argument("--dump-limit", type=int, default=2000,
                   help="Max chars to print per file in --dump mode (default 2000)")
    p.add_argument("-o", "--output",
                   help="Write findings report to this file")
    p.add_argument("-v", "--verbose", action="store_true")

    return p.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.null_session:
        args.username = ""
        args.password = ""

    # Collect targets
    targets = []
    if args.targets:
        with open(args.targets) as f:
            targets = [l.strip() for l in f if l.strip()]
    else:
        targets = [args.target]

    all_findings = []
    for host in targets:
        args.target = host
        print(f"\n{'#'*60}")
        info(f"Target: {host}")
        print(f"{'#'*60}")
        all_findings.extend(enumerate_host(args))

    # Summary
    print(f"\n{'='*60}")
    info(f"Total sensitive files found: {len(all_findings)}")
    matched = [f for f in all_findings if f["patterns"]]
    info(f"Files with credential pattern matches: {len(matched)}")
    print('='*60)

    if args.output:
        write_report(all_findings, args.output)


if __name__ == "__main__":
    main()
