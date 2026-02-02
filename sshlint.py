#!/usr/bin/env python3
"""sshlint - SSH Client Configuration Security Linter.

Static analysis of ~/.ssh/config for dangerous settings, weak crypto,
credential exposure risks, and misconfigurations. Unlike ssh-audit which
tests protocol-level crypto by connecting to servers, sshlint analyzes
the config file itself without any network access.

Zero dependencies. Stdlib only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

__version__ = "0.1.0"

# ── Severity ────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> int:
        return {
            "CRITICAL": 25, "HIGH": 15, "MEDIUM": 8,
            "LOW": 3, "INFO": 0,
        }[self.value]


# ── Finding ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    file: str
    line: int = 0
    host: str = ""
    evidence: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "file": self.file,
        }
        if self.line:
            d["line"] = self.line
        if self.host:
            d["host"] = self.host
        if self.evidence:
            d["evidence"] = self.evidence
        if self.fix:
            d["fix"] = self.fix
        return d


# ── SSH Config Parser ───────────────────────────────────────────────

@dataclass
class HostBlock:
    """Represents a Host or Match block in ssh_config."""
    patterns: List[str]
    line_start: int
    line_end: int = 0
    options: Dict[str, Tuple[str, int]] = field(default_factory=dict)
    # options maps lowercase key -> (value, line_number)

    @property
    def is_wildcard(self) -> bool:
        return any(p in ("*", "* !*") or "*" in p for p in self.patterns)

    @property
    def display_name(self) -> str:
        return " ".join(self.patterns)


def parse_ssh_config(content: str) -> Tuple[List[HostBlock], HostBlock]:
    """Parse ssh_config into host blocks. Returns (blocks, global_block)."""
    lines = content.split("\n")
    blocks: List[HostBlock] = []
    # Global block for options before any Host/Match
    global_block = HostBlock(patterns=["*"], line_start=1)
    current = global_block

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip empty and comments
        if not stripped or stripped.startswith("#"):
            continue

        # Host directive
        host_match = re.match(r'^Host\s+(.+)', stripped, re.I)
        if host_match:
            if current is not global_block:
                current.line_end = line_num - 1
            patterns = host_match.group(1).split()
            current = HostBlock(patterns=patterns, line_start=line_num)
            blocks.append(current)
            continue

        # Match directive
        match_match = re.match(r'^Match\s+(.+)', stripped, re.I)
        if match_match:
            if current is not global_block:
                current.line_end = line_num - 1
            current = HostBlock(patterns=[f"Match {match_match.group(1)}"],
                                line_start=line_num)
            blocks.append(current)
            continue

        # Key-value option
        kv_match = re.match(r'^(\w+)\s*[=\s]\s*(.*)', stripped)
        if kv_match:
            key = kv_match.group(1).lower()
            value = kv_match.group(2).strip().strip('"')
            current.options[key] = (value, line_num)

    if current is not global_block and not current.line_end:
        current.line_end = len(lines)
    global_block.line_end = len(lines)

    return blocks, global_block


# ── Crypto Knowledge Base ───────────────────────────────────────────

# Weak/deprecated ciphers
WEAK_CIPHERS: Set[str] = {
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "arcfour", "arcfour128", "arcfour256",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "rijndael-cbc@lysator.liu.se",
}

# Weak MACs
WEAK_MACS: Set[str] = {
    "hmac-md5", "hmac-md5-96",
    "hmac-sha1", "hmac-sha1-96",
    "hmac-ripemd160", "hmac-ripemd160@openssh.com",
    "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
    "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
}

# Weak key exchange algorithms
WEAK_KEX: Set[str] = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}

# Recommended strong ciphers
STRONG_CIPHERS: Set[str] = {
    "chacha20-poly1305@openssh.com",
    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
    "aes128-ctr", "aes192-ctr", "aes256-ctr",
}

# Recommended strong MACs
STRONG_MACS: Set[str] = {
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256", "hmac-sha2-512",
}

# Recommended strong KEX
STRONG_KEX: Set[str] = {
    "curve25519-sha256", "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
    "sntrup761x25519-sha512@openssh.com",
}

# Recommended host key algorithms
STRONG_HOSTKEY: Set[str] = {
    "ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com",
    "sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com",
    "rsa-sha2-512", "rsa-sha2-512-cert-v01@openssh.com",
    "rsa-sha2-256", "rsa-sha2-256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
}

WEAK_HOSTKEY: Set[str] = {
    "ssh-rsa", "ssh-dss",
}


# ── Scan Result ─────────────────────────────────────────────────────

@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    host_blocks: int = 0

    @property
    def risk_score(self) -> int:
        score = sum(f.severity.score for f in self.findings)
        return min(score, 100)

    @property
    def grade(self) -> str:
        s = self.risk_score
        if s == 0:
            return "A+"
        elif s <= 10:
            return "A"
        elif s <= 20:
            return "B"
        elif s <= 35:
            return "C"
        elif s <= 50:
            return "D"
        else:
            return "F"

    @property
    def risk_label(self) -> str:
        s = self.risk_score
        if s == 0:
            return "SAFE"
        elif s <= 20:
            return "LOW"
        elif s <= 50:
            return "MODERATE"
        elif s <= 75:
            return "HIGH"
        else:
            return "CRITICAL"


# ── Rules ───────────────────────────────────────────────────────────

def _truncate(text: str, maxlen: int = 120) -> str:
    text = text.strip()
    return text[:maxlen - 3] + "..." if len(text) > maxlen else text


def _check_block(block: HostBlock, filepath: str, result: ScanResult) -> None:
    """Run all rules against a single Host/Match block."""
    host = block.display_name
    opts = block.options

    # SL001: StrictHostKeyChecking disabled
    if "stricthostkeychecking" in opts:
        val, ln = opts["stricthostkeychecking"]
        if val.lower() == "no":
            sev = Severity.CRITICAL if block.is_wildcard else Severity.HIGH
            result.findings.append(Finding(
                rule_id="SL001",
                severity=sev,
                message="StrictHostKeyChecking disabled — vulnerable to MITM attacks",
                file=filepath, line=ln, host=host,
                evidence=f"StrictHostKeyChecking {val}",
                fix="Remove this setting or set to 'ask' or 'accept-new'",
            ))
        elif val.lower() == "accept-new":
            result.findings.append(Finding(
                rule_id="SL001",
                severity=Severity.LOW,
                message="StrictHostKeyChecking set to accept-new — trusts first connection",
                file=filepath, line=ln, host=host,
                evidence=f"StrictHostKeyChecking {val}",
                fix="Consider 'yes' for high-security hosts (requires manual key management)",
            ))

    # SL002: ForwardAgent enabled
    if "forwardagent" in opts:
        val, ln = opts["forwardagent"]
        if val.lower() == "yes":
            sev = Severity.HIGH if block.is_wildcard else Severity.MEDIUM
            result.findings.append(Finding(
                rule_id="SL002",
                severity=sev,
                message="ForwardAgent enabled — compromised hosts can use your SSH keys",
                file=filepath, line=ln, host=host,
                evidence=f"ForwardAgent {val}",
                fix="Disable ForwardAgent or use ProxyJump instead for hopping",
            ))

    # SL003: PermitLocalCommand enabled
    if "permitlocalcommand" in opts:
        val, ln = opts["permitlocalcommand"]
        if val.lower() == "yes":
            result.findings.append(Finding(
                rule_id="SL003",
                severity=Severity.MEDIUM,
                message="PermitLocalCommand enabled — allows command execution via LocalCommand",
                file=filepath, line=ln, host=host,
                evidence=f"PermitLocalCommand {val}",
                fix="Disable unless specifically required for this host",
            ))

    # SL004: UserKnownHostsFile set to /dev/null
    if "userknownhostsfile" in opts:
        val, ln = opts["userknownhostsfile"]
        if "/dev/null" in val:
            sev = Severity.CRITICAL if block.is_wildcard else Severity.HIGH
            result.findings.append(Finding(
                rule_id="SL004",
                severity=sev,
                message="UserKnownHostsFile set to /dev/null — host key verification disabled",
                file=filepath, line=ln, host=host,
                evidence=f"UserKnownHostsFile {val}",
                fix="Remove this setting to use default known_hosts file",
            ))

    # SL005: Weak ciphers
    if "ciphers" in opts:
        val, ln = opts["ciphers"]
        specified = {c.strip().lower() for c in val.split(",")}
        # Handle +append syntax
        if val.startswith("+"):
            specified = {c.strip().lower().lstrip("+") for c in val.split(",")}
        weak_found = specified & {c.lower() for c in WEAK_CIPHERS}
        if weak_found:
            result.findings.append(Finding(
                rule_id="SL005",
                severity=Severity.HIGH,
                message=f"Weak cipher(s) configured: {', '.join(sorted(weak_found))}",
                file=filepath, line=ln, host=host,
                evidence=f"Ciphers {val}",
                fix=f"Use only strong ciphers: {', '.join(sorted(STRONG_CIPHERS)[:4])}",
            ))

    # SL006: Weak MACs
    if "macs" in opts:
        val, ln = opts["macs"]
        specified = {m.strip().lower() for m in val.split(",")}
        if val.startswith("+"):
            specified = {m.strip().lower().lstrip("+") for m in val.split(",")}
        weak_found = specified & {m.lower() for m in WEAK_MACS}
        if weak_found:
            result.findings.append(Finding(
                rule_id="SL006",
                severity=Severity.HIGH,
                message=f"Weak MAC(s) configured: {', '.join(sorted(weak_found))}",
                file=filepath, line=ln, host=host,
                evidence=f"MACs {val}",
                fix=f"Use only strong MACs: {', '.join(sorted(STRONG_MACS)[:3])}",
            ))

    # SL007: Weak key exchange algorithms
    if "kexalgorithms" in opts:
        val, ln = opts["kexalgorithms"]
        specified = {k.strip().lower() for k in val.split(",")}
        if val.startswith("+"):
            specified = {k.strip().lower().lstrip("+") for k in val.split(",")}
        weak_found = specified & {k.lower() for k in WEAK_KEX}
        if weak_found:
            result.findings.append(Finding(
                rule_id="SL007",
                severity=Severity.HIGH,
                message=f"Weak key exchange algorithm(s): {', '.join(sorted(weak_found))}",
                file=filepath, line=ln, host=host,
                evidence=f"KexAlgorithms {val}",
                fix=f"Use only strong KEX: {', '.join(sorted(STRONG_KEX)[:3])}",
            ))

    # SL008: Weak host key algorithms
    if "hostkeyalgorithms" in opts:
        val, ln = opts["hostkeyalgorithms"]
        specified = {h.strip().lower() for h in val.split(",")}
        if val.startswith("+"):
            specified = {h.strip().lower().lstrip("+") for h in val.split(",")}
        weak_found = specified & {h.lower() for h in WEAK_HOSTKEY}
        if weak_found:
            result.findings.append(Finding(
                rule_id="SL008",
                severity=Severity.MEDIUM,
                message=f"Weak host key algorithm(s): {', '.join(sorted(weak_found))}",
                file=filepath, line=ln, host=host,
                evidence=f"HostKeyAlgorithms {val}",
                fix="Use ssh-ed25519 or rsa-sha2-512",
            ))

    # SL009: ProxyCommand with potential shell injection
    if "proxycommand" in opts:
        val, ln = opts["proxycommand"]
        # Check for risky patterns in ProxyCommand
        risky_patterns = [
            (re.compile(r'curl\b.*\|\s*(ba)?sh', re.I), "download-and-execute in ProxyCommand"),
            (re.compile(r'wget\b.*\|\s*(ba)?sh', re.I), "download-and-execute in ProxyCommand"),
            (re.compile(r'\beval\b', re.I), "eval in ProxyCommand"),
            (re.compile(r'\$\(.*\)', re.I), "command substitution in ProxyCommand"),
            (re.compile(r'`.*`', re.I), "backtick execution in ProxyCommand"),
        ]
        for pat, desc in risky_patterns:
            if pat.search(val):
                result.findings.append(Finding(
                    rule_id="SL009",
                    severity=Severity.HIGH,
                    message=f"Risky ProxyCommand: {desc}",
                    file=filepath, line=ln, host=host,
                    evidence=f"ProxyCommand {_truncate(val)}",
                    fix="Use ProxyJump or a simple nc/socat proxy instead",
                ))
                break

    # SL010: Tunneling enabled
    if "tunnel" in opts:
        val, ln = opts["tunnel"]
        if val.lower() in ("yes", "point-to-point", "ethernet"):
            result.findings.append(Finding(
                rule_id="SL010",
                severity=Severity.MEDIUM,
                message="Tunnel enabled — creates a VPN-like network tunnel",
                file=filepath, line=ln, host=host,
                evidence=f"Tunnel {val}",
                fix="Disable unless you specifically need tun/tap tunneling",
            ))

    # SL011: Password authentication fallback
    if "passwordauthentication" in opts:
        val, ln = opts["passwordauthentication"]
        if val.lower() == "yes":
            result.findings.append(Finding(
                rule_id="SL011",
                severity=Severity.LOW,
                message="PasswordAuthentication explicitly enabled",
                file=filepath, line=ln, host=host,
                evidence=f"PasswordAuthentication {val}",
                fix="Use key-based authentication instead",
            ))

    # Prefer PreferredAuthentications
    if "preferredauthentications" in opts:
        val, ln = opts["preferredauthentications"]
        methods = [m.strip().lower() for m in val.split(",")]
        if "password" in methods and methods.index("password") == 0:
            result.findings.append(Finding(
                rule_id="SL011",
                severity=Severity.MEDIUM,
                message="Password authentication is the first preferred method",
                file=filepath, line=ln, host=host,
                evidence=f"PreferredAuthentications {val}",
                fix="Put publickey first: PreferredAuthentications publickey,password",
            ))

    # SL012: LocalForward / RemoteForward / DynamicForward
    for fwd_key, fwd_desc in [
        ("localforward", "LocalForward"),
        ("remoteforward", "RemoteForward"),
        ("dynamicforward", "DynamicForward"),
    ]:
        if fwd_key in opts:
            val, ln = opts[fwd_key]
            sev = Severity.INFO
            # Remote forward is more risky
            if fwd_key == "remoteforward":
                sev = Severity.LOW
            # Forwarding to sensitive ports
            sensitive_ports = {"22", "3306", "5432", "6379", "27017", "9200", "2379"}
            for port in sensitive_ports:
                if f":{port}" in val or val.startswith(port + " ") or val.startswith(port + ":"):
                    sev = Severity.MEDIUM
                    break
            result.findings.append(Finding(
                rule_id="SL012",
                severity=sev,
                message=f"{fwd_desc} configured — persistent port forwarding",
                file=filepath, line=ln, host=host,
                evidence=f"{fwd_desc} {_truncate(val)}",
                fix="Prefer on-demand forwarding with -L/-R flags instead of config",
            ))

    # SL013: Wildcard host with dangerous settings
    if block.is_wildcard:
        dangerous_in_wildcard = {
            "forwardagent": "ForwardAgent",
            "forwardx11": "ForwardX11",
            "permitlocalcommand": "PermitLocalCommand",
        }
        for key, display in dangerous_in_wildcard.items():
            if key in opts:
                val, _ = opts[key]
                if val.lower() == "yes":
                    # Already caught by specific rules, but flag the wildcard context
                    pass  # Handled by SL002, SL003 with elevated severity

    # SL014: ForwardX11 enabled
    if "forwardx11" in opts:
        val, ln = opts["forwardx11"]
        if val.lower() == "yes":
            sev = Severity.MEDIUM if block.is_wildcard else Severity.LOW
            trusted = opts.get("forwardx11trusted", ("no", 0))
            if trusted[0].lower() == "yes":
                sev = Severity.HIGH if block.is_wildcard else Severity.MEDIUM
            result.findings.append(Finding(
                rule_id="SL014",
                severity=sev,
                message="X11 forwarding enabled — remote apps can access your display"
                + (" (TRUSTED — full display access)" if trusted[0].lower() == "yes" else ""),
                file=filepath, line=ln, host=host,
                evidence=f"ForwardX11 {val}" + (f", ForwardX11Trusted {trusted[0]}" if trusted[0].lower() == "yes" else ""),
                fix="Disable ForwardX11 unless needed; never use ForwardX11Trusted yes",
            ))

    # SL015: LogLevel set to QUIET (hides security events)
    if "loglevel" in opts:
        val, ln = opts["loglevel"]
        if val.lower() == "quiet":
            result.findings.append(Finding(
                rule_id="SL015",
                severity=Severity.LOW,
                message="LogLevel set to QUIET — connection errors and warnings hidden",
                file=filepath, line=ln, host=host,
                evidence=f"LogLevel {val}",
                fix="Use INFO or VERBOSE for better security visibility",
            ))

    # SL016: BatchMode yes (suppresses all prompts)
    if "batchmode" in opts:
        val, ln = opts["batchmode"]
        if val.lower() == "yes" and block.is_wildcard:
            result.findings.append(Finding(
                rule_id="SL016",
                severity=Severity.LOW,
                message="BatchMode enabled globally — all interactive prompts suppressed",
                file=filepath, line=ln, host=host,
                evidence=f"BatchMode {val}",
                fix="Only enable BatchMode for specific automation hosts",
            ))


def _check_global(global_block: HostBlock, filepath: str, result: ScanResult) -> None:
    """Check global (pre-Host) settings."""
    _check_block(global_block, filepath, result)


def _check_include(content: str, filepath: str, result: ScanResult) -> None:
    """SL017: Check Include directives for suspicious paths."""
    for line_num, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        inc_match = re.match(r'^Include\s+(.+)', stripped, re.I)
        if inc_match:
            inc_path = inc_match.group(1).strip().strip('"')
            # Flag includes from outside ~/.ssh/
            suspicious = False
            if inc_path.startswith("/tmp") or inc_path.startswith("/var/tmp"):
                suspicious = True
                reason = "temp directory"
            elif inc_path.startswith("/dev/"):
                suspicious = True
                reason = "device path"
            elif "/../" in inc_path or inc_path.startswith("../"):
                suspicious = True
                reason = "path traversal"

            if suspicious:
                result.findings.append(Finding(
                    rule_id="SL017",
                    severity=Severity.HIGH,
                    message=f"Include from suspicious path ({reason})",
                    file=filepath, line=line_num,
                    evidence=f"Include {inc_path}",
                    fix="Only include files from ~/.ssh/ or /etc/ssh/",
                ))


def _check_file_permissions(config_path: Path, result: ScanResult) -> None:
    """SL018: Check SSH config and key file permissions."""
    filepath = str(config_path)

    try:
        st = config_path.stat()
    except (OSError, PermissionError):
        return

    mode = st.st_mode
    # Config should not be world-readable
    if mode & stat.S_IROTH:
        result.findings.append(Finding(
            rule_id="SL018",
            severity=Severity.MEDIUM,
            message="SSH config is world-readable",
            file=filepath,
            evidence=f"Permissions: {oct(mode & 0o777)}",
            fix="Run: chmod 600 " + filepath,
        ))
    # Group readable
    if mode & stat.S_IRGRP:
        result.findings.append(Finding(
            rule_id="SL018",
            severity=Severity.LOW,
            message="SSH config is group-readable",
            file=filepath,
            evidence=f"Permissions: {oct(mode & 0o777)}",
            fix="Run: chmod 600 " + filepath,
        ))


def _check_key_permissions(ssh_dir: Path, result: ScanResult) -> None:
    """SL019: Check SSH private key file permissions."""
    if not ssh_dir.is_dir():
        return

    # Common private key filenames
    key_patterns = [
        "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
        "id_ed25519_sk", "id_ecdsa_sk",
    ]
    key_names = set(key_patterns)

    for item in ssh_dir.iterdir():
        if not item.is_file():
            continue
        # Check known key files or files without .pub extension that look like keys
        is_key = item.name in key_names
        if not is_key and not item.name.endswith(".pub") and item.name.startswith("id_"):
            is_key = True
        if not is_key:
            # Check if file content starts with a private key header
            try:
                with open(item, "rb") as f:
                    header = f.read(40)
                if b"PRIVATE KEY" in header:
                    is_key = True
            except (OSError, PermissionError):
                continue

        if not is_key:
            continue

        try:
            st = item.stat()
        except (OSError, PermissionError):
            continue

        mode = st.st_mode & 0o777
        if mode & 0o077:  # Any group or other permissions
            sev = Severity.CRITICAL if mode & stat.S_IROTH else Severity.HIGH
            result.findings.append(Finding(
                rule_id="SL019",
                severity=sev,
                message=f"Private key has excessive permissions",
                file=str(item),
                evidence=f"Permissions: {oct(mode)} (should be 0o600)",
                fix=f"Run: chmod 600 {item}",
            ))

    # Check known_hosts permissions
    known_hosts = ssh_dir / "known_hosts"
    if known_hosts.exists():
        try:
            st = known_hosts.stat()
            mode = st.st_mode & 0o777
            if mode & stat.S_IWOTH:
                result.findings.append(Finding(
                    rule_id="SL019",
                    severity=Severity.MEDIUM,
                    message="known_hosts is world-writable — could be tampered with",
                    file=str(known_hosts),
                    evidence=f"Permissions: {oct(mode)}",
                    fix=f"Run: chmod 644 {known_hosts}",
                ))
        except (OSError, PermissionError):
            pass


def _check_identity_files(blocks: List[HostBlock], global_block: HostBlock,
                          filepath: str, result: ScanResult) -> None:
    """SL020: Check IdentityFile references."""
    all_blocks = [global_block] + blocks
    for block in all_blocks:
        if "identityfile" in block.options:
            val, ln = block.options["identityfile"]
            expanded = os.path.expanduser(val)

            # Check for DSA keys (deprecated since OpenSSH 7.0)
            if "dsa" in val.lower():
                result.findings.append(Finding(
                    rule_id="SL020",
                    severity=Severity.HIGH,
                    message="DSA key referenced — deprecated since OpenSSH 7.0",
                    file=filepath, line=ln, host=block.display_name,
                    evidence=f"IdentityFile {val}",
                    fix="Generate an Ed25519 key: ssh-keygen -t ed25519",
                ))

            # Check if key file is outside ~/.ssh/
            if not val.startswith("~/.ssh/") and not val.startswith("%d/.ssh/"):
                # Might be intentional, but flag it
                if val.startswith("/tmp") or val.startswith("/var/tmp"):
                    result.findings.append(Finding(
                        rule_id="SL020",
                        severity=Severity.HIGH,
                        message="IdentityFile in temp directory — key could be stolen",
                        file=filepath, line=ln, host=block.display_name,
                        evidence=f"IdentityFile {val}",
                        fix="Move key to ~/.ssh/ with proper permissions",
                    ))


def _check_deprecated(blocks: List[HostBlock], global_block: HostBlock,
                      filepath: str, result: ScanResult) -> None:
    """SL021: Check for deprecated or removed options."""
    deprecated_opts = {
        "protocol": ("Protocol", "Removed in OpenSSH 7.6; only SSH-2 is supported"),
        "rhostsrsaauthentication": ("RhostsRSAAuthentication", "Removed — insecure"),
        "rsaauthentication": ("RSAAuthentication", "Removed in OpenSSH 7.6"),
        "useroaming": ("UseRoaming", "Removed — CVE-2016-0777 vulnerability"),
        "fallbacktorsh": ("FallBackToRsh", "Removed — rsh is insecure"),
        "usersh": ("UseRsh", "Removed — rsh is insecure"),
        "compressionlevel": ("CompressionLevel", "Removed — only zlib compression supported"),
    }

    all_blocks = [global_block] + blocks
    for block in all_blocks:
        for key, (display, reason) in deprecated_opts.items():
            if key in block.options:
                _, ln = block.options[key]
                result.findings.append(Finding(
                    rule_id="SL021",
                    severity=Severity.MEDIUM,
                    message=f"Deprecated option: {display} — {reason}",
                    file=filepath, line=ln, host=block.display_name,
                    evidence=f"{display}",
                    fix=f"Remove {display} from config",
                ))

    # Special check for Protocol 1
    all_blocks2 = [global_block] + blocks
    for block in all_blocks2:
        if "protocol" in block.options:
            val, ln = block.options["protocol"]
            if "1" in val:
                result.findings.append(Finding(
                    rule_id="SL021",
                    severity=Severity.CRITICAL,
                    message="SSH Protocol 1 specified — critically insecure",
                    file=filepath, line=ln, host=block.display_name,
                    evidence=f"Protocol {val}",
                    fix="Remove Protocol option entirely (SSH-2 is the only option)",
                ))


def _check_connection_sharing(blocks: List[HostBlock], global_block: HostBlock,
                               filepath: str, result: ScanResult) -> None:
    """SL022: Check ControlMaster/ControlPath for security."""
    all_blocks = [global_block] + blocks
    for block in all_blocks:
        if "controlpath" in block.options:
            val, ln = block.options["controlpath"]
            # Socket in world-writable directory
            if val.startswith("/tmp/") or val.startswith("/var/tmp/"):
                result.findings.append(Finding(
                    rule_id="SL022",
                    severity=Severity.MEDIUM,
                    message="ControlPath socket in world-writable directory",
                    file=filepath, line=ln, host=block.display_name,
                    evidence=f"ControlPath {val}",
                    fix="Use a user-owned directory: ControlPath ~/.ssh/sockets/%r@%h:%p",
                ))
            # Predictable socket name (no %r, %h, %p)
            if "%r" not in val and "%h" not in val and "%C" not in val:
                result.findings.append(Finding(
                    rule_id="SL022",
                    severity=Severity.LOW,
                    message="ControlPath uses predictable socket name — could be hijacked",
                    file=filepath, line=ln, host=block.display_name,
                    evidence=f"ControlPath {val}",
                    fix="Include %r@%h:%p or %C in ControlPath for uniqueness",
                ))


# ── Main Scanner ────────────────────────────────────────────────────

def scan_config(config_path: Path, check_permissions: bool = True) -> ScanResult:
    """Scan an SSH config file."""
    result = ScanResult()

    if not config_path.is_file():
        result.findings.append(Finding(
            rule_id="SL000",
            severity=Severity.INFO,
            message=f"File not found: {config_path}",
            file=str(config_path),
        ))
        return result

    result.files_scanned = 1
    filepath = str(config_path)

    try:
        content = config_path.read_text(errors="replace")
    except (OSError, PermissionError) as e:
        result.findings.append(Finding(
            rule_id="SL000",
            severity=Severity.INFO,
            message=f"Cannot read file: {e}",
            file=filepath,
        ))
        return result

    if not content.strip():
        return result

    blocks, global_block = parse_ssh_config(content)
    result.host_blocks = len(blocks)

    # Check global settings
    _check_global(global_block, filepath, result)

    # Check each host block
    for block in blocks:
        _check_block(block, filepath, result)

    # Check Include directives
    _check_include(content, filepath, result)

    # Check for deprecated options
    _check_deprecated(blocks, global_block, filepath, result)

    # Check IdentityFile references
    _check_identity_files(blocks, global_block, filepath, result)

    # Check ControlPath security
    _check_connection_sharing(blocks, global_block, filepath, result)

    # File permissions
    if check_permissions:
        _check_file_permissions(config_path, result)
        # Check SSH directory and key permissions
        ssh_dir = config_path.parent
        if ssh_dir.name == ".ssh":
            _check_key_permissions(ssh_dir, result)

    return result


# ── Output Formatting ───────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"
MAGENTA = "\033[95m"

SEVERITY_COLORS = {
    Severity.CRITICAL: RED,
    Severity.HIGH: YELLOW,
    Severity.MEDIUM: MAGENTA,
    Severity.LOW: CYAN,
    Severity.INFO: GRAY,
}


def _supports_color() -> bool:
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


def format_text(result: ScanResult, verbose: bool = False, color: bool = True) -> str:
    use_color = color and _supports_color()

    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if use_color else text

    lines: List[str] = []

    grade = result.grade
    risk = result.risk_label
    score = result.risk_score

    grade_color = GREEN if grade.startswith("A") else (YELLOW if grade in ("B", "C") else RED)
    risk_color = GREEN if risk == "SAFE" else (YELLOW if risk in ("LOW", "MODERATE") else RED)

    lines.append(c(BOLD, "sshlint") + " — SSH Client Config Security Audit")
    lines.append("")
    lines.append(f"  Grade: {c(grade_color, c(BOLD, grade))}  Risk: {c(risk_color, risk)} ({score}/100)")
    lines.append(f"  Files scanned: {result.files_scanned}  Host blocks: {result.host_blocks}")
    lines.append(f"  Findings: {len(result.findings)}")
    lines.append("")

    if not result.findings:
        lines.append(c(GREEN, "  ✓ No security issues found"))
        return "\n".join(lines)

    by_severity: Dict[Severity, List[Finding]] = {}
    for f in result.findings:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in Severity:
        findings = by_severity.get(sev, [])
        if not findings:
            continue
        if sev == Severity.INFO and not verbose:
            continue

        sev_color = SEVERITY_COLORS[sev]
        lines.append(c(sev_color, c(BOLD, f"  {sev.value} ({len(findings)})")))

        for f in findings:
            loc = f.file
            if f.line:
                loc += f":{f.line}"
            host_str = f" (Host: {f.host})" if f.host else ""
            lines.append(f"    [{f.rule_id}] {f.message}{host_str}")
            lines.append(f"      {c(GRAY, loc)}")
            if f.evidence:
                lines.append(f"      {c(GRAY, '→ ' + f.evidence)}")
            if f.fix:
                lines.append(f"      {c(CYAN, '⚡ ' + f.fix)}")
            lines.append("")

    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    data = {
        "grade": result.grade,
        "risk": result.risk_label,
        "score": result.risk_score,
        "files_scanned": result.files_scanned,
        "host_blocks": result.host_blocks,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(data, indent=2)


# ── Rule Reference ──────────────────────────────────────────────────

RULES = {
    "SL001": ("CRITICAL/HIGH", "StrictHostKeyChecking disabled (MITM vulnerability)"),
    "SL002": ("HIGH/MEDIUM", "ForwardAgent enabled (credential exposure via compromised hosts)"),
    "SL003": ("MEDIUM", "PermitLocalCommand enabled (arbitrary command execution)"),
    "SL004": ("CRITICAL/HIGH", "UserKnownHostsFile /dev/null (host verification disabled)"),
    "SL005": ("HIGH", "Weak ciphers (3DES-CBC, Blowfish, RC4, CBC modes)"),
    "SL006": ("HIGH", "Weak MACs (MD5, SHA1, RIPEMD160, UMAC-64)"),
    "SL007": ("HIGH", "Weak key exchange (DH group1/14-sha1, group-exchange-sha1)"),
    "SL008": ("MEDIUM", "Weak host key algorithms (ssh-rsa, ssh-dss)"),
    "SL009": ("HIGH", "Risky ProxyCommand (shell injection, download-and-execute)"),
    "SL010": ("MEDIUM", "Tunnel enabled (VPN-like tun/tap tunneling)"),
    "SL011": ("LOW/MEDIUM", "Password authentication enabled/preferred"),
    "SL012": ("INFO-MEDIUM", "Port forwarding configured (LocalForward/RemoteForward)"),
    "SL013": ("—", "Wildcard host with dangerous settings (elevates other rules)"),
    "SL014": ("LOW-HIGH", "X11 forwarding enabled (display access risk)"),
    "SL015": ("LOW", "LogLevel QUIET (hides security events)"),
    "SL016": ("LOW", "BatchMode globally enabled (suppresses all prompts)"),
    "SL017": ("HIGH", "Include from suspicious path (temp dir, path traversal)"),
    "SL018": ("LOW/MEDIUM", "SSH config file permissions too open"),
    "SL019": ("HIGH/CRITICAL", "Private key file permissions too open"),
    "SL020": ("HIGH", "Risky IdentityFile (DSA key, temp directory)"),
    "SL021": ("MEDIUM/CRITICAL", "Deprecated/removed SSH options"),
    "SL022": ("LOW/MEDIUM", "ControlPath in world-writable dir or predictable name"),
}


def format_rules() -> str:
    lines = ["sshlint rules:", ""]
    for rule_id, (severity, desc) in sorted(RULES.items()):
        lines.append(f"  {rule_id}  [{severity:>14s}]  {desc}")
    return "\n".join(lines)


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sshlint",
        description="SSH Client Configuration Security Linter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  sshlint                           Scan ~/.ssh/config
  sshlint /path/to/ssh_config       Scan specific config file
  sshlint --json                    JSON output for CI
  sshlint --no-perms                Skip file permission checks
  sshlint --rules                   List all rules
""",
    )
    parser.add_argument("path", nargs="?", default=None,
                        help="SSH config file to scan (default: ~/.ssh/config)")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show INFO-level findings")
    parser.add_argument("--rules", action="store_true",
                        help="List all rules and exit")
    parser.add_argument("--ci", action="store_true",
                        help="CI mode: exit 1 if HIGH+ findings, exit 2 if CRITICAL")
    parser.add_argument("--no-perms", action="store_true",
                        help="Skip file permission checks")
    parser.add_argument("--version", action="version",
                        version=f"sshlint {__version__}")

    args = parser.parse_args()

    if args.rules:
        print(format_rules())
        return 0

    if args.path:
        config_path = Path(args.path).resolve()
    else:
        config_path = Path.home() / ".ssh" / "config"

    result = scan_config(config_path, check_permissions=not args.no_perms)

    if args.json:
        print(format_json(result))
    else:
        print(format_text(result, verbose=args.verbose))

    if args.ci:
        has_critical = any(f.severity == Severity.CRITICAL for f in result.findings)
        has_high = any(f.severity == Severity.HIGH for f in result.findings)
        if has_critical:
            return 2
        if has_high:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
