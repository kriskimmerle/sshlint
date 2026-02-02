# sshlint

**SSH Client Configuration Security Linter**

Static analysis of `~/.ssh/config` for dangerous settings, weak crypto, credential exposure risks, and misconfigurations. Unlike [ssh-audit](https://github.com/jtesta/ssh-audit) which tests protocol-level crypto by connecting to servers, sshlint analyzes the **config file itself** without any network access.

Zero dependencies. Stdlib only. Python 3.8+.

## Why?

Your `~/.ssh/config` controls how every SSH connection behaves. Common misconfigurations silently weaken security:

- **`StrictHostKeyChecking no`** on wildcard hosts → every connection is vulnerable to MITM
- **`ForwardAgent yes`** globally → any compromised server can use your SSH keys
- **`UserKnownHostsFile /dev/null`** → host verification completely disabled
- **Weak ciphers/MACs/KEX** → cryptographic downgrade attacks
- **`Protocol 1`** → critically insecure (CVEs galore)
- **Bad file permissions** → private keys readable by others

These settings are often copy-pasted from Stack Overflow without understanding the implications. sshlint catches them.

## Install

```bash
# Just copy the script
curl -o sshlint.py https://raw.githubusercontent.com/kriskimmerle/sshlint/main/sshlint.py
chmod +x sshlint.py

# Or clone
git clone https://github.com/kriskimmerle/sshlint.git
```

## Usage

```bash
# Scan default ~/.ssh/config
python3 sshlint.py

# Scan a specific config file
python3 sshlint.py /path/to/ssh_config

# JSON output for CI
python3 sshlint.py --json

# Skip file permission checks (e.g., in CI where files are owned by runner)
python3 sshlint.py --no-perms

# CI mode (exit 1 for HIGH, exit 2 for CRITICAL)
python3 sshlint.py --ci

# Show all rules
python3 sshlint.py --rules

# Verbose (include INFO findings)
python3 sshlint.py -v
```

## What It Checks

### Host Configuration (per Host block)

| Rule | Severity | Description |
|------|----------|-------------|
| SL001 | CRITICAL/HIGH | StrictHostKeyChecking disabled (MITM vulnerability) |
| SL002 | HIGH/MEDIUM | ForwardAgent enabled (credential exposure via compromised hosts) |
| SL003 | MEDIUM | PermitLocalCommand enabled (arbitrary command execution) |
| SL004 | CRITICAL/HIGH | UserKnownHostsFile /dev/null (host verification disabled) |
| SL009 | HIGH | Risky ProxyCommand (shell injection, download-and-execute) |
| SL010 | MEDIUM | Tunnel enabled (VPN-like tun/tap tunneling) |
| SL011 | LOW/MEDIUM | Password authentication enabled or preferred over keys |
| SL012 | INFO–MEDIUM | Port forwarding configured (sensitive ports flagged higher) |
| SL014 | LOW–HIGH | X11 forwarding enabled (trusted mode is much riskier) |
| SL015 | LOW | LogLevel QUIET (hides security events) |
| SL016 | LOW | BatchMode globally enabled (suppresses all prompts) |

### Cryptography

| Rule | Severity | Description |
|------|----------|-------------|
| SL005 | HIGH | Weak ciphers (3DES-CBC, Blowfish, RC4, all CBC modes) |
| SL006 | HIGH | Weak MACs (MD5, SHA1, RIPEMD160, UMAC-64) |
| SL007 | HIGH | Weak key exchange (DH group1-sha1, group14-sha1) |
| SL008 | MEDIUM | Weak host key algorithms (ssh-rsa, ssh-dss) |

### Files & Permissions

| Rule | Severity | Description |
|------|----------|-------------|
| SL017 | HIGH | Include from suspicious path (/tmp, path traversal) |
| SL018 | LOW/MEDIUM | SSH config file permissions too open |
| SL019 | HIGH/CRITICAL | Private key file permissions too open |
| SL020 | HIGH | Risky IdentityFile (DSA key deprecated, key in /tmp) |
| SL021 | MEDIUM/CRITICAL | Deprecated/removed SSH options (Protocol 1, UseRoaming) |
| SL022 | LOW/MEDIUM | ControlPath in world-writable dir or predictable name |

### Context-Aware Severity

Severity escalates when dangerous settings are applied to **wildcard hosts** (`Host *`):

| Setting | Specific Host | Wildcard (`Host *`) |
|---------|--------------|---------------------|
| StrictHostKeyChecking no | HIGH | **CRITICAL** |
| ForwardAgent yes | MEDIUM | **HIGH** |
| UserKnownHostsFile /dev/null | HIGH | **CRITICAL** |
| ForwardX11Trusted yes | MEDIUM | **HIGH** |

## Example Output

### Clean configuration
```
sshlint — SSH Client Config Security Audit

  Grade: A+  Risk: SAFE (0/100)
  Files scanned: 1  Host blocks: 3
  Findings: 0

  ✓ No security issues found
```

### Dangerous configuration
```
sshlint — SSH Client Config Security Audit

  Grade: F  Risk: CRITICAL (100/100)
  Files scanned: 1  Host blocks: 1
  Findings: 9

  CRITICAL (2)
    [SL001] StrictHostKeyChecking disabled — vulnerable to MITM attacks (Host: *)
      ~/.ssh/config:3
      → StrictHostKeyChecking no
      ⚡ Remove this setting or set to 'ask' or 'accept-new'

    [SL004] UserKnownHostsFile set to /dev/null — host key verification disabled (Host: *)
      ~/.ssh/config:4
      → UserKnownHostsFile /dev/null
      ⚡ Remove this setting to use default known_hosts file

  HIGH (4)
    [SL002] ForwardAgent enabled — compromised hosts can use your SSH keys (Host: *)
      ~/.ssh/config:5
      → ForwardAgent yes
      ⚡ Disable ForwardAgent or use ProxyJump instead for hopping

    [SL005] Weak cipher(s) configured: 3des-cbc
      ...
```

## CI Integration

### GitHub Actions

```yaml
- name: Lint SSH config
  run: python3 sshlint.py --ci /path/to/ssh_config
```

Exit codes:
- `0` — No HIGH or CRITICAL findings
- `1` — HIGH findings detected
- `2` — CRITICAL findings detected

## How It Differs from ssh-audit

| Feature | sshlint | ssh-audit |
|---------|---------|-----------|
| Analyzes config **file** | ✅ | ❌ |
| Connects to servers | ❌ | ✅ |
| Checks file permissions | ✅ | ❌ |
| Checks ForwardAgent/X11/Tunnel | ✅ | ❌ |
| Detects deprecated options | ✅ | ❌ |
| Tests actual protocol crypto | ❌ | ✅ |
| Requires network access | ❌ | ✅ |

**Use both:** sshlint for your local config, ssh-audit for your servers.

## License

MIT
