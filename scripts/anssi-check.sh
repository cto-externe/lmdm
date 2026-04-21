#!/usr/bin/env bash
# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 CTO Externe
#
# anssi-check.sh — LMDM ANSSI-BP-028 v2.0 conformity smoke test.
#
# Usage: sudo ./scripts/anssi-check.sh [minimal|intermediaire|renforce|eleve]
#
# This is a minimal smoke check covering the most load-bearing sysctl/service
# /nftables/file items of each profile. A full audit should use OpenSCAP.
set -euo pipefail

LEVEL="${1:-minimal}"
PASS=0
FAIL=0

check_sysctl() {
    local key="$1" expected="$2"
    local got
    got=$(sysctl -n "$key" 2>/dev/null || echo "MISSING")
    if [[ "$got" == "$expected" ]]; then
        echo "  ✓ sysctl $key = $expected"
        PASS=$((PASS + 1))
    else
        echo "  ✗ sysctl $key: got $got, want $expected"
        FAIL=$((FAIL + 1))
    fi
}

check_service_inactive() {
    local svc="$1"
    local got
    got=$(systemctl is-active "$svc" 2>&1 || true)
    if [[ "$got" == "inactive" || "$got" == "failed" || "$got" == "unknown" ]]; then
        echo "  ✓ service $svc is not active ($got)"
        PASS=$((PASS + 1))
    else
        echo "  ✗ service $svc: got $got, want inactive/failed/unknown"
        FAIL=$((FAIL + 1))
    fi
}

check_nft_table() {
    local table="$1"
    if nft list tables 2>/dev/null | grep -q "inet $table"; then
        echo "  ✓ nftables table 'inet $table' present"
        PASS=$((PASS + 1))
    else
        echo "  ✗ nftables table 'inet $table' absent"
        FAIL=$((FAIL + 1))
    fi
}

check_file_contains() {
    local path="$1" pattern="$2"
    if [[ -f "$path" ]] && grep -Eq "$pattern" "$path"; then
        echo "  ✓ $path contains /$pattern/"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $path missing or does not contain /$pattern/"
        FAIL=$((FAIL + 1))
    fi
}

check_minimal() {
    # R8 — mémoire
    check_sysctl kernel.dmesg_restrict 1
    check_sysctl kernel.kptr_restrict 2
    # R9 — noyau
    check_sysctl kernel.sysrq 0
    check_sysctl kernel.unprivileged_bpf_disabled 1
    # R12 — IPv4
    check_sysctl net.ipv4.ip_forward 0
    check_sysctl net.ipv4.conf.all.accept_redirects 0
    check_sysctl net.ipv4.conf.all.accept_source_route 0
    # R14 — filesystem
    check_sysctl fs.protected_symlinks 1
    check_sysctl fs.protected_hardlinks 1
    check_sysctl fs.suid_dumpable 0
    # R62 — services désactivés
    check_service_inactive rpcbind
    check_service_inactive avahi-daemon
    # R36 — umask
    check_file_contains /etc/login.defs '^UMASK[[:space:]]+077'
    # R80 — nftables baseline
    check_nft_table lmdm_base || true
}

check_intermediaire_extra() {
    # R32 — TMOUT
    check_file_contains /etc/profile.d/99-lmdm-tmout.sh 'TMOUT='
    # R73 — auditd
    check_service_inactive systemd-timesyncd  # R75 side-effect
    if systemctl is-active auditd >/dev/null 2>&1; then
        echo "  ✓ service auditd is active"
        PASS=$((PASS + 1))
    else
        echo "  ✗ service auditd inactive (want active at intermédiaire+)"
        FAIL=$((FAIL + 1))
    fi
}

check_renforce_extra() {
    # kernel_module_blacklist
    check_file_contains /etc/modprobe.d/lmdm-fs-uncommon.conf 'install cramfs /bin/true'
    check_file_contains /etc/modprobe.d/lmdm-net-uncommon.conf 'install dccp /bin/true'
    check_file_contains /etc/modprobe.d/lmdm-usb.conf 'install usb_storage /bin/true'
    # R37 — AppArmor enforce
    if systemctl is-active apparmor >/dev/null 2>&1; then
        echo "  ✓ service apparmor is active"
        PASS=$((PASS + 1))
    else
        echo "  ✗ service apparmor inactive"
        FAIL=$((FAIL + 1))
    fi
    # R76 — AIDE
    check_file_contains /etc/default/aide 'CRON_DAILY_RUN=yes'
}

check_eleve_extra() {
    # R31 hardened pwquality
    check_file_contains /etc/security/pwquality.conf 'minlen[[:space:]]*=[[:space:]]*16'
    check_file_contains /etc/security/pwquality.conf 'minclass[[:space:]]*=[[:space:]]*4'
    # R66 — MFA package present
    if dpkg -l libpam-google-authenticator 2>/dev/null | grep -q '^ii'; then
        echo "  ✓ libpam-google-authenticator installed"
        PASS=$((PASS + 1))
    else
        echo "  ✗ libpam-google-authenticator missing"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== ANSSI-BP-028 conformity check — level: $LEVEL ==="
case "$LEVEL" in
    minimal)
        check_minimal
        ;;
    intermediaire)
        check_minimal
        check_intermediaire_extra
        ;;
    renforce)
        check_minimal
        check_intermediaire_extra
        check_renforce_extra
        ;;
    eleve)
        check_minimal
        check_intermediaire_extra
        check_renforce_extra
        check_eleve_extra
        ;;
    *)
        echo "Usage: $0 [minimal|intermediaire|renforce|eleve]" >&2
        exit 2
        ;;
esac

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[[ $FAIL -eq 0 ]]
