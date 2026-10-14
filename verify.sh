#!/usr/bin/env bash
# verify.sh - check that a running host actually has the hardening walls up.
# Run as root (or with sudo) on the hardened machine. Exit non-zero on any gap.
set -u
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

chk_sysctl() { # name expected
  local got; got=$(sysctl -n "$1" 2>/dev/null)
  [ "$got" = "$2" ] && ok "$1 = $2" || bad "$1 = ${got:-unset} (want $2)"
}

echo "kernel:"
chk_sysctl kernel.kptr_restrict 2
chk_sysctl kernel.dmesg_restrict 1
chk_sysctl kernel.unprivileged_bpf_disabled 1
chk_sysctl fs.protected_symlinks 1
echo "network:"
chk_sysctl net.ipv4.conf.all.rp_filter 1
chk_sysctl net.ipv4.conf.all.accept_redirects 0
chk_sysctl net.ipv4.tcp_syncookies 1
echo "ssh:"
if command -v sshd >/dev/null; then
  sshd -T 2>/dev/null | grep -qx 'permitrootlogin no' && ok "PermitRootLogin no" || bad "PermitRootLogin not 'no'"
  sshd -T 2>/dev/null | grep -qx 'passwordauthentication no' && ok "PasswordAuthentication no" || bad "PasswordAuthentication not 'no'"
else
  echo "  (sshd not installed, skipping)"
fi
echo "firewall:"
systemctl is-active --quiet firewall.service && ok "firewall active" || bad "firewall not active"

echo
[ "$fail" -eq 0 ] && echo "PASS: hardening walls are up" || echo "FAIL: gaps above"
exit "$fail"
