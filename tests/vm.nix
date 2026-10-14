# Boot a machine with hardening enabled and assert the walls actually hold.
{ pkgs, self }:
pkgs.testers.runNixOSTest {
  name = "nixos-hardening";

  nodes.machine = { ... }: {
    imports = [ self.nixosModules.default ];
    security.hardening.enable = true;
    security.hardening.audit.enable = true;
    services.openssh.enable = true;
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # kernel hardening sysctls
    machine.succeed("sysctl -n kernel.kptr_restrict | grep -qx 2")
    machine.succeed("sysctl -n kernel.dmesg_restrict | grep -qx 1")
    machine.succeed("sysctl -n fs.protected_symlinks | grep -qx 1")
    machine.succeed("sysctl -n kernel.unprivileged_bpf_disabled | grep -qx 1")

    # network hardening sysctls
    machine.succeed("sysctl -n net.ipv4.conf.all.rp_filter | grep -qx 1")
    machine.succeed("sysctl -n net.ipv4.conf.all.accept_redirects | grep -qx 0")
    machine.succeed("sysctl -n net.ipv4.tcp_syncookies | grep -qx 1")

    # ssh lockdown (sshd -T prints the effective, lowercased config)
    machine.succeed("sshd -T | grep -qx 'permitrootlogin no'")
    machine.succeed("sshd -T | grep -qx 'passwordauthentication no'")
    machine.succeed("sshd -T | grep -qx 'allowtcpforwarding no'")

    # firewall up, coredumps off
    machine.succeed("systemctl is-active firewall.service")
    machine.succeed("test \"$(systemctl is-active systemd-coredump.socket || true)\" != active")

    # audit baseline loaded
    machine.succeed("auditctl -l | grep -q identity")
  '';
}
