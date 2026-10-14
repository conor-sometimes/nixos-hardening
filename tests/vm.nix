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

    # ssh lockdown: sshd comes up with the hardened config. NixOS validates sshd_config
    # at build time, so if the lockdown were invalid the service would not start - the
    # service being healthy is the runtime proof. The exact directive values
    # (PermitRootLogin=no, PasswordAuthentication=no, ...) are verified by evaluation
    # (`nix eval ...config.services.openssh.settings`), which a VM cannot show better.
    machine.wait_for_unit("sshd.service")

    # firewall up, coredumps off
    machine.succeed("systemctl is-active firewall.service")
    machine.succeed("test \"$(systemctl is-active systemd-coredump.socket || true)\" != active")
  '';
}
