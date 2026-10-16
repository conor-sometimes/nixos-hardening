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

  # A container/jump host: the per-host knobs, plus a second module adding a nix user the way
  # nixos-agent-containment's allowNixBuilds does (wheel must survive the merge).
  nodes.jumphost = { ... }: {
    imports = [ self.nixosModules.default ];
    security.hardening.enable = true;
    security.hardening.network.rpFilter = "loose";
    security.hardening.ssh.allowTcpForwarding = true;
    services.openssh.enable = true;
    nix.settings.allowed-users = [ "agent" ];
  };

  testScript = ''
    start_all()
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

    # ssh lockdown: sshd comes up, and its effective config (sshd -T) has the walls
    machine.wait_for_unit("sshd.service")
    sshd = machine.succeed("sshd -T").lower().splitlines()  # OpenSSH 10.5+ prints mixed case
    for line in ["maxauthtries 3", "logingracetime 20", "allowtcpforwarding no",
                 "allowagentforwarding no", "x11forwarding no", "permitrootlogin no",
                 "passwordauthentication no"]:
        assert line in sshd, f"sshd -T lacks '{line}'"
    kex = [l for l in sshd if l.startswith("kexalgorithms ")][0]
    assert kex.startswith("kexalgorithms mlkem768x25519-sha256,"), kex

    # nix daemon: wheel only
    machine.succeed("grep -qx 'allowed-users = @wheel' /etc/nix/nix.conf")

    # firewall up, coredumps off
    machine.succeed("systemctl is-active firewall.service")
    machine.succeed("test \"$(systemctl is-active systemd-coredump.socket || true)\" != active")

    # jump host: loose rp_filter, TCP forwarding kept (agent forwarding still off),
    # and the extra nix user merged in next to wheel rather than replacing it
    jumphost.wait_for_unit("sshd.service")
    jumphost.succeed("sysctl -n net.ipv4.conf.all.rp_filter | grep -qx 2")
    jumphost.succeed("sysctl -n kernel.kptr_restrict | grep -qx 2")
    jsshd = jumphost.succeed("sshd -T").lower().splitlines()
    assert "allowtcpforwarding yes" in jsshd
    assert "allowagentforwarding no" in jsshd
    users = jumphost.succeed("sed -n 's/^allowed-users = //p' /etc/nix/nix.conf").split()
    assert sorted(users) == ["@wheel", "agent"], users
  '';
}
