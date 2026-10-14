# Example host: hardened, with an ephemeral root and an impermanent home for a
# contained agent user ("claude"). Only the declared paths survive a reboot, so the
# agent cannot accumulate undeclared state. Composes with nixos-agent-containment.
#
# This is a build (not boot) example for CI: the device labels need not exist to
# realise the system, only to run it.
{ lib, ... }:
{
  # minimal bootable skeleton so the system can be realised
  boot.loader.systemd-boot.enable = true;
  fileSystems."/persist" = {
    device = "/dev/disk/by-label/persist";
    fsType = "ext4";
    neededForBoot = true;
  };
  fileSystems."/boot" = { device = "/dev/disk/by-label/boot"; fsType = "vfat"; };
  system.stateVersion = "24.11";

  # the hardening
  security.hardening.enable = true;

  # ephemeral tmpfs root; only these survive, restored from /persist
  security.hardening.impermanence.root.enable = true;
  security.hardening.impermanence.rootPersist = [
    "/var/log"
    "/var/lib/nixos"
    "/etc/ssh"
    "/etc/machine-id"
  ];

  # the agent's "slice of heaven": a fresh home every boot, keeping only what is
  # declared. Note repos is persisted so uncommitted work is not lost; drop it to
  # force the agent to push everything before reboot.
  security.hardening.impermanence.homes.claude.persist = [ ".ssh" "repos" ".config" ];
  users.users.claude = {
    isNormalUser = true;
    uid = 1100;
    home = "/home/claude";
  };
}
