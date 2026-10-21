# Boot a machine with an ephemeral home and check it across a reboot: the user can write its home
# (and a persisted subdirectory's parent), declared directories survive, everything else is gone.
{ pkgs, self }:
let
  inherit (pkgs) lib;
  home = { ... }: {
    imports = [ self.nixosModules.default ];
    security.hardening.enable = true;
    users.users.agent = { isNormalUser = true; uid = 1100; };
    security.hardening.impermanence.homes.agent.directories = [ "repos" ".config/gh" ];
  };
  # the test VM replaces fileSystems with virtualisation.fileSystems, so take the module's own home
  # mounts from a plain evaluation of the same config (the persist device is a directory on the
  # VM's disk)
  homeMounts = lib.filterAttrs (n: _: lib.hasPrefix "/home/" n) (import "${pkgs.path}/nixos/lib/eval-config.nix" {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [ home { fileSystems."/".device = "none"; boot.loader.grub.enable = false; } ];
  }).config.fileSystems;
in
pkgs.testers.runNixOSTest {
  name = "nixos-hardening-impermanence";

  nodes.machine = { ... }: {
    imports = [ home ];
    virtualisation.fileSystems = homeMounts;
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    # the fresh home and the parent of a nested persisted dir belong to the user
    machine.succeed("stat -c '%U %a' /home/agent | grep -qx 'agent 700'")
    machine.succeed("stat -c %U /home/agent/.config | grep -qx agent")
    machine.succeed("findmnt -n -o FSTYPE /home/agent | grep -qx tmpfs")
    # the user can write anywhere in it: scratch, a sibling of a persisted dir, the persisted dirs
    machine.succeed("su - agent -c 'touch ~/scratch'")
    machine.succeed("su - agent -c 'mkdir -p ~/.config/fish && echo x > ~/.config/fish/config.fish'")
    machine.succeed("su - agent -c 'echo keep > ~/repos/a'")
    machine.succeed("su - agent -c 'echo tok > ~/.config/gh/hosts.yml'")

    machine.shutdown()
    machine.start()
    machine.wait_for_unit("multi-user.target")
    # declared directories survive, everything else in the home is gone
    machine.succeed("grep -qx keep /home/agent/repos/a")
    machine.succeed("grep -qx tok /home/agent/.config/gh/hosts.yml")
    machine.fail("test -e /home/agent/scratch")
    machine.fail("test -e /home/agent/.config/fish")
    machine.succeed("stat -c '%U %a' /home/agent | grep -qx 'agent 700'")
  '';
}
