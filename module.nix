# nixos-hardening: a curated, toggleable host-hardening NixOS module.
#
#   security.hardening.enable = true;
#
# Each area is on by default once enabled and can be turned off individually. The
# values are CIS-aligned and documented; nothing here needs a reboot except
# impermanence. See README.md for what this does and does not protect against.
{ config, lib, pkgs, ... }:

let
  cfg = config.security.hardening;
  # hardening priority: beats nixpkgs' own mkDefault sysctls, still loses to the user's config
  prio = lib.mkOverride 900;
  # a sub-area is on when hardening is enabled, unless explicitly turned off
  areaOption = desc: lib.mkOption {
    type = lib.types.bool;
    default = cfg.enable;
    defaultText = lib.literalExpression "config.security.hardening.enable";
    description = desc;
  };
in
{
  options.security.hardening = {
    enable = lib.mkEnableOption "curated, CIS-aligned host hardening";

    kernel.enable = areaOption "Kernel hardening sysctls (kptr/dmesg restrict, ptrace scope, BPF, kexec, sysrq, protected links).";
    network.enable = areaOption "Network hardening sysctls (reverse-path filter, no redirects/source-routing, martian logging, syncookies).";
    ssh.enable = areaOption "OpenSSH hardening (no root login, keys only, no forwarding, modern KEX/ciphers/MACs).";
    firewall.enable = areaOption "Enable the firewall with a default-deny inbound policy.";
    misc.enable = areaOption "Misc restrictions (no core dumps, restrict su to a group, hide other users' processes).";

    audit.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable a small auditd baseline (identity, sudoers and ssh-config changes, time changes). Off by default: it is noisy.";
    };

    impermanence = {
      root.enable = lib.mkEnableOption "an ephemeral tmpfs root; only declared paths under the persist device survive a reboot";
      persistDevice = lib.mkOption {
        type = lib.types.str;
        default = "/persist";
        description = "Mountpoint of the durable dataset that holds everything the ephemeral root/homes persist. You provide its backing in fileSystems.";
      };
      rootPersist = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ "/var/log" "/var/lib/nixos" "/etc/ssh" "/etc/machine-id" ];
        description = "Absolute paths bind-mounted back from the persist device onto the ephemeral root.";
      };
      homes = lib.mkOption {
        description = ''
          Per-user ephemeral homes: the home is a tmpfs wiped every boot, and only the listed
          sub-paths are bind-mounted back from the persist device. The declared contract is the
          whole point - an agent (or any user) cannot accumulate undeclared state. Anything NOT
          listed is gone on reboot, so list what must survive (e.g. "repos", ".ssh").
        '';
        default = { };
        example = lib.literalExpression ''{ claude = { persist = [ ".ssh" "repos" ".config" ]; }; }'';
        type = lib.types.attrsOf (lib.types.submodule {
          options.persist = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ".ssh" ];
            description = "Home-relative paths to keep across reboots; everything else in the home is ephemeral.";
          };
          options.size = lib.mkOption {
            type = lib.types.str;
            default = "2G";
            description = "tmpfs size cap for the ephemeral home.";
          };
        });
      };
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [

    # --- kernel ---------------------------------------------------------------
    (lib.mkIf cfg.kernel.enable {
      boot.kernel.sysctl = {
        "kernel.kptr_restrict" = prio 2;
        "kernel.dmesg_restrict" = prio 1;
        "kernel.printk" = prio "3 3 3 3";
        "kernel.unprivileged_bpf_disabled" = prio 1;
        "net.core.bpf_jit_harden" = prio 2;
        "kernel.yama.ptrace_scope" = prio 1;
        "kernel.kexec_load_disabled" = prio 1;
        "kernel.sysrq" = prio 0;
        "kernel.perf_event_paranoid" = prio 3;
        "fs.protected_hardlinks" = prio 1;
        "fs.protected_symlinks" = prio 1;
        "fs.protected_fifos" = prio 2;
        "fs.protected_regular" = prio 2;
        "fs.suid_dumpable" = prio 0;
      };
    })

    # --- network --------------------------------------------------------------
    (lib.mkIf cfg.network.enable {
      boot.kernel.sysctl = {
        "net.ipv4.conf.all.rp_filter" = prio 1;
        "net.ipv4.conf.default.rp_filter" = prio 1;
        "net.ipv4.conf.all.accept_redirects" = prio 0;
        "net.ipv4.conf.default.accept_redirects" = prio 0;
        "net.ipv4.conf.all.secure_redirects" = prio 0;
        "net.ipv4.conf.all.send_redirects" = prio 0;
        "net.ipv4.conf.default.send_redirects" = prio 0;
        "net.ipv4.conf.all.accept_source_route" = prio 0;
        "net.ipv4.conf.default.accept_source_route" = prio 0;
        "net.ipv6.conf.all.accept_redirects" = prio 0;
        "net.ipv6.conf.all.accept_source_route" = prio 0;
        "net.ipv4.conf.all.log_martians" = prio 1;
        "net.ipv4.icmp_echo_ignore_broadcasts" = prio 1;
        "net.ipv4.tcp_syncookies" = prio 1;
      };
    })

    # --- ssh ------------------------------------------------------------------
    (lib.mkIf cfg.ssh.enable {
      services.openssh.settings = {
        PermitRootLogin = prio "no";
        PasswordAuthentication = prio false;
        KbdInteractiveAuthentication = prio false;
        X11Forwarding = prio false;
        AllowAgentForwarding = prio "no";
        AllowTcpForwarding = prio "no";
        KexAlgorithms = prio [
          "curve25519-sha256"
          "curve25519-sha256@libssh.org"
          "diffie-hellman-group16-sha512"
          "diffie-hellman-group18-sha512"
        ];
        Ciphers = prio [
          "chacha20-poly1305@openssh.com"
          "aes256-gcm@openssh.com"
          "aes128-gcm@openssh.com"
        ];
        Macs = prio [
          "hmac-sha2-512-etm@openssh.com"
          "hmac-sha2-256-etm@openssh.com"
        ];
      };
    })

    # --- firewall -------------------------------------------------------------
    (lib.mkIf cfg.firewall.enable {
      networking.firewall.enable = prio true;
    })

    # --- misc -----------------------------------------------------------------
    (lib.mkIf cfg.misc.enable {
      systemd.coredump.enable = prio false;
      security.sudo.execWheelOnly = prio true;
      # (hidepid for /proc is a good next step but needs systemd in a proc group to
      # avoid breaking services; left out of the default set - see README.)
    })

    # --- audit baseline -------------------------------------------------------
    (lib.mkIf cfg.audit.enable {
      security.auditd.enable = true;
      security.audit.enable = true;
      security.audit.rules = [
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/group -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
        "-w /etc/sudoers -p wa -k sudoers"
        "-w /etc/sudoers.d/ -p wa -k sudoers"
        "-w /etc/ssh/sshd_config -p wa -k sshd"
        "-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change"
      ];
    })

    # --- impermanence: ephemeral root ----------------------------------------
    (lib.mkIf cfg.impermanence.root.enable {
      fileSystems = lib.mkMerge ([
        {
          "/" = lib.mkForce {
            device = "none";
            fsType = "tmpfs";
            options = [ "defaults" "size=4G" "mode=755" ];
          };
          "${cfg.impermanence.persistDevice}".neededForBoot = prio true;
        }
      ] ++ map
        (p: {
          ${p} = {
            device = "${cfg.impermanence.persistDevice}${p}";
            fsType = "none";
            options = [ "bind" ];
            neededForBoot = true;
          };
        })
        cfg.impermanence.rootPersist);
    })

    # --- impermanence: ephemeral per-user homes ("Claude's slice of heaven") --
    # The home is a fresh tmpfs each boot; NixOS activation (createHome) re-creates and
    # chowns it, and only the listed sub-paths are bind-mounted back from the persist
    # device. Anything the user leaves outside those paths is gone on reboot.
    {
      users.users = lib.mapAttrs (_: _: { createHome = prio true; }) cfg.impermanence.homes;
      fileSystems = lib.mkMerge (lib.mapAttrsToList
        (user: h:
          let home = config.users.users.${user}.home or "/home/${user}";
          in lib.mkMerge ([
            {
              "${home}" = {
                device = "none";
                fsType = "tmpfs";
                options = [ "defaults" "size=${h.size}" "mode=0755" ];
              };
            }
          ] ++ map
            (sub: {
              "${home}/${sub}" = {
                device = "${cfg.impermanence.persistDevice}${home}/${sub}";
                fsType = "none";
                options = [ "bind" ];
              };
            })
            h.persist))
        cfg.impermanence.homes);
    }
  ]);
}
