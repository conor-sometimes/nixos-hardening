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
  rpFilter = if cfg.network.rpFilter == "loose" then 2 else 1;
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
    network.rpFilter = lib.mkOption {
      type = lib.types.enum [ "strict" "loose" ];
      default = "strict";
      description = ''
        Reverse-path filtering (rp_filter). "strict" (1) drops packets arriving on an interface
        the route back would not use; "loose" (2) only drops sources with no route at all. Strict
        can break container and network-namespace routing (podman, per-agent netns): use "loose" there.
      '';
    };
    ssh.enable = areaOption "OpenSSH hardening (no root login, keys only, few auth tries, no forwarding, modern KEX/ciphers/MACs).";
    ssh.allowTcpForwarding = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Keep TCP forwarding (ssh -L/-R/-W, ProxyJump through this host). Off by default; turn it on
        for a jump host rather than turning off the whole ssh area. Agent and X11 forwarding stay off.
      '';
    };
    firewall.enable = areaOption "Enable the firewall with a default-deny inbound policy.";
    misc.enable = areaOption "Misc restrictions (no core dumps, sudo only for wheel).";
    nix.enable = areaOption "Nix daemon: only wheel may use it, and a warning when anyone but root is a trusted user.";

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
          Per-user ephemeral homes - OPT-IN BY NAME. Each named user's home is a fresh tmpfs every
          boot; only the declared directories are bind-mounted back from the persist device, so the
          rest of the home starts clean. Anything inside a declared directory survives, so keep
          code-running paths (.config, .ssh) out of it. Users you do not list (including your own) are
          untouched. There is deliberately no "all users" switch: naming each user is the safety.
          Boot granularity - the reset is a reboot, never a login/logout (that would clobber an
          agent's jobs, which outlive sessions; see README).
        '';
        default = { };
        example = lib.literalExpression ''{ claude = { directories = [ "repos" ".config/gh" ".config/git" ]; }; }'';
        type = lib.types.attrsOf (lib.types.submodule {
          options.directories = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ".ssh" ];
            description = ''
              Home-relative directories to persist (bind-mounted from the persist device); everything
              else in the home is ephemeral. For individual config files, persist the narrowest
              containing directory (e.g. ".config/gh", not ".config") or manage them declaratively -
              no per-file binds.
            '';
          };
          options.size = lib.mkOption {
            type = lib.types.str;
            default = "2G";
            description = "tmpfs size cap for the ephemeral part of the home (persisted dirs live on disk, not here).";
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
        "net.ipv4.conf.all.rp_filter" = prio rpFilter;
        "net.ipv4.conf.default.rp_filter" = prio rpFilter;
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
        MaxAuthTries = prio 3;
        LoginGraceTime = prio 20;
        X11Forwarding = prio false;
        AllowAgentForwarding = prio "no";
        AllowTcpForwarding = prio (if cfg.ssh.allowTcpForwarding then "yes" else "no");
        KexAlgorithms = prio [
          # post-quantum hybrids first (OpenSSH 9.9+ / 9.0+), as OpenSSH's own defaults do
          "mlkem768x25519-sha256"
          "sntrup761x25519-sha512"
          "sntrup761x25519-sha512@openssh.com"
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

    # --- nix daemon -----------------------------------------------------------
    # allowed-users is set at normal priority on purpose: list definitions only merge at equal
    # priority, so a weaker one would be dropped whole by any module that adds a user (e.g.
    # nixos-agent-containment's allowNixBuilds) and wheel would lose the daemon.
    (lib.mkIf cfg.nix.enable {
      nix.settings.allowed-users = [ "@wheel" ];
      # a trusted user can import unsigned store paths: root without sudo
      warnings = lib.optional (lib.any (u: u != "root") config.nix.settings.trusted-users)
        "security.hardening.nix: trusted-users has more than root (${toString config.nix.settings.trusted-users}); a trusted user is effectively root.";
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

      # keep the persist-side source dirs present and user-owned (idempotent create-if-absent,
      # the only non-mount op; everything else is bind mounts, no cp/mv/rm). Also hand the fresh
      # tmpfs home and the parents of nested persisted dirs (.config for .config/gh) to the user:
      # the tmpfs and systemd's mount points come up root-owned, and `d` fixes owner and mode of a
      # directory that already exists (tmpfiles runs after the mounts).
      systemd.tmpfiles.rules = lib.concatLists (lib.mapAttrsToList
        (user: h:
          let
            u = config.users.users.${user};
            home = u.home or "/home/${user}";
            group = u.group or "users";
            parents = sub: let parts = lib.splitString "/" sub; in
              map (n: lib.concatStringsSep "/" (lib.take n parts)) (lib.range 1 (lib.length parts - 1));
          in [ "d ${home} ${u.homeMode or "0700"} ${user} ${group} -" ]
            ++ map (p: "d ${home}/${p} 0700 ${user} ${group} -") (lib.unique (lib.concatMap parents h.directories))
            ++ map (sub: "d ${cfg.impermanence.persistDevice}${home}/${sub} 0700 ${user} ${group} -") h.directories)
        cfg.impermanence.homes);

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
            h.directories))
        cfg.impermanence.homes);
    }
  ]);
}
