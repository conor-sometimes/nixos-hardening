# nixos-hardening

A curated, **toggleable** NixOS module for host hardening — CIS-aligned kernel and network
sysctls, SSH lockdown, a default-deny firewall and sensible restrictions, each on by default once
enabled and each individually overridable. Plus **opt-in impermanence**: an ephemeral tmpfs root,
and ephemeral per-user homes where only declared paths survive a reboot.

```nix
# configuration.nix
{
  imports = [ inputs.nixos-hardening.nixosModules.default ];
  security.hardening.enable = true;
}
```

That one line turns on the lot. Everything is `lib.mkDefault`, so any value you set elsewhere wins —
hardening never fights your own config.

## What it sets

| Area | Option | What |
| --- | --- | --- |
| **Kernel** | `kernel.enable` | `kptr_restrict=2`, `dmesg_restrict`, `unprivileged_bpf_disabled`, hardened BPF JIT, `yama.ptrace_scope=1`, `kexec_load_disabled`, `sysrq=0`, protected hard/sym links & FIFOs, no suid core dumps |
| **Network** | `network.enable` | reverse-path filter (`network.rpFilter`: `"strict"`, or `"loose"` for container / netns hosts), no ICMP redirects, no source routing, martian logging, broadcast-ICMP ignore, TCP syncookies (v4 + v6) |
| **SSH** | `ssh.enable` | no root login, keys only, 3 auth tries, 20 s login grace, no agent/TCP/X11 forwarding (`ssh.allowTcpForwarding` keeps TCP for a jump host), post-quantum KEX first, modern ciphers / MACs only |
| **Firewall** | `firewall.enable` | enabled with a default-deny inbound policy |
| **Misc** | `misc.enable` | no core dumps, `sudo` restricted to the wheel group |
| **Nix** | `nix.enable` | only wheel may use the Nix daemon (merges with users other modules add, e.g. an agent's `allowNixBuilds`); warns when anyone but root is a trusted user (a trusted user is root without sudo) |
| **Audit** | `audit.enable` (off by default) | auditd baseline: identity, sudoers, sshd-config and time-change watches |

Turn any area off while keeping the rest:

```nix
security.hardening.enable = true;
security.hardening.ssh.enable = false;   # e.g. you manage sshd yourself
```

## Impermanence (opt-in)

An ephemeral system that rebuilds to a declared state every boot: undeclared state does not survive,
so drift and leftovers are gone on reboot, and so is anything an attacker (or a wayward agent) plants
*outside* the paths you persist. What it plants *inside* them stays (see the limits below).

```nix
# ephemeral tmpfs root; only these come back from /persist
security.hardening.impermanence.root.enable = true;
security.hardening.impermanence.rootPersist = [ "/var/log" "/var/lib/nixos" "/etc/ssh" "/etc/machine-id" ];
```

**Ephemeral homes** are the sharp version — opt in a user *by name* and its home becomes a fresh
tmpfs every boot, keeping only the declared directories. It composes with
[nixos-agent-containment](https://github.com/conor-sometimes/nixos-agent-containment) (the two
modules are independent; neither needs the other): the agent's home stops being a place to keep
things between reboots. On its own an ephemeral home is not enough. Paths outside the home that the
user can write (`/var/tmp`, its Nix profiles under `/nix/var`) still persist unless the root is
ephemeral too, and everything inside a persisted directory persists, including whatever the agent
plants there. So persist narrow directories, never the places that run code later:

```nix
# only the claude user; everyone else (incl. you) is untouched
security.hardening.impermanence.homes.claude.directories = [ "repos" ".config/gh" ".config/git" ];
# not ".config" (systemd user units, shell configs and autostart live there), and not ".ssh" if
# sshd reads ~/.ssh/authorized_keys: the agent could add a key of its own that survives
```

There is deliberately **no "all users" switch** — you name each user, and that explicit naming is the
safety. The declared directories are **bind-mounted** from the persist device into the fresh tmpfs
home: no `cp`, no `mv`, no `rm`, nothing shuffled — the data lives in one place and simply appears at
the home path, so it can't be half-copied or lost. Only the *scratch* part of the home (the tmpfs)
is ephemeral; the persisted dirs live on disk, so repo size is not a RAM concern.

You provide the backing for the persist device (`/persist` by default) in your own `fileSystems`,
and seed its per-user dirs once (the module keeps them user-owned via a `tmpfiles` rule). Declare
what must survive — keep `~/repos` if uncommitted work matters, or drop it to *force* a push before
reboot. For individual config *files*, persist the containing directory or manage them declaratively;
there are no per-file binds on purpose.

**Granularity is per-boot, not per-session.** Login/logout triggers are deliberately out: an agent's
jobs outlive its SSH sessions, so a session-boundary reset would clobber running work. If you want
aggressive per-unit-of-work resets, that's an ephemeral VM/container per job — a different tool.
`examples/impermanent-agent.nix` is a complete, buildable showcase.

## Verify it

`sudo ./verify.sh` on the running host checks the sysctls, the effective `sshd` config and the
firewall, and exits non-zero on any gap. The module is also **VM-tested**: `nix flake check` boots a
machine with hardening on and asserts every wall holds (`tests/vm.nix`), boots an ephemeral home
across a reboot (`tests/impermanence.nix`: the user owns and can write its fresh home, declared
directories survive, the rest is gone), and builds the impermanence example.

## What it does not protect against

- **It is host hardening, not a sandbox.** It raises the cost of a foothold; it does not contain a
  kernel exploit or a local privilege escalation. For untrusted *code*, wall it in a user/VM
  (that's what [nixos-agent-containment](https://github.com/conor-sometimes/nixos-agent-containment)
  is for) — this module hardens the host they both run on.
- **Defaults are conservative on purpose.** `hidepid` on `/proc`, `unprivileged_userns` lockdown and
  a more aggressive `ptrace_scope=2` are deliberately left out of the default set because they break
  common workflows (systemd, nix sandbox, containers). Opt into them yourself if your threat model
  wants them.
- **Impermanence is a property, not a guarantee of cleanliness.** It discards *undeclared* state on
  reboot; whatever you persist persists, compromise and all. Keep the persist list minimal, and keep
  code-running paths out of it: `~/.config` holds systemd user units and shell configs, `~/.ssh`
  holds `authorized_keys` (turn off home-directory key files for an agent user and give it keys
  from `/etc`), and a persisted repo keeps its `.git/hooks`.
- **An ephemeral home leaves the rest of the disk alone.** `/var/tmp` and the user's Nix profiles
  under `/nix/var` survive a reboot unless the root is ephemeral as well (`/nix` itself is always on
  disk).

## Licence

GNU General Public License v3.0 or later (see [LICENSE](LICENSE)).
