{
  description = "nixos-hardening: a curated, toggleable, VM-tested host-hardening NixOS module (with opt-in impermanence)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      # The module. Import it and set `security.hardening.enable = true;`.
      nixosModules.default = import ./module.nix;
      nixosModules.hardening = import ./module.nix;

      # An example host wiring the ephemeral-home showcase, built (not booted) in CI to
      # prove the impermanence options produce a valid, buildable system.
      nixosConfigurations.example = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          self.nixosModules.default
          ./examples/impermanent-agent.nix
        ];
      };

      checks.${system} = {
        # The real proof: boot a machine with hardening on and assert the walls hold.
        vm = import ./tests/vm.nix { inherit pkgs self; };
        # Ephemeral homes booted and rebooted: writable, declared dirs survive, the rest is gone.
        impermanence = import ./tests/impermanence.nix { inherit pkgs self; };
        # The impermanence wiring evaluates and builds into a valid system.
        example = self.nixosConfigurations.example.config.system.build.toplevel;
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = [ pkgs.nixpkgs-fmt pkgs.statix ];
      };
    };
}
