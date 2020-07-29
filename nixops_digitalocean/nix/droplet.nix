{ config, lib, ... }:

with lib;
let cfg = config.deployment.doDroplet;
in {
  options = {
    deployment.doDroplet.enableFloatingIP = mkOption {
      default = false;
      type = types.bool;
      description = ''
        Whether to enable the Floating IP anchor IP on the droplet.
      '';
    };

    deployment.doDroplet.floatingIP = mkOption {
      default = "";
      type = types.str;
      description = ''
        An existing floatingIP to use.
      '';
    };

    deployment.doDroplet.enablePrivateNetworking = mkOption {
      default = false;
      type = types.bool;
      description = ''
        Whether to enable private networking support on the droplet.
      '';
    };

    deployment.doDroplet.enableMonitoring = mkOption {
      default = false;
      type = types.bool;
      description = ''
        Whether to enable do-agent on the droplet.
      '';
    };

    deployment.doDroplet.authToken = mkOption {
      default = "";
      example =
        "8b2f4e96af3997853bfd4cd8998958eab871d9614e35d63fab45a5ddf981c4da";
      type = types.str;
      description = ''
        The API auth token. We're checking the environment for
        <envar>DIGITAL_OCEAN_AUTH_TOKEN</envar> first and if that is
        not set we try this auth token.
      '';
    };

    deployment.doDroplet.region = mkOption {
      default = "";
      example = "nyc3";
      type = types.str;
      description = ''
        The region. See https://status.digitalocean.com/ for a list
        of regions.
      '';
    };

    deployment.doDroplet.size = mkOption {
      example = "512mb";
      type = types.str;
      description = ''
        The size identifier between <literal>512mb</literal> and <literal>64gb</literal>.
        The supported size IDs for a region can be queried via API:
        https://developers.digitalocean.com/documentation/v2/#list-all-sizes
      '';
    };

    deployment.doDroplet.enableIpv6 = mkOption {
      default = false;
      type = types.bool;
      description = ''
        Whether to enable IPv6 support on the droplet.
      '';
    };
  };

  config = mkIf (config.deployment.targetEnv == "doDroplet") {
    nixpkgs.system = mkOverride 900 "x86_64-linux";
    services.openssh.enable = true;
  };
}
