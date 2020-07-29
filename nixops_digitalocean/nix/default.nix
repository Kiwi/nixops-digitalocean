{
  config_exporters = { optionalAttrs, ... }: [
    (config: { doDroplet = optionalAttrs (config.deployment.targetEnv == "doDroplet") config.deployment.doDroplet; })
  ];
  options = [
    ./droplet.nix
  ];
  resources = { evalResources, zipAttrs, resourcesByType, ... }: { };
}
