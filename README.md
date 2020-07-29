# NixOps DigitalOcean Plugin

NixOps (formerly known as Charon) is a tool for deploying NixOS
machines in a network or cloud.

This repo contains the NixOps DigitalOcean Plugin.

* [Manual](https://nixos.org/nixops/manual/)
* [Installation](https://nixos.org/nixops/manual/#chap-installation) / [Hacking](https://nixos.org/nixops/manual/#chap-hacking)
* [Continuous build](http://hydra.nixos.org/jobset/nixops/master#tabs-jobs)
* [Source code](https://github.com/NixOS/nixops)
* [Issue Tracker](https://github.com/NixOS/nixops/issues)
* [Mailing list / Google group](https://groups.google.com/forum/#!forum/nixops-users)
* [IRC - #nixos on freenode.net](irc://irc.freenode.net/#nixos)

## Developing

To start developing on the NixOps DigitalOcean plugin, you can run:

```bash
  $ nix-shell
  $ poetry install
  $ poetry shell
```

To view active plugins:

```bash
  $ nixops list-plugins
```

The python code should be formatted with the latest release of [black](https://black.readthedocs.io/en/stable)

The nix code should be formatted with nixfmt or nixpkgs-fmt...

## Building from source

You can build the Nix package by simply invoking nix-build on the project root:

```bash
  $ nix-build
```
