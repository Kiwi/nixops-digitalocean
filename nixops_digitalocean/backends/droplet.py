# -*- coding: utf-8 -*-
"""
A backend for www.digitalocean.com (short as "DO").

This backend uses nixos-infect (which uses nixos LUSTRATE) to infect a
Ubuntu digitial ocean instance. The setup requires two reboots, one for
the infect itself, another after we pushed the nixos image.

I hit a few subtle problems along the way:
* DO doesn't do dhcp so we have to hard-code the network configuration
* Ubuntu still uses eth0, 1 etc, not ens3 etc so we have a network
  link name change after the reboot.
* I had to modify nixos-infect to reflect the network link name changes,
  and to not reboot to avoid ssh-interruption and therefore errors.

Still to do:
* Floating IPs
* Network attached storage
"""
import os
import os.path
import time
import socket
from typing import Optional, List, Set, cast

from nixops.resources import ResourceEval, ResourceOptions, ssh_keypair

# import nixops.known_hosts
from nixops.backends import MachineDefinition, MachineOptions, MachineState
from nixops.deployment import Deployment
from nixops.nix_expr import Function, RawValue
from nixops.util import attr_property
from nixops.state import RecordId
import codecs

from digitalocean import FloatingIP, Droplet, Manager
import digitalocean  # type: ignore

infect_path: str = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "nixos-infect")
)


class DigitalOceanStatus(object):
    pass


class StatusUnchanged(DigitalOceanStatus):
    pass


class StatusChanged(DigitalOceanStatus):
    pass


class StatusFIPDoesNotExist(DigitalOceanStatus):
    pass


class StatusNew(DigitalOceanStatus):
    pass


class StatusUnknown(DigitalOceanStatus):
    pass


class StatusDeleted(DigitalOceanStatus):
    pass


class DropletOptions(ResourceOptions):
    authToken: Optional[str]
    region: Optional[str]
    size: Optional[str]
    enableIpv6: Optional[bool]
    enablePrivateNetworking: Optional[bool]
    enableMonitoring: Optional[bool]
    enableFloatingIP: Optional[bool]
    floatingIP: Optional[str]


class DropletDeploymentOptions(MachineOptions):
    doDroplet: DropletOptions


class DropletDefinition(MachineDefinition):
    @classmethod
    def get_type(cls) -> str:
        return "doDroplet"

    config: DropletDeploymentOptions

    auth_token: Optional[str]
    region: Optional[str]
    size: Optional[str]
    enable_ipv6: Optional[bool]
    enable_private_networking: Optional[bool]
    enable_monitoring: Optional[bool]
    enable_floating_ip: Optional[bool]
    floating_ip: Optional[str]

    def __init__(self, name: str, config: ResourceEval):
        super().__init__(name, config)

        if self.config.doDroplet.authToken:
            self.auth_token = self.config.doDroplet.authToken.strip()
        else:
            self.auth_token = None

        self.region = self.config.doDroplet.region
        self.size = self.config.doDroplet.size
        self.enable_ipv6 = self.config.doDroplet.enableIpv6
        self.enable_private_networking = self.config.doDroplet.enablePrivateNetworking
        self.enable_monitoring = self.config.doDroplet.enableMonitoring
        self.enable_floating_ip = self.config.doDroplet.enableFloatingIP
        self.floating_ip = self.config.doDroplet.floatingIP

    def show_type(self) -> str:
        return "{0} [{1}]".format(self.get_type(), self.region)


class DropletState(MachineState[DropletDefinition]):
    @classmethod
    def get_type(cls) -> str:
        return "doDroplet"

    # generic options
    # TODO: is state supposed to be commented?
    # state: int= attr_property("state", MachineState.MISSING, int)  # override
    public_ipv4: Optional[str] = attr_property("publicIpv4", None)
    public_ipv6: dict = attr_property("publicIpv6", {}, "json")
    default_gateway: Optional[str] = attr_property("defaultGateway", None)
    netmask: Optional[str] = attr_property("netmask", None)
    # droplet options
    enable_ipv6: Optional[bool] = attr_property("doDroplet.enableIpv6", False, bool)
    default_gateway6: Optional[str] = attr_property("defaultGateway6", None)
    region: Optional[str] = attr_property("doDroplet.region", None)
    size: Optional[str] = attr_property("doDroplet.size", None)
    auth_token: Optional[str] = attr_property("doDroplet.authToken", None)
    droplet_id: Optional[str] = attr_property("doDroplet.dropletId", None)
    key_pair: Optional[str] = attr_property("doDroplet.keyPair", None)
    enable_monitoring: Optional[bool] = attr_property(
        "doDroplet.enableMonitoring", False, bool
    )
    enable_floating_ip: Optional[bool] = attr_property(
        "doDroplet.enableFloatingIP", False, bool
    )
    enable_private_networking: Optional[bool] = attr_property(
        "doDroplet.enablePrivateNetworking", False, bool
    )
    private_ipv4_address: Optional[str] = attr_property("doDroplet.privateIpv4", None)
    floating_ip: Optional[str] = attr_property("doDroplet.floatingIP", None)

    def __init__(self, depl: Deployment, name: str, id: RecordId) -> None:
        MachineState.__init__(self, depl, name, id)
        self.name: str = name

    def get_ssh_name(self) -> Optional[str]:
        return self.public_ipv4

    def get_ssh_flags(self, *args, **kwargs) -> List[str]:
        super_flags = super(DropletState, self).get_ssh_flags(*args, **kwargs)
        return super_flags + [
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-i",
            self.get_ssh_private_key_file(),
        ]

    def get_physical_spec(self) -> Function:
        def prefix_len(netmask):
            return bin(int(codecs.encode(socket.inet_aton(netmask), "hex"), 16)).count(
                "1"
            )

        networking = {
            "defaultGateway": self.default_gateway,
            "nameservers": ["67.207.67.2", "67.207.67.3"],  # default provided by DO
            ("dhcpcd", "enable"): False,
            ("interfaces", "ens3", "ipv4", "addresses"): [
                {"address": self.public_ipv4, "prefixLength": prefix_len(self.netmask)}
            ],
        }

        if self.private_ipv4_address and self.enable_private_networking:
            networking[("interfaces", "ens4", "ipv4", "addresses")] = [
                {"address": self.private_ipv4_address, "prefixLength": 16}
            ]

        if self.enable_floating_ip:
            networking[("interfaces", "ens3", "ipv4", "addresses")] += [
                {
                    "address": self.run_command(
                        "curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/anchor_ipv4/address",
                        capture_stdout=True,
                    ),
                    "prefixLength": 16,
                },
            ]

        if self.public_ipv6:
            networking[("interfaces", "ens3", "ipv6", "addresses")] = [
                {
                    "address": self.public_ipv6["address"],
                    "prefixLength": self.public_ipv6["prefixLength"],
                }
            ]
        if self.default_gateway6:
            networking["defaultGateway6"] = self.default_gateway6

        return Function(
            "{ ... }",
            {
                "imports": [
                    RawValue("<nixpkgs/nixos/modules/profiles/qemu-guest.nix>")
                ],
                "networking": networking,
                (
                    "boot",
                    "loader",
                    "grub",
                    "device",
                ): "nodev",  # keep ubuntu bootloader?
                ("fileSystems", "/"): {"device": "/dev/vda1", "fsType": "ext4"},
                ("users", "extraUsers", "root", "openssh", "authorizedKeys", "keys"): [
                    self.get_ssh_key_resource().public_key
                ],
                ("services", "do-agent", "enable"): self.enable_monitoring,
            },
        )

    def get_ssh_private_key_file(self) -> str:
        return self.write_ssh_private_key(self.get_ssh_key_resource().private_key)

    def get_ssh_key_resource(self) -> ssh_keypair.SSHKeyPairState:
        return cast(ssh_keypair.SSHKeyPairState, self.depl.active_resources["ssh-key"])

    def create_after(self, resources, defn) -> Set:
        # make sure the ssh key exists before we do anything else
        return {r for r in resources if isinstance(r, ssh_keypair.SSHKeyPairState)}

    def load_floating_ip(self, floating_ip: str) -> Optional[FloatingIP]:
        if not floating_ip:
            return None
        fip = FloatingIP(ip=floating_ip, token=self.get_auth_token())

        try:
            fip.load()
        except digitalocean.DataReadError:
            self.log("can't load floating ip")
        return fip

    def compare_floating_ip(self, defn: DropletDefinition) -> DigitalOceanStatus:
        if self.floating_ip == defn.floating_ip:
            # state and definition are up to date
            return StatusUnchanged()
        elif self.floating_ip and not defn.floating_ip:
            # state has a floating ip, definition does not
            return StatusDeleted()
        elif defn.floating_ip and not self.floating_ip:
            # floating ip requested but not yet assigned
            return StatusNew()
        elif self.floating_ip != defn.floating_ip:
            # the defined IP has changed from previous one assigned
            return StatusChanged()
        else:
            return StatusUnknown()

    def set_floating_ip(self, defn: DropletDefinition) -> None:
        status = self.compare_floating_ip(defn)
        manager = Manager(token=self.get_auth_token())
        if isinstance(status, StatusUnchanged):
            return
        elif isinstance(status, StatusDeleted):
            try:
                fip = self.load_floating_ip(self.floating_ip)
                fip.unassign()
                self.floating_ip = None
            except digitalocean.DataReadError:
                self.log("StatusDeleted: could not unassign floating ip")
        elif isinstance(status, StatusNew):
            try:
                fip = self.load_floating_ip(defn.floating_ip)
                if fip in manager.get_all_floating_ips():
                    fip.unassign()
                    time.sleep(1)
                fip.assign(droplet_id=self.droplet_id)
                self.floating_ip = defn.floating_ip
            except digitalocean.DataReadError:
                self.log("StatusNew: could not assign ip or unassign ip")
        elif isinstance(status, StatusChanged):
            try:
                state_fip = self.load_floating_ip(self.floating_ip)
                defn_fip = self.load_floating_ip(defn.floating_ip)
                if not state_fip and not defn_fip:
                    return
                try:
                    state_fip.unassign()
                    self.floating_ip = None
                except digitalocean.DataReadError:
                    self.log("could not unassign state_fip - already gone?")
                try:
                    defn_fip.unassign()
                    defn.floating_ip = None
                except digitalocean.DataReadError:
                    self.log("could not unassign defn_fip - already gone?")
                time.sleep(1)
                defn_fip.assign(droplet_id=self.droplet_id)
                self.floating_ip = defn.floating_ip
            except digitalocean.DataReadError:
                self.log("StatusChanged: could not assign floating ip")
        else:
            return

    def set_common_state(self, defn: DropletDefinition) -> None:
        super().set_common_state(defn)
        self.auth_token = defn.auth_token
        self.enable_monitoring = defn.enable_monitoring
        self.enable_floating_ip = defn.enable_floating_ip

        # Once it is on it can't be disabled with this api (or in console);
        # all we can do is not configure the ip on the interface in NixOS
        # Only need to enable it if it's not enabled at creation time and
        # is changed in the definition later
        # these checks make the DO api be called less often, is the idea anyway
        # yay state machines I don't understand
        if defn.enable_private_networking and not self.enable_private_networking:
            droplet = Droplet(id=self.droplet_id, token=self.get_auth_token())
            droplet.shutdown()
            self.wait_for_down()
            droplet.enable_private_networking()
            droplet.power_on()
            # TODO: is this necessary?
            droplet.load()
            self.private_ipv4_address = droplet.private_ip_address

        self.enable_private_networking = defn.enable_private_networking

        self.set_floating_ip(defn)

        # defn_floating_ip: Optional[
        #    digitalocean.FloatingIP
        # ] = None if not defn.floating_ip else digitalocean.FloatingIP(
        #     ip=defn.floating_ip, token=self.get_auth_token()
        # )

        # state_floating_ip: Optional[
        #    digitalocean.FloatingIP
        # ] = None if not self.floating_ip else digitalocean.FloatingIP(
        #     ip=self.floating_ip, token=self.get_auth_token()
        # )

        # if state_floating_ip:
        #     try:
        #         state_floating_ip.load()
        #     except Exception:
        #         self.log("assigned floating IP no longer exists")
        #         state_floating_ip = None

        # if defn_floating_ip:
        #     try:
        #         defn_floating_ip.load()
        #     except Exception:
        #         self.log("requested floating IP does not exist")
        #         defn_floating_ip = None

        # The definition of Floating IPs has changed and both are valid
        # This could get interesting if lots of reassigning is done in one go
        # if defn_floating_ip and state_floating_ip and (defn.floating_ip != self.floating_ip):
        #     print("changed")
        #     # droplet = digitalocean.Droplet(
        #     #     id=self.droplet_id, token=self.get_auth_token()
        #     # )
        #     # State IP has not been assigned to a different droplet yet
        #     # unassign it so that it can be used later
        #     # we don't want to unassign it if it is being used elsewhere
        #     if state_floating_ip.droplet.get("id") == self.droplet_id:
        #         state_floating_ip.unassign()
        #         print("unassign")
        #     elif "id" in defn_floating_ip.droplet:
        #         # Defined IP has already been assigned to a different droplet
        #         # unassign it so that it can be used on this one
        #         print("unassign 2")
        #         defn_floating_ip.unassign()
        #         state_floating_ip.unassign()
        #     defn_floating_ip.assign(droplet_id=self.droplet_id)
        #     self.floating_ip = defn.floating_ip
        # # The droplet state does not have an IP but one has been defined
        # elif defn_floating_ip and not state_floating_ip:  #TODO is this self.floating_ip or state_floating_ip
        #     # Defined IP has already been assigned to a different droplet
        #     # unassign it so that it can be used on this one
        #     if "id" in defn_floating_ip.droplet:
        #         print("unassign 4")
        #         defn_floating_ip.unassign()
        #     # defn_floating_ip.assign(droplet_id=self.droplet_id)
        #     # self.floating_ip = defn.floating_ip
        # # The droplet had a floating IP but does not have one defined now
        # # remove it from the state and unassign IFF the droplet id matches
        # if state_floating_ip and not defn.floating_ip:
        #     if state_floating_ip.droplet["id"] is self.droplet_id:
        #         print("unassign 3")
        #         state_floating_ip.unassign()
        #     self.floating_ip = None

        # if defn.floating_ip:
        #     droplet = digitalocean.Droplet(
        #         id=self.droplet_id, token=self.get_auth_token()
        #     )
        #     floatingIp = digitalocean.FloatingIP(
        #         ip=defn.floating_ip, token=self.get_auth_token()
        #     )
        #     floatingIp.load()
        #     if floatingIp.droplet:
        #         # it will error if you try to assign twice
        #         if floatingIp.droplet["id"] is self.droplet_id:
        #             pass
        #         else:
        #             # TODO: handle if the floating ip has changed
        #             pass
        #     else:
        #         # TODO: might need to unassign if it's already assigned to a different droplet?
        #         floatingIp.assign(droplet_id=self.droplet_id)

    def get_auth_token(self) -> Optional[str]:
        return os.environ.get("DIGITAL_OCEAN_AUTH_TOKEN", self.auth_token)

    def destroy(self, wipe: bool = False) -> bool:
        self.log("destroying droplet {}".format(self.droplet_id))
        try:
            droplet = Droplet(id=self.droplet_id, token=self.get_auth_token())
            droplet.destroy()
        except digitalocean.baseapi.NotFoundError:
            self.log("droplet not found - assuming it's been destroyed already")
        self.public_ipv4 = None
        self.droplet_id = None

        return True

    def create(self, defn, check, allow_reboot: bool, allow_recreate: bool) -> None:
        try:
            ssh_key = self.get_ssh_key_resource()
        except KeyError:
            raise Exception(
                "Please specify a ssh-key resource (resources.sshKeyPairs.ssh-key = {})."
            )

        self.set_common_state(defn)

        if self.droplet_id is not None:
            return

        self.manager = Manager(token=self.get_auth_token())
        droplet = Droplet(
            token=self.get_auth_token(),
            name=self.name,
            region=defn.region,
            ipv6=defn.enable_ipv6,
            monitoring=defn.enable_monitoring,
            private_networking=defn.enable_private_networking,
            ssh_keys=[ssh_key.public_key],
            image="ubuntu-16-04-x64",  # only for lustration
            size_slug=defn.size,
        )

        self.log_start("creating droplet ...")
        droplet.create()

        status = "in-progress"
        while status == "in-progress":
            actions = droplet.get_actions()
            for action in actions:
                action.load()
                if action.status != "in-progress":
                    status = action.status
            time.sleep(1)
            self.log_continue("[{}] ".format(status))

        if status != "completed":
            raise Exception("unexpected status: {}".format(status))

        droplet.load()
        self.droplet_id = droplet.id
        self.public_ipv4 = droplet.ip_address
        self.private_ipv4_address = droplet.private_ip_address
        self.enable_private_networking = defn.enable_private_networking
        self.enable_monitoring = defn.enable_monitoring
        self.enable_floating_ip = defn.enable_floating_ip
        self.log_end("{}".format(droplet.ip_address))

        for n in droplet.networks["v4"]:
            if n["ip_address"] == self.public_ipv4:
                self.default_gateway = n["gateway"]

        self.netmask = droplet.networks["v4"][0]["netmask"]

        first_ipv6 = {}
        first_gw6 = None
        if "v6" in droplet.networks:
            public_ipv6_networks = [
                n for n in droplet.networks["v6"] if n["type"] == "public"
            ]
            if len(public_ipv6_networks) > 0:
                # The DigitalOcean API does not expose an explicit
                # default interface or gateway, so assume this is it.
                first_ipv6["address"] = public_ipv6_networks[0]["ip_address"]
                first_ipv6["prefixLength"] = public_ipv6_networks[0]["netmask"]
                first_gw6 = public_ipv6_networks[0]["gateway"]
        self.public_ipv6 = first_ipv6
        self.default_gateway6 = first_gw6

        # run modified nixos-infect
        # - no reboot
        # - predictable network interface naming (ens3 etc)
        self.wait_for_ssh()
        self.log_start("running nixos-infect")
        self.run_command("bash </dev/stdin 2>&1", stdin=open(infect_path))
        self.reboot_sync()

    def reboot(self, hard: bool = False) -> None:
        if hard:
            self.log("sending hard reset to droplet...")
            droplet = Droplet(id=self.droplet_id, token=self.get_auth_token())
            droplet.reboot()
            self.wait_for_ssh()
            self.state = self.STARTING
        else:
            MachineState.reboot(self, hard=hard)
