""" Manages network interfaces, addresses and firewalls """
# pylint: disable=trailing-whitespace, line-too-long, no-name-in-module, no-member
from ipaddress import IPv4Network, IPv6Network
import datetime
import ipaddress
import json
import typing
from enum import Enum
from typing import Protocol
import nftables

import dateutil.parser
from pyroute2 import NDB, WireGuard, IPRoute

class TunnelInterface(Protocol):
    """ Generic tunnel interface """
    class TunnelType(Enum):
        """ Possible tunnel types """
        WIREGUARD = 1

    int_type: TunnelType
    ifname: str
    peer_addrs: list[IPv4Network | IPv6Network]
    local_addrs: list[IPv4Network | IPv6Network]
    interface_created: bool

    def getbasename(self) -> str:
        """ Get interface base name, for example sown-wg """
    
    def setup_interface(self) -> None:
        """ Set up interface (create device, add IPs, etc) """
    
    def delete_interface(self) -> None:
        """ Delete interface (delete device, down interface) """

    # Find the next available name to give this interface
    def __get_next_int_name_for_type(self) -> str:
        ifname = None
        with IPRoute() as ipr: # This is pretty awful. Should fix
            interface = [None]
            ifidx = 0
            while len(interface) > 0:
                ifname = self.getbasename()+str(ifidx)
                interface = ipr.link_lookup(ifname=ifname)
                ifidx = ifidx + 1

        return ifname

    def __init__(self, int_type: TunnelType, peer_addrs: list[IPv4Network | IPv6Network], 
                 local_addrs: list[IPv4Network | IPv6Network], auto_name = True):
        self.int_type = int_type
        if auto_name:
            self.ifname = self.__get_next_int_name_for_type()
        self.peer_addrs = peer_addrs
        self.local_addrs = local_addrs
        self.interface_created = False

    def __del__(self):
        self.delete_interface()

class WireguardTunnel(TunnelInterface):
    """ Wireguard interface """
    def getbasename(self) -> str:
        return "sown-wg"
    
    # Create the interface
    def setup_interface(self) -> None:
        # Create wireguard interface
        with NDB() as ndb:
            with ndb.interfaces.create(kind='wireguard', ifname=self.ifname) as link:
                for local_addr in self.local_addrs:
                    link.add_ip(local_addr.with_prefixlen)
                link.set(state='up')
            ndb.close()

        # TODO: Set up firewall here!
                    
        wg = WireGuard()

        # Add peer configuration. For now very minimal.
        peer = {
            'public_key': self.peer_pubkey,
            'allowed_ips': [x.with_prefixlen for x in self.peer_addrs]
        }

        # Set up interface wireguard parameters
        wg.set(self.ifname, private_key=self.own_privkey, listen_port=self.listen_port, peer=peer)

        self.interface_created = True

    # Delete this interface
    def delete_interface(self) -> None:
        if self.interface_created is not True:
            return
        
        # Find the interface
        with IPRoute() as ipr:
            interface = ipr.link_lookup(ifname=self.ifname)
            if len(interface) == 0:
                raise RuntimeError("Cannot delete interface that doesn't exist!")
            
            # Actually delete the interface
            ipr.link("delete", index=interface[0])

        self.interface_created = False

    # Get peer info. We only set up one peer and this is only equipped to handle that!
    def __get_peer_info(self) -> dict:
        """ Get wireguard-specific peer information """
        wg = WireGuard()

        # Get current interface info
        info = wg.info(self.ifname)

        # Return peer info
        return dict(dict(info[0]["attrs"])["WGDEVICE_A_PEERS"][0]["attrs"])

    # Is the peer more than peer_max_noact seconds without activity? TODO: CONFIG ITEM
    def is_peer_alive(self) -> bool:
        """ Check if wireguard peer has handshaked recently """
        # Get peer info
        peer_info = self.__get_peer_info()

        # Parse last handshake datetime
        last_handshake = dateutil.parser.parse(
            peer_info["WGPEER_A_LAST_HANDSHAKE_TIME"]["latest handshake"]
        )

        # Check if peer is dead
        return (datetime.datetime.now() - last_handshake).total_seconds() <= 300 # TODO: Add config entry for dead time
            
    def __init__(self, peer_addrs, local_addrs, listen_port, peer_pubkey, own_privkey, auto_name=True):
        self.peer_pubkey = peer_pubkey
        self.own_privkey = own_privkey
        self.listen_port = listen_port
        super().__init__(TunnelInterface.TunnelType.WIREGUARD, peer_addrs, local_addrs, auto_name=auto_name)

class NFTablesEntry(Protocol):
    """ Manage firewall rules """
    class RuleType(Enum):
        """ Possible nftables rule types """
        ADD = "add"
        FLUSH = "flush"
        DELETE = "delete"
        REPLACE = "replace"
        CREATE = "create"
        INSERT = "insert"
        # As of now have not included RESET as this system is more for setting up dial-in firewalls
        # TODO: Review this

    class ObjectType(Enum):
        """ Possible nftables object types """
        TABLE = "table"
        SET = "set"
        CHAIN = "chain"
        RULE = "rule"
        # TODO: The rest?

    obj_type: ObjectType
    # TODO: methods

class NFTablesMatch:
    """ Describes a single nftables match expression """
    class OperatorType(Enum):
        """ nftables builtin operators """
        EQUAL = "eq"
        NOT_EQUAL = "ne"
        LESS_THAN = "lt"
        GREATER_THAN = "gt"
        LESS_EQUAL = "le"
        GREATER_EQUAL = "ge"
        NONE = "" # TODO: determine whether this is actually needed!

    left: str
    right: str
    op: OperatorType

    def __init__(self, left: str, op: OperatorType, right: str):
        """ Generic constructor for match expression """
        self.left = left
        self.right = right
        self.op = op

    def convert_to_dict(self):
        """ Convert into libnftables JSON schema compliant format """
        return {"left":self.left, "right":self.right, "op":self.op.value}

class NFTablesStatement: 
    """ Describes an nftables statement """
    class StatementType(Enum):
        """ nftables statement types """
        ACCEPT = {"name":"accept","needs_extra":False}
        DROP = {"name":"drop","needs_extra":False}
        QUEUE = {"name":"accept","needs_extra":None} # None means it **CAN** have extra
        CONTINUE = {"name":"continue","needs_extra":False}
        RETURN = {"name":"return","needs_extra":False}
        JUMP = {"name":"jump","needs_extra":True}
        GOTO = {"name":"goto","needs_extra":True}
        REJECT = {"name":"reject","needs_extra":None}
        COUNTER = {"name":"counter","needs_extra":None}
        LIMIT = {"name":"limit","needs_extra":True}
        DNAT = {"name":"dnat","needs_extra":True}
        SNAT = {"name":"snat","needs_extra":True}
        MASQUERADE = {"name":"masquerade","needs_extra":False}

    s_type: StatementType
    extra: str # For types that need it, for instance `dnat [[to 192.168.1.1]]` == {type: DNAT, extra: "to 192.168.1.1"} 

    def __init__(self, s_type: StatementType, extra: typing.Optional[str] = None):
        """ Generic constructor """#
        if s_type.value["needs_extra"] is not False and extra is None:
            raise ValueError("Extra information must be provided for this statment type: "+s_type.name)
        if s_type.value["needs_extra"] is False and extra is not None:
            raise ValueError("Extra information must not be provided for this statement type: "+s_type.name)
        self.s_type = s_type
        self.extra = extra

    def convert_to_dict(self):
        """ Convert into libnftables JSON schema compliant format """
        return {self.s_type.value["name"]: self.extra}

