from enum import Enum
from pyroute2 import NDB, WireGuard, IPRoute
import ipaddress
from ipaddress import IPv4Network, IPv6Network
import dateutil.parser
import datetime

class TunnelInterface:
    class TunnelType(Enum):
        WIREGUARD = 1

    def getbasename(self) -> str:
        raise NotImplementedError("getbasename() not implemented")
    
    def setup_interface(self) -> None:
        raise NotImplementedError("setup_interface() not implemented")
    
    def delete_interface(self) -> None:
        raise NotImplementedError("setup_interface() not implemented")

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

    def __init__(self, int_type: TunnelType, peer_addrs: list[IPv4Network | IPv6Network], local_addrs: list[IPv4Network | IPv6Network]):
        self.int_type = int_type
        self.ifname = self.__get_next_int_name_for_type()
        self.peer_addrs = peer_addrs
        self.local_addrs = local_addrs
        self.interface_created = False

    def __del__(self):
        self.delete_interface()

class WireguardTunnel(TunnelInterface):
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
        if self.interface_created != True:
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
        wg = WireGuard()

        # Get current interface info
        info = wg.info(self.ifname)

        # Return peer info
        return dict(dict(info[0]["attrs"])["WGDEVICE_A_PEERS"][0]["attrs"])

    # Is the peer more than peer_max_noact seconds without activity? TODO: CONFIG ITEM
    def is_peer_alive(self) -> bool:
        # Get peer info
        peer_info = self.__get_peer_info()

        # Parse last handshake datetime
        last_handshake = dateutil.parser.parse(peer_info["WGPEER_A_LAST_HANDSHAKE_TIME"]["latest handshake"])

        # Check if peer is dead
        return (datetime.datetime.now() - last_handshake).total_seconds() <= 300 # TODO: Add config entry for dead time
            
    def __init__(self, peer_addrs, local_addrs, listen_port, peer_pubkey, own_privkey):
        self.peer_pubkey = peer_pubkey
        self.own_privkey = own_privkey
        self.listen_port = listen_port
        super().__init__(TunnelInterface.TunnelType.WIREGUARD, peer_addrs, local_addrs)