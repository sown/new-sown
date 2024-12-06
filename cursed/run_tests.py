# pylint: skip-file

import unittest
import ipaddress
from pyroute2 import NDB, WireGuard, IPRoute

class TestWireguardTunnel(unittest.TestCase):
    def test_wg_interface_lifecycle(self):
        import modules.networking
        tun = modules.networking.WireguardTunnel(
            [ipaddress.ip_network("192.0.0.2/32")],
            [ipaddress.ip_network("192.0.0.1/32")],
            2525,
            'Xp1hqSAy/FHGOqqwygAPUcWBG0ub6bwHcE6/5gXegQQ=',
            'uPY4uKjZqRRQLatbWW2EQ/nGKrdqV0M9X32APYju7Vs=',
            auto_name = False
        )
        tun.ifname = "testing-if99"

        try:
            tun.setup_interface()

            self.assertTrue(tun.interface_created) # Do we think we have an interface?

            with IPRoute() as ipr:
                interface = ipr.link_lookup(ifname=tun.ifname)
                self.assertEqual(len(interface), 1) # Do we have exactly one interface under the correct name?

            self.assertFalse(tun.is_peer_alive()) # Is our fictional peer dead?
        finally:
            tun.delete_interface()

        with IPRoute() as ipr:
                interface = ipr.link_lookup(ifname=tun.ifname)
                self.assertEqual(len(interface), 0) # Have we succesfully got rid of it?

class TestNFTablesFeatures(unittest.TestCase):
    def test_nftables_build_simple_statement(self):
        from modules.networking import NFTablesStatement
        statement = NFTablesStatement(NFTablesStatement.StatementType.ACCEPT)

        self.assertEqual(statement.convert_to_dict(), {"accept":None})

    def test_nftables_build_complex_statement(self):
        from modules.networking import NFTablesStatement
        statement = NFTablesStatement(NFTablesStatement.StatementType.REJECT,"with icmpv6 type no-route")

        self.assertEqual(statement.convert_to_dict(), {"reject":"with icmpv6 type no-route"})

    def test_nftables_match(self):
        from modules.networking import NFTablesMatch
        match = NFTablesMatch("ip length", NFTablesMatch.OperatorType.EQUAL, "1000")

        self.assertEqual(match.convert_to_dict(), {"left":"ip length","right":"1000","op":"eq"})

# Run the tests!
if __name__ == '__main__':
    unittest.main()