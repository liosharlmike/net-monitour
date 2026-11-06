import unittest

from netwatch import parse_neighbor_output


class ParseNeighborOutputTests(unittest.TestCase):
    def test_extracts_valid_neighbor_entries(self):
        output = """192.168.1.12 dev wlan0 lladdr AA:BB:CC:DD:EE:FF REACHABLE
192.168.1.20 dev wlan0 lladdr 01:23:45:67:89:ab STALE
192.168.1.1 dev wlan0 INCOMPLETE
"""

        self.assertEqual(
            parse_neighbor_output(output),
            [
                {
                    "ip": "192.168.1.12",
                    "interface": "wlan0",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "state": "REACHABLE",
                },
                {
                    "ip": "192.168.1.20",
                    "interface": "wlan0",
                    "mac": "01:23:45:67:89:ab",
                    "state": "STALE",
                },
            ],
        )

    def test_ignores_malformed_mac_and_incomplete_rows(self):
        output = """192.168.1.2 dev wlan0 lladdr not-a-mac REACHABLE
192.168.1.3 dev wlan0 INCOMPLETE
"""
        self.assertEqual(parse_neighbor_output(output), [])


if __name__ == "__main__":
    unittest.main()