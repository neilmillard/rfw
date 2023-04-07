from unittest import TestCase

import cmdparse
from iptables import Rule


class CmdParseTest(TestCase):
    def test_parse_command_drop_input_eth0_ip(self):
        self.assertEqual(
            cmdparse.parse_command_path('/drop/input/eth0/5.6.7.8'),
            ('drop',
             Rule(chain='INPUT', num=None, pkts=None, bytes=None, target='DROP', prot='all', opt='--', inp='eth0',
                  out='*', source='5.6.7.8', destination='0.0.0.0/0', extra='')))

    def test_parse_command_drop_input_eth_ip(self):
        self.assertEqual(
            cmdparse.parse_command_path('/drop/input/eth /5.6.7.8/'),
            ('drop',
             Rule(chain='INPUT', num=None, pkts=None, bytes=None, target='DROP', prot='all', opt='--', inp='eth+',
                  out='*', source='5.6.7.8', destination='0.0.0.0/0', extra='')))

    def test_parse_command_drop_input_any_ip_port(self):
        self.assertEqual(
            cmdparse.parse_command_path('/drop/input/any/5.6.7.8:5678/'),
            ('drop',
             Rule(chain='INPUT', num=None, pkts=None, bytes=None, target='DROP', prot='tcp', opt='--', inp='*', out='*',
                  source='5.6.7.8', destination='0.0.0.0/0', extra='tcp spt:5678')))

    def test_parse_command_drop_output_any_ip_port(self):
        self.assertEqual(
            cmdparse.parse_command_path('/drop/output/any/5.6.7.8:5678/'),
            ('drop', Rule(chain='OUTPUT', num=None, pkts=None, bytes=None, target='DROP', prot='tcp', opt='--', inp='*',
                          out='*', source='0.0.0.0/0', destination='5.6.7.8', extra='tcp dpt:5678')))
