from unittest import TestCase

import iptables
from iptables import Rule


class IptablesTest(TestCase):

    # this function must be called 'load' to be able to instantiate mock Iptables
    def load(self, rules):
        inst = iptables.Iptables(rules)
        return inst

    def test_find(self):
        r1 = Rule(chain='INPUT', num='9', pkts='0', bytes='0', target='DROP', prot='all', opt='--', inp='eth+', out='*',
                  source='2.2.2.2', destination='0.0.0.0/0', extra='')
        r2 = Rule(chain='INPUT', num='10', pkts='0', bytes='0', target='ACCEPT', prot='tcp', opt='--', inp='*', out='*',
                  source='3.4.5.6', destination='0.0.0.0/0', extra='tcp spt:12345')
        r3 = Rule(chain='INPUT', num='1', pkts='14', bytes='840', target='DROP', prot='tcp', opt='--', inp='*', out='*',
                  source='0.0.0.0/0', destination='0.0.0.0/0', extra='tcp dpt:7393')
        r4 = Rule(chain='OUTPUT', num='1', pkts='0', bytes='0', target='DROP', prot='all', opt='--', inp='*',
                  out='tun+', source='0.0.0.0/0', destination='7.7.7.6', extra='')
        rules = [r1, r2, r3, r4]
        inst1 = self.load(rules)
        self.assertEqual(inst1.find({}), rules)
        self.assertEqual(inst1.find({'destination': ['0.0.0.0/0']}), [r1, r2, r3])
        self.assertEqual(inst1.find({'target': ['ACCEPT']}), [r2])
        self.assertEqual(inst1.find({'chain': ['OUTPUT']}), [r4])
        self.assertEqual(inst1.find({'chain': ['OUTPUT'], 'target': ['ACCEPT']}), [])
        self.assertEqual(inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target': ['ACCEPT']}), [r2])
        self.assertEqual(inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target': ['ACCEPT', 'DROP']}), rules)
        self.assertEqual(inst1.find({'chain': ['OUTPUT', 'INPUT'], 'target': ['DROP'], 'extra': ['']}), [r1, r4])

    def test_create_rule(self):
        """Test creating Rule objects in various ways
        """
        r1 = Rule({'chain': 'INPUT', 'source': '1.2.3.4'})
        self.assertEqual(str(r1),
                          "Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', "
                          "inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', extra='')")
        r2 = Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', inp='*', out='*',
                  source='1.2.3.4', destination='0.0.0.0/0', extra='')
        self.assertEqual(str(r2),
                          "Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', "
                          "inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', extra='')")
        r3 = Rule(['INPUT', None, None, None, None, 'all', '--', '*', '*', '1.2.3.4', '0.0.0.0/0', ''])
        self.assertEqual(str(r3),
                          "Rule(chain='INPUT', num=None, pkts=None, bytes=None, target=None, prot='all', opt='--', "
                          "inp='*', out='*', source='1.2.3.4', destination='0.0.0.0/0', extra='')")
