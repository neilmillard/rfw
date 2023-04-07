from unittest import TestCase

import iputil


class IpUtilTest(TestCase):

    def test_ip2long(self):
        self.assertEqual(iputil.ip2long('1.2.3.4'), 16909060)
        self.assertEqual(iputil.ip2long('1.2.3.250'), 16909306)
        self.assertEqual(iputil.ip2long('250.2.3.4'), 4194435844)
        self.assertEqual(iputil.ip2long('129.2.3.129'), 2164392833)

    def test_cidr2range(self):
        self.assertEqual(iputil.cidr2range('1.2.3.4'), (16909060, 16909060))
        self.assertEqual(iputil.cidr2range('1.2.3.4/32'), (16909060, 16909060))
        self.assertEqual(iputil.cidr2range('1.2.3.4/31'), (16909060, 16909061))
        self.assertEqual(iputil.cidr2range('1.2.3.4/30'), (16909060, 16909063))
        self.assertEqual(iputil.cidr2range('1.2.3.4/0'), (0, 4294967295))
        self.assertEqual(iputil.cidr2range('129.2.3.129/28'), (2164392832, 2164392847))

    def test_ip_in_list(self):
        self.assertEqual(iputil.ip_in_list('1.2.0.0/16', ['1.2.3.4']), True)

    def test_extract_endpoint(self):
        ip, port = iputil.extract_endpoint('127.0.0.1:7865')
        self.assertEqual('127.0.0.1', ip)
        self.assertEqual('7865', port)

        ip, port = iputil.extract_endpoint('127.0.0.1')
        self.assertEqual('127.0.0.1', ip)
        self.assertEqual(None, port)

        ip, port = iputil.extract_endpoint('5.c.7.6:6543')
        self.assertEqual(False, ip)
        self.assertEqual('6543', port)

