from unittest import TestCase

import timeutil


class TimeUtilTest(TestCase):

    def test_parse_interval(self):
        self.assertEqual(timeutil.parse_interval('350'), 350)
        self.assertEqual(timeutil.parse_interval('20000s'), 20000)
        self.assertEqual(timeutil.parse_interval('10m'), 600)
        self.assertEqual(timeutil.parse_interval('2h'), 7200)
        self.assertEqual(timeutil.parse_interval('10d'), 864000)
        self.assertEqual(timeutil.parse_interval('0'), 0)
        self.assertEqual(timeutil.parse_interval('0m'), 0)
        self.assertEqual(timeutil.parse_interval('-3'), None)
        self.assertEqual(timeutil.parse_interval('10u'), None)
        self.assertEqual(timeutil.parse_interval('abc'), None)
        self.assertEqual(timeutil.parse_interval(''), None)


