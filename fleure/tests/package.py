#
# Copyright (C) 2016 Satoru SATOH <ssato at redhat.com>
# License: AGPLv3+
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import unittest
import fleure.package as TT
from fleure.tests.common import dicts_equal


class Test00(unittest.TestCase):

    def test_10_inspect_origin__genuine(self):
        origin = TT.inspect_origin("bash", TT.VENDOR_RH, "builder.redhat.com")
        ref = dict(origin="redhat", rebuilt=False, replaced=False)
        self.assertTrue(dicts_equal(origin, ref))

    def test_12_inspect_origin__genuine_other_vendor(self):
        origin = TT.inspect_origin("crash-trace-command", "Fujitsu Limited",
                                   "builder.redhat.com")
        ref = dict(origin="redhat", rebuilt=False, replaced=False)
        self.assertTrue(dicts_equal(origin, ref))

    def test_14_inspect_origin__genuine_other_vendor_w_extras(self):
        origin = TT.inspect_origin("crash-trace-command", "Fujitsu Limited",
                                   "builder.redhat.com", extra_names=[])
        ref = dict(origin="redhat", rebuilt=False, replaced=False)
        self.assertTrue(dicts_equal(origin, ref))

    def test_16_inspect_origin__rebuilt(self):
        origin = TT.inspect_origin("bash", TT.VENDOR_RH, "localhost")
        ref = dict(origin="redhat", rebuilt=True, replaced=False)
        self.assertTrue(dicts_equal(origin, ref), origin)

# vim:sw=4:ts=4:et:
