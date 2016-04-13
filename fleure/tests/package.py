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

    def setUp(self):
        self.ref = dict(origin="redhat", rebuilt=False, replaced=False,
                        from_others=False)

    def test_10_inspect_origin__genuine(self):
        origin = TT.inspect_origin("bash", TT.VENDOR_RH, "builder.redhat.com")
        self.assertTrue(dicts_equal(origin, self.ref))

    def test_12_inspect_origin__genuine_not_rh(self):
        origin = TT.inspect_origin("crash-trace-command", "Fujitsu Limited",
                                   "builder.redhat.com")
        self.assertTrue(dicts_equal(origin, self.ref))

    def test_13_inspect_origin__genuine_other_vendor_w_extras(self):
        origin = TT.inspect_origin("crash-trace-command", "Fujitsu Limited",
                                   "builder.redhat.com")
        self.assertTrue(dicts_equal(origin, self.ref))

    def test_14_inspect_origin__rebuilt(self):
        origin = TT.inspect_origin("bash", TT.VENDOR_RH, "localhost")
        self.ref["rebuilt"] = True
        self.assertTrue(dicts_equal(origin, self.ref), origin)

    def test_16_inspect_origin__replaced(self):
        origin = TT.inspect_origin("bash", "CentOS", "a.centos.org")
        self.ref.update(origin="centos", replaced=True)
        self.assertTrue(dicts_equal(origin, self.ref), origin)

    def test_18_inspect_origin__from_others(self):
        origin = TT.inspect_origin("ansible", "CentOS", "a.centos.org",
                                   extra_names=["ansible"])
        self.ref.update(origin="centos", from_others=True)
        self.assertTrue(dicts_equal(origin, self.ref), origin)

# vim:sw=4:ts=4:et:
