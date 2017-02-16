#
# Copyright (C) 2016 Satoru SATOH <ssato at redhat.com>
# License: MIT
#
# pylint: disable=missing-docstring,invalid-name,no-member
from __future__ import absolute_import

# import itertools
import unittest

import fleure.models.package as TT
import fleure.models.tests.common


PACKAGES = [TT.Package("kernel", "2.6.38.8", "32", "x86_64"),
            TT.Package("nss", "3.16.1-4", "1.el6_5", "x86_64", "0"),
            TT.Package("nss-util", "3.16.1-4", "1.el6_5", "x86_64", "0"),
            TT.Package("nspr", "4.10.6", "1.el6_5", "x86_64", "0")]


class Test00(unittest.TestCase):

    def setUp(self):
        # (origin, rebuilt, replaced, from_others)
        self.ref = ("redhat", False, False, False)

    def test_10_inspect_origin__genuine(self):
        origin = TT.inspect_origin("bash", TT.VENDOR_RH, "builder.redhat.com")
        self.assertEquals(origin, self.ref)

    def test_12_inspect_origin__genuine_not_rh(self):
        origin = TT.inspect_origin("crash-trace-command", "Fujitsu Limited",
                                   "builder.redhat.com")
        self.assertEquals(origin, self.ref)

    def test_13_inspect_origin__genuine_other_vendor_w_extras(self):
        origin = TT.inspect_origin("crash-trace-command", "Fujitsu Limited",
                                   "builder.redhat.com")
        self.assertEquals(origin, self.ref)

    def test_14_inspect_origin__rebuilt(self):
        origin = TT.inspect_origin("bash", TT.VENDOR_RH, "localhost")
        self.assertEquals(origin, ("redhat", True, False, False))

    def test_16_inspect_origin__replaced(self):
        origin = TT.inspect_origin("bash", "CentOS", "a.centos.org")
        self.assertEquals(origin, ("centos", False, True, False))

    def test_18_inspect_origin__from_others(self):
        origin = TT.inspect_origin("ansible", "CentOS", "a.centos.org",
                                   extras=["ansible"])
        self.assertEquals(origin, ("centos", False, False, True))


class Test10(fleure.models.tests.common.TestsWithSession):

    def test_00_empty_db(self):
        nevras = self.session.query(TT.NEVRA).all()
        self.assertEquals(len(nevras), 0)

    def test_10_add_one(self):
        pkg0 = TT.NEVRA("kernel", "2.6.38.8", "32", "x86_64")
        self.session.add(pkg0)
        self.session.commit()

        pkgs = self.session.query(TT.NEVRA).all()
        self.assertEquals(len(pkgs), 1)
        self.assertEquals(pkgs[0].nevra, "kernel 0:2.6.38.8-32 x86_64")


"""
class Test20(fleure.models.tests.common.TestsWithSession):

    def test_00_empty_db(self):
        pkgs = self.session.query(TT.Package).all()
        self.assertEquals(len(pkgs), 0)

    def test_10_add_one(self):
        self.session.add(PACKAGES[0])
        self.session.commit()

        pkgs = self.session.query(TT.Package).all()
        self.assertEquals(len(pkgs), 1)
        self.assertEquals(pkgs[0].nevra, PACKAGES[0].nevra)
        self.assertEquals(pkgs[0].rebuilt, PACKAGES[0].rebuilt)
        self.assertEquals(pkgs[0].from_others, PACKAGES[0].from_others)

    def test_20_add_some(self):
        ref = PACKAGES[1:]
        self.session.add_all(ref)
        self.session.commit()

        pkgs = self.session.query(TT.Package).all()
        self.assertEquals(len(pkgs), len(ref))
        for pkg_ref, pkg in itertools.izip_longest(ref, pkgs):
            self.assertEquals(pkg.nevra, pkg_ref.nevra)
            self.assertEquals(pkg.rebuilt, pkg_ref.rebuilt)
            self.assertEquals(pkg.from_others, pkg_ref.from_others)
"""

# vim:sw=4:ts=4:et:
