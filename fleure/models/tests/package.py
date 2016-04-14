#
# Copyright (C) 2016 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring,invalid-name,no-member
from __future__ import absolute_import

import sqlalchemy
import unittest
from sqlalchemy.orm import scoped_session, sessionmaker

import fleure.models.package as TT


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


class Test10(unittest.TestCase):

    def setUp(self):
        self.engine = sqlalchemy.create_engine("sqlite:///:memory:")
        self.session = scoped_session(sessionmaker(bind=self.engine))

        TT.Base.query = self.session.query_property()
        TT.Base.metadata.create_all(bind=self.engine)

    def tearDown(self):
        self.session.remove()

    def test_00_empty_db(self):
        pkgs = self.session.query(TT.Package).all()
        self.assertEquals(len(pkgs), 0)

    def test_10_add_one(self):
        pkg0 = TT.Package("kernel", "2.6.38.8", "32", "x86_64")
        self.session.add(pkg0)
        self.session.commit()

        pkgs = self.session.query(TT.Package).all()
        self.assertEquals(len(pkgs), 1)

# vim:sw=4:ts=4:et:
