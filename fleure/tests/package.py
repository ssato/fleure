#
# Copyright (C) 2016 Satoru SATOH <ssato at redhat.com>
# License: AGPLv3+
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import unittest
import fleure.package as TT


class Test00(unittest.TestCase):

    def test_20_may_be_rebuilt(self):
        vendors = ("Red Hat, Inc.", "ZABBIX-JP", "Example, Inc.")
        self.assertFalse(TT.may_be_rebuilt(vendors[0],
                                           "abc.builder.redhat.com"))
        self.assertTrue(TT.may_be_rebuilt(vendors[0], "localhost"))
        self.assertTrue(TT.may_be_rebuilt(vendors[0], "localhost.localdomain"))
        self.assertFalse(TT.may_be_rebuilt(vendors[1],
                                           "abc.builder.redhat.com"))
        self.assertFalse(TT.may_be_rebuilt(vendors[2],
                                           "abc.builder.redhat.com"))
        self.assertFalse(TT.may_be_rebuilt(vendors[2],
                                           "localhost.localdomain"))

# vim:sw=4:ts=4:et:
