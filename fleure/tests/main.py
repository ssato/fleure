#
# Copyright (C) 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import os.path
import tablib
import unittest

import fleure.main as TT
import fleure.tests.common


class Test00(unittest.TestCase):

    def setUp(self):
        self.workdir = fleure.tests.common.setup_workdir()

    def tearDown(self):
        fleure.tests.common.cleanup_workdir(self.workdir)

    def test_10_dump_xl(self):
        tds = tablib.Dataset()
        tds.title = "Test"
        tds.headres = ('a', 'b', 'c')
        tds.append((1, 2, 3))

        xlspath = os.path.join(self.workdir, "test.xls")
        TT.dump_xls([tds], xlspath)

        self.assertTrue(os.path.exists(xlspath))

# vim:sw=4:ts=4:et:
