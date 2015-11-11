#
# Copyright (C) 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import os.path
import tablib
import unittest
import fleure.tests.common
import fleure.decorators

try:
    import fleure.main as TT
except ImportError:
    TT = None


class Test00(unittest.TestCase):

    def setUp(self):
        self.workdir = fleure.tests.common.setup_workdir()

    def tearDown(self):
        fleure.tests.common.cleanup_workdir(self.workdir)

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_10_dump_xl(self):
        tds = tablib.Dataset()
        tds.title = "Test"
        tds.headres = ('a', 'b', 'c')
        tds.append((1, 2, 3))

        xlspath = os.path.join(self.workdir, "test.xls")
        fnc = getattr(TT, fleure.decorators.ref_to_original(TT.dump_xls))
        fnc([tds], xlspath)

        self.assertTrue(os.path.exists(xlspath))

# vim:sw=4:ts=4:et:
