#
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato at redhat.com>
#
# This software is licensed to you under the GNU General Public License,
# version 3 (GPLv3). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. You should have received a copy of GPLv3 along with this
# software; if not, see http://www.gnu.org/licenses/gpl.html
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import unittest

import fleure.rpmutils as TT
import fleure.tests.common


class Test00(unittest.TestCase):

    def setUp(self):
        self.workdir = fleure.tests.common.setup_workdir()
        fleure.tests.common.copy_rpmdb_files(self.workdir)

    def tearDown(self):
        fleure.tests.common.cleanup_workdir(self.workdir)

    def test_20_check_rpmdb_root(self):
        self.assertTrue(TT.check_rpmdb_root(self.workdir))

# vim:sw=4:ts=4:et:
