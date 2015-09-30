#
# Copyright (C) 2014 - 2015 Red Hat, Inc.
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

import fleure.yumbase as TT
import fleure.utils
import fleure.tests.common


if fleure.tests.common.is_rhel_or_fedora():
    class Test00(unittest.TestCase):

        def setUp(self):
            self.workdir = fleure.tests.common.setup_workdir()
            fleure.tests.common.copy_rpmdb_files(self.workdir)
            self.base = TT.Base(self.workdir)

        def tearDown(self):
            fleure.tests.common.cleanup_workdir(self.workdir)

        def test_10_create(self):
            self.assertTrue(isinstance(self.base.base, TT.yum.YumBase))

        def test_30_list_installed(self):
            self.base.prepare()
            pkgs = self.base.list_installed()

            self.assertTrue(isinstance(pkgs, list))
            self.assertNotEquals(pkgs, [])

        def test_40_list_errata(self):
            self.base.prepare()
            ers = self.base.list_errata()
            self.assertTrue(isinstance(ers, list))

        def test_50_list_updates(self):
            self.base.prepare()
            pkgs = self.base.list_updates()
            self.assertTrue(isinstance(pkgs, list))

# vim:sw=4:ts=4:et:
