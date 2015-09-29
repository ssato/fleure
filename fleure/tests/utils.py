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
import fleure.utils as TT
import fleure.tests.common

import os
import os.path
import shutil
import unittest


class Test00(unittest.TestCase):

    def setUp(self):
        self.workdir = fleure.tests.common.setup_workdir()

        if fleure.tests.common.is_rhel_or_fedora():
            rpmdbdir = os.path.join(self.workdir, TT.RPMDB_SUBDIR)
            os.makedirs(rpmdbdir)

            for dbn in TT.RPMDB_FILENAMES:
                shutil.copy(os.path.join('/', TT.RPMDB_SUBDIR, dbn), rpmdbdir)

    def tearDown(self):
        fleure.tests.common.cleanup_workdir(self.workdir)

    def test_20_check_rpmdb_root(self):
        self.assertTrue(TT.check_rpmdb_root(self.workdir))

    def test_30_subproc_call(self):
        (rcode, out, err) = TT.subproc_call(":")
        self.assertEquals(rcode, 0)
        self.assertEquals(out, '')
        self.assertEquals(err, '')

        (rcode, out, err) = TT.subproc_call("echo OK")
        self.assertEquals(rcode, 0)
        self.assertEquals(out, "OK\n")
        self.assertEquals(err, '')

        (rcode, out, err) = TT.subproc_call("echo NG > /dev/stderr && false")
        self.assertNotEquals(rcode, 0)
        self.assertEquals(out, '')
        self.assertEquals(err, "NG\n")

    def test_32_subproc_call__timeout(self):
        (rcode, out, err) = TT.subproc_call("sleep 10", timeout=2)
        self.assertNotEquals(rcode, 0)
        self.assertFalse(out, out)
        self.assertFalse(err, err)

# vim:sw=4:ts=4:et:
