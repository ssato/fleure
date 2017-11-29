#
# Copyright (C) 2013 - 2017 Red Hat, Inc.
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
import fleure.utils as TT


class Test00(unittest.TestCase):

    def test_30_subproc_call(self):
        (rcode, out, err) = TT.subproc_call(":")
        self.assertEqual(rcode, 0)
        self.assertEqual(out, '')
        self.assertEqual(err, '')

        (rcode, out, err) = TT.subproc_call("echo OK")
        self.assertEqual(rcode, 0)
        self.assertEqual(out, "OK\n")
        self.assertEqual(err, '')

        (rcode, out, err) = TT.subproc_call("echo NG > /dev/stderr && false")
        self.assertNotEqual(rcode, 0)
        self.assertEqual(out, '')
        self.assertEqual(err, "NG\n")

    def test_32_subproc_call__timeout(self):
        (rcode, out, err) = TT.subproc_call("sleep 10", timeout=2)
        self.assertNotEqual(rcode, 0)
        self.assertFalse(out, out)
        self.assertFalse(err, err)

# vim:sw=4:ts=4:et:
