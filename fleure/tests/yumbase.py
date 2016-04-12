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
import fleure.tests.common

try:
    import fleure.yumbase as TT
    import fleure.utils
except ImportError:
    TT = None


class Test00(fleure.tests.common.TestsWithRpmDB):

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_10_create(self):
        base = TT.Base(self.workdir)
        self.assertTrue(isinstance(base.base, TT.yum.YumBase))

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_30_list_installed(self):
        base = TT.Base(self.workdir)
        base.prepare()
        pkgs = base.list_installed()

        self.assertTrue(isinstance(pkgs, list))
        self.assertNotEquals(pkgs, [])

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_40_list_errata(self):
        base = TT.Base(self.workdir)
        base.prepare()
        ers = base.list_errata()
        self.assertTrue(isinstance(ers, list))

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_50_list_updates(self):
        base = TT.Base(self.workdir)
        base.prepare()
        pkgs = base.list_updates()
        self.assertTrue(isinstance(pkgs, list))

# vim:sw=4:ts=4:et:
