#
# Copyright (C) 2014 - 2016 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato at redhat.com>
# License: AGPLv3+
#
# pylint: disable=missing-docstring
from __future__ import absolute_import
import fleure.tests.common

try:
    import fleure.backends.yumbase as TT
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
        self.assertNotEqual(pkgs, [])

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
