#
# Copyright (C) 2014 - 2016 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import unittest
import fleure.tests.common

try:
    import fleure.utils  # rpm, yum modules
    import fleure.backends.dnfbase as TT  # dnf
except ImportError:
    TT = None


class Test10(unittest.TestCase):

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_12__init__with_root(self):
        base = TT.Base(root="/tmp")
        self.assertTrue(isinstance(base, TT.Base))

        conf = base.base.conf
        self.assertEquals(conf.installroot, u"/tmp")
        self.assertEquals(conf.logdir, u"/tmp/var/log")

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_14__init__with_cachedir(self):
        cachedir = u"/tmp/aaa"
        base = TT.Base(cachedir=cachedir)
        self.assertTrue(isinstance(base, TT.Base))
        self.assertEquals(base.base.conf.cachedir, cachedir,
                          "%s vs. %s" % (base.base.conf.cachedir,
                                         cachedir))


class Test20(fleure.tests.common.TestsWithRpmDB):

    def setUp(self):
        super(Test20, self).setUp()
        self.base = TT.Base(self.workdir)
        self.base.prepare()

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_20_list_installed(self):
        pkgs = self.base.list_installed()
        self.assertTrue(isinstance(pkgs, list))
        self.assertTrue(bool(pkgs))

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_30_list_updates(self):
        pkgs = self.base.list_updates()
        self.assertTrue(isinstance(pkgs, list))

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_40_list_errata(self):
        ers = self.base.list_errata()
        self.assertTrue(isinstance(ers, list))

# vim:sw=4:ts=4:et:
