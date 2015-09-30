#
# Copyright (C) 2014 - 2015 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
import fleure.dnfbase as TT
import fleure.utils
import fleure.tests.common

import os.path
import os
import shutil
import unittest


if fleure.tests.common.is_rhel_or_fedora():
    class Test10(unittest.TestCase):

        def test_12__init__with_root(self):
            base = TT.Base(root="/tmp")
            self.assertTrue(isinstance(base, TT.Base))

            conf = base.base.conf
            self.assertEquals(conf.installroot, u"/tmp")
            self.assertEquals(conf.logdir, u"/tmp/var/log")

        def test_14__init__with_cachedir(self):
            cachedir = u"/tmp/aaa"
            base = TT.Base(cachedir=cachedir)
            self.assertTrue(isinstance(base, TT.Base))
            self.assertEquals(base.base.conf.cachedir, cachedir,
                              "%s vs. %s" % (base.base.conf.cachedir,
                                             cachedir))

    class Test20(unittest.TestCase):

        def setUp(self):
            self.workdir = fleure.tests.common.setup_workdir()

            rpmdbdir = os.path.join(self.workdir, fleure.globals.RPMDB_SUBDIR)
            os.makedirs(rpmdbdir)

            for dbn in fleure.globals.RPMDB_FILENAMES:
                shutil.copy(os.path.join('/', fleure.globals.RPMDB_SUBDIR,
                                         dbn),
                            rpmdbdir)

            self.base = TT.Base(self.workdir)
            self.base.prepare()

        def tearDown(self):
            fleure.tests.common.cleanup_workdir(self.workdir)

        def test_20_list_installed(self):
            pkgs = self.base.list_installed()
            self.assertTrue(isinstance(pkgs, list))
            self.assertTrue(bool(pkgs))

        def test_30_list_updates(self):
            pkgs = self.base.list_updates()
            self.assertTrue(isinstance(pkgs, list))

        def test_40_list_errata(self):
            ers = self.base.list_errata()
            self.assertTrue(isinstance(ers, list))

# vim:sw=4:ts=4:et:
