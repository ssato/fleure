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
    class Test00(unittest.TestCase):

        def setUp(self):
            self.workdir = fleure.tests.common.setup_workdir()

            rpmdbdir = os.path.join(self.workdir, fleure.utils.RPMDB_SUBDIR)
            os.makedirs(rpmdbdir)

            for dbn in fleure.utils.RPMDB_FILENAMES:
                shutil.copy(os.path.join('/', fleure.utils.RPMDB_SUBDIR, dbn),
                            rpmdbdir)

            self.base = TT.Base(self.workdir)

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
