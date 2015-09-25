#
# Copyright (C) 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import os
import os.path
import shutil
import subprocess
import unittest

import fleure.config as TT
import fleure.utils
import fleure.tests.common


class Test00(unittest.TestCase):

    def setUp(self):
        self.workdir = fleure.tests.common.setup_workdir()

        rpmdbdir = os.path.join(self.workdir, fleure.utils.RPMDB_SUBDIR)
        os.makedirs(rpmdbdir)

        for dbn in fleure.utils.RPMDB_FILENAMES:
            src = os.path.join('/', fleure.utils.RPMDB_SUBDIR, dbn)
            if os.path.exists(src):
                shutil.copy(src, rpmdbdir)

    def tearDown(self):
        fleure.tests.common.cleanup_workdir(self.workdir)

    def test_20_setup_root__valid_root(self):
        self.assertEquals(TT.setup_root(self.workdir, None)[0], self.workdir)

    def test_22_setup_root__tar_xz_archive(self):
        txz = "rpmdb.tar.xz"
        cmd = "cd %s && timeout 60 tar --xz -cf %s var/lib/rpm/[A-Z]*" % \
            (self.workdir, txz)
        (out, err) = subprocess.Popen(cmd, shell=True).communicate()
        if err:
            raise ValueError("err=" + err)

        tpath = os.path.join(self.workdir, txz)
        (out, err) = TT.setup_root(tpath, self.workdir)
        print "out=%s, err=%s" % (out, err)
        self.assertEquals(out, self.workdir)

    def test_24_setup_root__zip_archive(self):
        txz = "rpmdb.zip"
        cmd = ("cd %s && timeout 60 zip %s var/lib/rpm/[A-Z]* && "
               "rm -rf var/" % (self.workdir, txz))
        (out, err) = subprocess.Popen(cmd, shell=True).communicate()
        if err:
            raise ValueError("err=" + err)

        tpath = os.path.join(self.workdir, txz)
        (out, err) = TT.setup_root(tpath, self.workdir)
        print "out=%s, err=%s" % (out, err)
        self.assertEquals(out, self.workdir)

# vim:sw=4:ts=4:et:
