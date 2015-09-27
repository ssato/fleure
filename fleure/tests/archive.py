#
# Copyright (C) 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring, protected-access
from __future__ import absolute_import

import os.path
import os
import unittest

import fleure.archive as TT
import fleure.utils
import fleure.tests.common


def touch(filepath):
    open(filepath, 'w').write("\n")


class Test00(unittest.TestCase):

    def setUp(self):
        self.workdir = fleure.tests.common.setup_workdir()

    def tearDown(self):
        fleure.tests.common.cleanup_workdir(self.workdir)

    def test_10__is_bad_path(self):
        thisfile = os.path.abspath(__file__)
        symlink = os.path.join(self.workdir, "symlink")

        os.symlink(thisfile, symlink)
        self.assertTrue(TT._is_bad_path(symlink, stat=True))

        # hdlink = os.path.join(self.workdir, "hardlink")
        # It cannot be created as it should be a cross-device link:
        # os.link(thisfile, hdlink)
        # self.assertTrue(TT._is_bad_path(hdlink, **opts))

    def test_20__subproc_communicate__success(self):
        self.assertTrue(TT._subproc_communicate(":")[1] is None)
        self.assertEquals(TT._subproc_communicate("echo OK")[0], "OK\n")

    def test_30_safe_untar(self):
        thisfile = os.path.abspath(__file__)
        arcfile = os.path.join(self.workdir, "test.tar.xz")
        destdir = os.path.join(self.workdir, "out")
        otherfile = os.path.join(self.workdir, "aaa.txt")

        os.makedirs(destdir)
        os.chdir(self.workdir)

        TT._subproc_communicate("ln -s %s ." % thisfile)
        touch(otherfile)
        TT._subproc_communicate("tar --xz -cvf %s ." % arcfile)

        TT.safe_untar(arcfile, destdir)

        filepath = os.path.join(destdir, os.path.basename(thisfile))
        self.assertFalse(os.path.exists(filepath))
        self.assertFalse(os.path.isfile(filepath))
        self.assertTrue(os.path.exists(otherfile))
        self.assertTrue(os.path.isfile(otherfile))

    def test_40_safe_unzip(self):
        thisfile = os.path.abspath(__file__)
        arcfile = os.path.join(self.workdir, "test.zip")
        destdir = os.path.join(self.workdir, "out")
        otherfile = os.path.join(self.workdir, "aaa.txt")

        os.makedirs(destdir)
        os.chdir(self.workdir)

        TT._subproc_communicate("ln -s %s ." % thisfile)
        touch(otherfile)
        TT._subproc_communicate("zip -r %s ." % arcfile)

        TT.safe_unzip(arcfile, destdir)

        filepath = os.path.join(destdir, os.path.basename(thisfile))
        self.assertFalse(os.path.exists(filepath))
        self.assertFalse(os.path.isfile(filepath))
        self.assertTrue(os.path.exists(otherfile))
        self.assertTrue(os.path.isfile(otherfile))


class Test10(unittest.TestCase):

    def setUp(self):
        self.workdir = fleure.tests.common.setup_workdir()

    def tearDown(self):
        fleure.tests.common.cleanup_workdir(self.workdir)

    def test_60_extract_rpmdb_archive__targz(self):
        if not os.path.exists("/var/lib/rpm/Packages"):
            return  # Not RHEL/Fedora/CentOS/...

        root = os.path.join(self.workdir, "sysroot")
        arcfile = os.path.join(self.workdir, "rpmdb.tar.gz")
        os.makedirs(root)

        cmd_s = "tar zcvf %s /var/lib/rpm/[A-Z]*" % arcfile
        TT._subproc_communicate(cmd_s)

        (root2, errors) = TT.extract_rpmdb_archive(arcfile, root)

        self.assertTrue(fleure.utils.check_rpmdb_root(root), errors)
        self.assertTrue(fleure.utils.check_rpmdb_root(root2), errors)

    def test_62_extract_rpmdb_archive__zip(self):
        if not os.path.exists("/var/lib/rpm/Packages"):
            return

        root = os.path.join(self.workdir, "sysroot")
        arcfile = os.path.join(self.workdir, "rpmdb.zip")
        os.makedirs(root)

        cmd_s = "zip %s /var/lib/rpm/[A-Z]*" % arcfile
        TT._subproc_communicate(cmd_s)

        (root2, errors) = TT.extract_rpmdb_archive(arcfile, root)

        self.assertTrue(fleure.utils.check_rpmdb_root(root), errors)
        self.assertTrue(fleure.utils.check_rpmdb_root(root2), errors)

# vim:sw=4:ts=4:et:
