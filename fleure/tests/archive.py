#
# Copyright (C) 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring, protected-access, invalid-name
from __future__ import absolute_import

import os.path
import os
import unittest

import fleure.archive as TT
import fleure.globals
import fleure.tests.common
import fleure.rpmutils

try:
    import fleure.utils
    _RPM_DB_FOUND = os.path.exists("/var/lib/rpm/Packages")
except ImportError:
    _RPM_DB_FOUND = False


def touch(filepath):
    open(filepath, 'w').write("\n")


class Test00(unittest.TestCase):

    def setUp(self):
        self.workdir = fleure.tests.common.setup_workdir()

    def tearDown(self):
        fleure.tests.common.cleanup_workdir(self.workdir)

    def test_10__is_link__symlink(self):
        thisfile = os.path.abspath(__file__)
        symlink = os.path.join(self.workdir, "symlink")

        os.symlink(thisfile, symlink)
        self.assertTrue(TT._is_link(symlink))

    def test_12__is_link__hardlink(self):
        orgfile = "org.txt"
        hdlink = "link.txt"

        with fleure.tests.common.Chdir(self.workdir):
            open(orgfile, 'w').write("Hello\n")
            os.link(orgfile, hdlink)

        hdlink = os.path.join(self.workdir, hdlink)
        orgfile = os.path.join(self.workdir, orgfile)

        self.assertTrue(TT._is_link(hdlink))
        # self.assertFalse(TT._is_link(orgfile))  # Cannot distinguish it.

    def test_20__is_bad_path(self):
        pass

    def test_40_safe_untar(self):
        thisfile = os.path.abspath(__file__)
        otherfile = "aaa.txt"
        arcfile = "test.tar.gz"

        with fleure.tests.common.Chdir(self.workdir):
            fleure.utils.subproc_call("ln -s %s ." % thisfile)
            touch(otherfile)
            fleure.utils.subproc_call("tar zcvf %s ." % arcfile)

        destdir = os.path.join(self.workdir, "out")
        os.makedirs(destdir)

        TT.safe_untar(os.path.join(self.workdir, arcfile), destdir)

        filepath = os.path.join(destdir, os.path.basename(thisfile))
        otherpath = os.path.join(destdir, otherfile)

        self.assertTrue(os.path.exists(otherpath))
        self.assertTrue(os.path.isfile(otherpath))
        self.assertFalse(os.path.exists(filepath))
        self.assertFalse(os.path.isfile(filepath))

    def test_50_safe_unzip(self):
        thisfile = os.path.abspath(__file__)
        otherfile = "aaa.txt"
        arcfile = "test.zip"

        with fleure.tests.common.Chdir(self.workdir):
            fleure.utils.subproc_call("ln -s %s ." % thisfile)
            touch(otherfile)
            fleure.utils.subproc_call("zip -ry %s ." % arcfile)

        destdir = os.path.join(self.workdir, "out")
        os.makedirs(destdir)

        TT.safe_unzip(os.path.join(self.workdir, arcfile), destdir)

        filepath = os.path.join(destdir, os.path.basename(thisfile))
        otherpath = os.path.join(destdir, otherfile)

        self.assertTrue(os.path.exists(otherpath))
        self.assertTrue(os.path.isfile(otherpath))
        # Note: It looks like zipfile.extrat don't extract symlink as it is.
        # self.assertFalse(os.path.exists(filepath))
        # self.assertFalse(os.path.isfile(filepath))
        self.assertTrue(os.path.exists(filepath))

    def test_70_archive_report(self):
        filenames = fleure.globals.REPORT_FILES
        for fname in filenames:
            touch(os.path.join(self.workdir, fname))

        output = TT.archive_report(self.workdir, filenames=filenames)
        self.assertTrue(os.path.exists(output))

        topdir = os.path.basename(self.workdir)
        paths = sorted(os.path.join(topdir, fn) for fn in filenames)

        with TT.zipfile.ZipFile(output) as zipf:
            self.assertEquals(sorted(zipf.namelist()), paths)


class Test10(unittest.TestCase):

    def setUp(self):
        self.workdir = fleure.tests.common.setup_workdir()

    def tearDown(self):
        fleure.tests.common.cleanup_workdir(self.workdir)

    @fleure.tests.common.skip_if_not(_RPM_DB_FOUND)
    def test_60_extract_rpmdb_archive__targz(self):
        root = os.path.join(self.workdir, "sysroot")
        arcfile = os.path.join(self.workdir, "rpmdb.tar.gz")
        os.makedirs(root)

        cmd_s = "tar zcvf %s /var/lib/rpm/[A-Z]*" % arcfile
        fleure.utils.subproc_call(cmd_s)

        (root2, errors) = TT.extract_rpmdb_archive(arcfile, root)

        self.assertTrue(fleure.rpmutils.check_rpmdb_root(root), errors)
        self.assertTrue(fleure.rpmutils.check_rpmdb_root(root2), errors)

    @fleure.tests.common.skip_if_not(_RPM_DB_FOUND)
    def test_62_extract_rpmdb_archive__zip(self):
        root = os.path.join(self.workdir, "sysroot")
        arcfile = os.path.join(self.workdir, "rpmdb.zip")
        os.makedirs(root)

        cmd_s = "zip %s /var/lib/rpm/[A-Z]*" % arcfile
        fleure.utils.subproc_call(cmd_s)

        (root2, errors) = TT.extract_rpmdb_archive(arcfile, root)

        self.assertTrue(fleure.rpmutils.check_rpmdb_root(root), errors)
        self.assertTrue(fleure.rpmutils.check_rpmdb_root(root2), errors)

# vim:sw=4:ts=4:et:
