#
# Copyright (C) 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import collections
import os.path
import os
import unittest

import fleure.config as TT
import fleure.utils
import fleure.tests.common


class HostTest00(unittest.TestCase):

    def test_10___init__(self):
        (root, workdir) = ("/tmp", "/tmp/out")
        host = TT.Host(root, workdir=workdir)
        self.assertTrue(isinstance(host, TT.Host))

        self.assertEquals(host.root, root)
        self.assertEquals(host.workdir, workdir)
        self.assertTrue(host.hid is not None)
        self.assertEquals(host.tpaths, TT.Host.tpaths)

        self.assertTrue(host.repos is None)
        self.assertTrue(host.base is None)
        self.assertFalse(host.available)
        self.assertEquals(host.errors, [])


class HostTest10(unittest.TestCase):

    def setUp(self):
        self.workdir = fleure.tests.common.setup_workdir()
        fleure.tests.common.copy_rpmdb_files(self.workdir)

        workdir = os.path.join(self.workdir, "out")
        self.host = TT.Host(self.workdir, workdir=workdir)

    def tearDown(self):
        # fleure.tests.common.cleanup_workdir(self.workdir)
        pass

    def test_20_configure(self):
        self.host.configure()
        self.assertTrue(self.host.has_valid_root())

    def test_30_init_base(self):
        self.host.configure()
        base = self.host.init_base()
        base.prepare()
        self.assertNotEquals(base.list_installed(), [])

    def test_40_save_and_load(self):
        abc = collections.namedtuple("abc", "a b c")
        xyz = collections.namedtuple("xyz", "x y z")
        obj = abc("aaa", 0, xyz(1, 2, abc("aa", "bb", "cc")))  # nested.

        name = "abc_xyz"
        fname = name + ".json"
        self.host.save(obj, name)
        self.assertTrue(os.path.exists(os.path.join(self.host.workdir, fname)))
        self.assertTrue(self.host.load(name))

        savedir = os.path.join(self.host.workdir, "saved")
        self.host.save(obj, name, savedir)
        self.assertTrue(os.path.exists(os.path.join(savedir, fname)))
        self.assertTrue(self.host.load(name, savedir))

# vim:sw=4:ts=4:et:
