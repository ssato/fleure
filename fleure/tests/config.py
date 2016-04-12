#
# Copyright (C) 2015, 2016 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import anyconfig
import os.path
import os
import unittest

import fleure.config as TT
import fleure.globals
import fleure.utils
import fleure.tests.common


class FunctionsTest00(unittest.TestCase):

    def test_20_try_to_load_config_from_files__no_arg(self):
        cnf = TT.try_to_load_config_from_files()
        for key in TT.DEFAULTS.keys():
            self.assertEquals(cnf[key], TT.DEFAULTS[key])

    def test_22_try_to_load_config_from_files__sysconf(self):
        cnf_path = fleure.globals.FLEURE_SYSCONF
        cnf_ref = anyconfig.load(cnf_path)
        cnf = TT.try_to_load_config_from_files(cnf_path)
        for key in cnf_ref.keys():
            self.assertEquals(cnf[key], cnf_ref[key])


class HostTest00(unittest.TestCase):

    def test_10___init__(self):
        (root, workdir) = ("/tmp", "/tmp/out")
        host = TT.Host(root, conf_path=fleure.globals.FLEURE_SYSCONF,
                       workdir=workdir)
        self.assertTrue(isinstance(host, TT.Host))

        self.assertEquals(host.root, root)
        self.assertEquals(host.workdir, workdir)
        self.assertTrue(host.hid is not None)
        self.assertEquals(host.tpaths, TT.DEFAULTS["tpaths"])

        self.assertTrue(host.repos == [])
        self.assertTrue(host.base is None)
        self.assertFalse(host.available)
        self.assertEquals(host.errors, [])


class HostTest10(fleure.tests.common.TestsWithRpmDB):

    def setUp(self):
        super(HostTest10, self).setUp()
        workdir = os.path.join(self.workdir, "out")
        self.host = TT.Host(self.workdir, workdir=workdir)

    def test_20_configure(self):
        self.host.configure()
        self.assertTrue(self.host.has_valid_root())

    def test_30_init_base(self):
        self.host.configure()
        base = self.host.init_base()
        base.prepare()
        self.assertNotEquals(base.list_installed(), [])

# vim:sw=4:ts=4:et:
