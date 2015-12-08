#
# Copyright (C) 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import unittest
import fleure.package as TT


class Test00(unittest.TestCase):

    def test_40_factory(self):
        nevra = ("foo", 2, "0.0.1", "1", "x86_64")
        info = dict(summary="foo package", vendor="Red Hat, Inc.",
                    buildhost="builder.example.redhat.com", ex0="aaa")
        pcache = dict()

        pkg = TT.factory(nevra, cache=pcache, **info)
        self.assertEquals(pkg.name, nevra[0])
        self.assertEquals(pkg.epoch, nevra[1])
        self.assertEquals(pkg.version, nevra[2])
        self.assertEquals(pkg.release, nevra[3])
        self.assertEquals(pkg.arch, nevra[4])
        for key in info.keys():
            self.assertEquals(getattr(pkg, key), info[key])
        self.assertTrue(nevra in pcache)

        pkg1 = TT.factory(nevra, pcache, **info)  # Cached one.
        self.assertEquals(id(pkg), id(pkg1))

        nevra2 = nevra[0:1] + (None, ) + nevra[2:]
        pkg2 = TT.factory(nevra2, pcache, **info)
        self.assertEquals(pkg2.epoch, 0)
        self.assertNotEquals(id(pkg), id(pkg2))

# vim:sw=4:ts=4:et:
