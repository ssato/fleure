#
# Copyright (C) 2011 - 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
"""Tests for decorators.
"""
from __future__ import absolute_import

import inspect
import unittest

from .. import decorators as TT


def fnc():
    """Always returns True."""
    return True


class Test(unittest.TestCase):

    def test_10_noop_original_kept(self):
        fnc2 = TT.noop(fnc)
        self.assertEquals(inspect.getdoc(fnc), inspect.getdoc(fnc2))

    def test_10_noop_not_callable(self):
        self.assertRaises(ValueError, TT.noop, None)

    def test_20_memoize(self):
        param = 0
        fnc2 = lambda _param: param  # Function lgnores parameters
        fnc2 = TT.memoize(fnc2)
        param = 1
        self.assertEquals(fnc2(0), fnc2(1))

    def test_30_async(self):
        TT.async.pool = TT.multiprocessing.Pool()
        fnc2 = TT.async(fnc)
        fnc2()

# vim:sw=4:ts=4:et:
