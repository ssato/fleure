#
# Copyright (C) 2011 - 2017 Satoru SATOH <ssato at redhat.com>
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
        self.assertEqual(inspect.getdoc(fnc), inspect.getdoc(fnc2))

    def test_10_noop_not_callable(self):
        self.assertRaises(ValueError, TT.noop, None)

    def test_20_memoize(self):
        param = 0

        def fnc2(_param):
            return param

        fnc2 = TT.memoize(fnc2)
        param = 1
        self.assertEqual(fnc2(0), fnc2(1))

# vim:sw=4:ts=4:et:
