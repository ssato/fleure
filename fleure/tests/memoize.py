#
# Copyright (C) 2011 - 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
"""Tests for memoize module.
"""
from __future__ import absolute_import
from inspect import getdoc

import unittest
from .. import memoize as TT


class Test(unittest.TestCase):

    def test_00_simple_case(self):
        param = 0
        fnc = lambda _param: param

        fnc = TT.memoize(fnc)
        param = 1

        self.assertEquals(fnc(0), fnc(1))

    def test_10_doc_string_is_kept(self):
        def fnc():
            """Always returns True."""
            return True

        fnc2 = TT.memoize(fnc)
        self.assertEquals(getdoc(fnc), getdoc(fnc2))

    def test_20_not_callable(self):
        self.assertRaises(AssertionError, TT.memoize, None)

# vim:sw=4:ts=4:et:
