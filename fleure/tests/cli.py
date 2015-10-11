#
# Copyright (C) 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring, protected-access, invalid-name
from __future__ import absolute_import

import unittest
import fleure.tests.common

try:
    import fleure.cli as TT
except ImportError:
    TT = None


class Test(unittest.TestCase):

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_10_parse_args__defaults(self):
        root = "/tmp/dummy_root"
        args = TT.parse_args([root])

        defaults = TT._DEFAULTS
        for key, val in defaults.items():
            self.assertEquals(getattr(args, key), val)

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_11_parse_args__repos(self):
        root = "/tmp/dummy_root"
        repos = ["rhel-x86_64-server-6", "rhel-x86_64-server-6-scl-2"]
        args = TT.parse_args([root, "-r", repos[0], "--repo", repos[1]])

        defaults = TT._DEFAULTS.copy()
        defaults["repos"] = repos

        for key, val in defaults.items():
            self.assertEquals(getattr(args, key), val)

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_12_parse_args__period(self):
        root = "/tmp/dummy_root"

        period = "2015-01-01"
        args = TT.parse_args([root, "--period", period])
        self.assertEquals(args.period, [period])

        period = "2015-01-01,2015-09-29"
        args = TT.parse_args([root, "--period", period])
        self.assertEquals(args.period, period.split(','))

    @fleure.tests.common.skip_if_not(TT is not None)
    def test_24_main__no_root_arg(self):
        raised = False
        try:
            TT.sys.argv[0] = __name__  # Override.
            TT.main([__name__, "/path/to/not_existing_root"])
        except SystemExit:
            raised = True

        self.assertTrue(raised)

# vim:sw=4:ts=4:et:
