#
# Copyright (C) 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import unittest
import fleure.errata as TT
from fleure.globals import NEVRA


class Test00(unittest.TestCase):

    def test_20_factory(self):
        adv = 'RHEA-2012:0852'
        ups = [NEVRA("system-config-keyboard-base", 0, "1.3.1", "4.el6",
                     "x86_64"),
               NEVRA("system-config-keyboard", 0, "1.3.1", "4.el6", "x86_64")]
        ecache = dict()
        info = dict(type='enhancement', severity='N/A',
                    synopsis='system-config-keyboard enhancement update',
                    description="The system-config-keyboard packages provide "
                                "a graphical user interface that\nallows ...",
                    issue_date="2012-06-20", update_date="2012-06-20",
                    bzs=[TT.Bugzilla('771389', "Need to create subpackage ...",
                                     "https://bugilla.redhat.com/.../771389")])

        ert = TT.factory(adv, ups, ecache, **info)
        self.assertEquals(ert.advisory, adv)
        self.assertEquals(ert.updates, ups)
        self.assertEquals(ert.update_names, [u.name for u in ups])
        for key in info.keys():
            self.assertEquals(getattr(ert, key), info[key])

        for attr in "id url update_names".split():
            self.assertTrue(getattr(ert, attr, None) is not None)

        self.assertTrue(ert.advisory in ecache)

        ert1 = TT.factory(adv, ups, ecache, **info)  # Cached one.
        self.assertEquals(ert, ert1)
        self.assertEquals(id(ert), id(ert1))

# vim:sw=4:ts=4:et:
