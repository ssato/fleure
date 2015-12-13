#
# Copyright (C) 2015 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import collections
import unittest

import fleure.errata as TT
from fleure.globals import NEVRA


_Errata = collections.namedtuple("Errata", "adv ups info")

ERS = [_Errata("RHEA-2012:0852",
               [NEVRA("system-config-keyboard-base", 0, "1.3.1", "4.el6",
                      "x86_64"),
                NEVRA("system-config-keyboard", 0, "1.3.1", "4.el6",
                      "x86_64")],
               dict(type='enhancement', severity='N/A',
                    synopsis='system-config-keyboard enhancement update',
                    description=("The system-config-keyboard packages "
                                 "provide a graphical user interface "
                                 "that\nallows ..."),
                    issue_date="2012-06-20", update_date="2012-06-20",
                    bzs=[TT.make_rhbz(771389, "Need to create sub...")])),
       _Errata("RHSA-2012:0874",
               [NEVRA('mysql-libs', 0, '5.1.61', '4.el6', 'x86_64')],
               dict(type='security', severity='Low',
                    synopsis="Low: mysql security and enhancement update",
                    description="MySQL is a multi-user, multi-threaded ...",
                    issue_date='2012-06-20', update_date='2012-06-20',
                    bzs=[TT.make_rhbz(740224, 'Enabling MySQL InnoDB Plugin'),
                         TT.make_rhbz(812431, 'CVE-2012-2102 mysql: ...')],
                    cves=[TT.make_cve("CVE-2012-2102", 0, "...")]))]


class Test00(unittest.TestCase):

    def test_20_factory(self):
        ecache = dict()

        for eri in ERS:
            ert0 = TT.factory(eri.adv, eri.ups, ecache, **eri.info)
            self.assertEquals(ert0.advisory, eri.adv)
            self.assertEquals(ert0.updates, eri.ups)
            self.assertEquals(ert0.update_names,
                              sorted(u.name for u in eri.ups))
            for key in eri.info.keys():
                self.assertEquals(getattr(ert0, key), eri.info[key])

            for attr in "id url update_names".split():
                self.assertTrue(getattr(ert0, attr, None) is not None)

            self.assertTrue(ert0.advisory in ecache)

            # Cached one.
            ert1 = TT.factory(eri.adv, eri.ups, ecache, **eri.info)
            self.assertEquals(ert0, ert1)
            self.assertEquals(id(ert0), id(ert1))
            self.assertEquals(hash(ert0), hash(ert1))

    def test_20_factory__comp(self):
        ecache = dict()
        ers = [TT.factory(e.adv, e.ups, ecache, **e.info) for e in ERS]
        ers1 = [TT.factory(e.adv, e.ups, ecache, **e.info) for e in ERS]

        self.assertTrue(all(e0 == e1 for e0, e1 in zip(ers, ers1)))
        self.assertTrue(ers[0] < ers[1])

# vim:sw=4:ts=4:et:
