#
# Copyright (C) 2016 Satoru SATOH <ssato at redhat.com>
# License: GPLv3+
#
# pylint: disable=missing-docstring,invalid-name,no-member
from __future__ import absolute_import

import fleure.models.errata as TT
import fleure.models.package
import fleure.models.tests.common
import fleure.models.tests.package


_EINFO_0 = ("RHSA-2014:0917",
            "Critical: nss and nspr security, bug fix, ...",
            """Network Security Services (NSS) is a set of libraries designed
to support\nthe cross-platform development of security-enabled client and
server\napplications. Netscape Portable Runtime (NSPR) provides
platform\nindependence for non-GUI operating system facilities.\n\nA race
condition was found in the way NSS verified certain certificates.\n""",
            "2014-07-22",
            "2014-07-22",
            "Critical")


class Test_10_Errata(fleure.models.tests.common.TestsWithSession):

    def test_00_empty_db(self):
        self.assertEquals(len(self.session.query(TT.Bugzilla).all()), 0)
        self.assertEquals(len(self.session.query(TT.CVE).all()), 0)
        self.assertEquals(len(self.session.query(TT.Errata).all()), 0)

    def test_10_add_one(self):
        bzs = [TT.Bugzilla("1301846",
                           "CVE-2015-3197 OpenSSL: SSLv2 doesn't block ..."),
               TT.Bugzilla("1310593",
                           "CVE-2016-0800 SSL/TLS: Cross-protocol attack ..."),
               TT.Bugzilla("1310596",
                           "CVE-2016-0705 OpenSSL: Double-free in DSA code")]
        cves = [TT.CVE("CVE-2014-1492"), TT.CVE("CVE-2014-1545"),
                TT.CVE("CVE-2014-1491")]

        pkgs = fleure.models.tests.package.PACKAGES
        ups = pkgs[:]

        for bz in bzs:
            self.session.add(bz)
        for cve in cves:
            self.session.add(cve)
        for pkg in pkgs:
            self.session.add(pkg)
        for pkg in ups:
            # self.session.add(pkg)
            print(repr(pkg))

        errata = TT.Errata(*_EINFO_0, bzs=bzs, cves=cves, packages=pkgs,
                           updates=ups)
        self.session.add(errata)
        self.session.commit()

        items = self.session.query(TT.Errata).all()
        self.assertEquals(len(items), 1)
        self.assertEquals(items[0].advisory, "RHSA-2014:0917")

# vim:sw=4:ts=4:et:
