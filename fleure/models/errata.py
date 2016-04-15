#
# Copyright (C) 2016 Satoru SATOH <ssato redhat.com>
# License: GPLv3+
#
# pylint: disable=too-few-public-methods,invalid-name
"""Model represents Errata Advisory.
"""
from __future__ import absolute_import

import sqlalchemy
from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import relationship

from .base import Base


_RHBZ_URL_FMT = "https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=%d"
_CVE_URL_FMT = "https://www.redhat.com/security/data/cve/%s.html"

SEVERITIES = ('Critical', 'Important', 'Moderate', 'Low', 'N/A')
TYPES = ("security", "bugfix", "enhancement")


errata_bz_table = sqlalchemy.Table(
    "errata_bz_association", Base.metadata,
    Column("errata_id", String(20), ForeignKey("errata.advisory")),
    Column("bz_id", sqlalchemy.Integer, ForeignKey("bugzilla.id")))

errata_cve_table = sqlalchemy.Table(
    "errata_cve_association", Base.metadata,
    Column("errata_id", String(20), ForeignKey("errata.advisory")),
    Column("cve_id", String(20), ForeignKey("cve.id")))

errata_pkgs_table = sqlalchemy.Table(
    "errata_pkg_association", Base.metadata,
    Column("errata_id", String(20), ForeignKey("errata.advisory")),
    Column("pkg_id", String(150), ForeignKey("packages.nevra")))


class Bugzilla(Base):
    """Bugzilla model.
    """
    __tablename__ = "bugzilla"

    id = Column("id", sqlalchemy.Integer, primary_key=True)
    summary = Column(String(100))
    url = Column(String(80))

    def __init__(self, id_, summary):
        """
        :param id_: Bugzilla ID
        :param summary: Bugzilla summary text
        """
        self.id = int(id_)
        self.summary = summary
        self.url = _RHBZ_URL_FMT % self.id


class CVE(Base):
    """CVE model.

    TODO: add CVSS base metrics, score, etc.
    """
    __tablename__ = "cve"

    id = Column("id", String(20), primary_key=True)
    url = Column(String(60))

    def __init__(self, id_):
        """
        :param id_: CVE ID
        """
        self.id = id_
        self.url = _CVE_URL_FMT % id

    @property
    def cve(self):
        """alias for self.id_
        """
        return self.id


class Errata(Base):
    """Errata model.
    """
    __tablename__ = "errata"

    advisory = Column(String(20), primary_key=True)
    synopsis = Column(String(100))
    description = Column(sqlalchemy.Text)
    issue_date = Column(String(20))
    update_date = Column(String(20))
    severity = Column(sqlalchemy.Enum(*SEVERITIES))
    type_ = Column("type", sqlalchemy.Enum(*TYPES))
    url = Column(String(50))

    bzs = relationship("Bugzilla", secondary=errata_bz_table)
    cves = relationship("CVE", secondary=errata_cve_table)
    packages = relationship("Package", secondary=errata_pkgs_table)
    updates = relationship("Package", secondary=errata_pkgs_table)

    def __init__(self, advisory, synopsis, description, issue_date,
                 update_date, severity="N/A", bzs=None, cves=None,
                 packages=None, updates=None):
        """
        :param advisory: Errata advisory ID
        """
        self.advisory = advisory
        self.synopsis = synopsis
        self.description = description
        self.issue_date = issue_date
        self.update_date = update_date
        self.severity = severity
        self.bzs = [] if bzs is None else bzs
        self.cves = [] if cves is None else cves
        self.packages = [] if packages is None else packages
        self.updates = [] if updates is None else updates

    @property
    def id(self):
        """alias for self.advisory
        """
        return self.advisory

    def __repr__(self):
        """repr.
        """
        return "<Errata('%s', '%s')>" % (self.advisory, self.synopsis)

# vim:sw=4:ts=4:et:
