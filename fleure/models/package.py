#
# Copyright (C) 2014 - 2016 Satoru SATOH <ssato redhat.com>
# License: GPLv3+
#
"""Model represents RPM Package.
"""
from __future__ import absolute_import

import operator
import sqlalchemy

from sqlalchemy import Column
from .base import Base


RPM_ORIGIN_DEFAULT = "redhat"
VENDOR_RH = "Red Hat, Inc."

# (vendor, origin, buildhost suffix)
VENDORS = [(VENDOR_RH, "redhat", "redhat.com"),
           ("Fujitsu Limited", "redhat", "redhat.com"),
           ("Symantec Corporation", "symantec", "veritas.com"),
           ("ZABBIX-JP", "zabbixjp", "zabbix.jp"),
           ("Fedora Project", "fedora", "fedoraproject.org"),
           ("CentOS", "centos", "centos.org")]

BH_ORIGIN_MAP = {sfx: origin for _vendor, origin, sfx in VENDORS}
VENDOR_BH_MAP = {vendor: sfx for vendor, _origin, sfx in VENDORS}
VENDORS_MAP = {vendor: origin for vendor, origin, _sfx in VENDORS}


def inspect_origin(name, vendor, buildhost, extras=None,
                   expected=RPM_ORIGIN_DEFAULT):
    """
    Inspect package info and detect its origin, etc.

    - rebuilt: available from repos (name is not found in extras),
      origin == expected and buildhost suffix != the one by vendor
    - replaced: available from repos and origin by vendor != `expected`
    - from_others: may came from unknown source

    :param name: Package name
    :param vendor: vendor string in RPM
    :param buildhost: buildhost string in RPM
    :param extra_names: Extra (non-vendor-origin) package names
    :param expected: Expected origin
    :return: (origin, rebuilt, replaced, from_others)
    """
    if extras is None:
        extras = []

    available = name not in extras
    bhsfx = '.'.join(buildhost.split('.')[-2:])  # ex. www.a.t.co -> t.co
    origin_by_v = VENDORS_MAP.get(vendor, None)
    origin_by_b = BH_ORIGIN_MAP.get(bhsfx, None)
    bhsfx_by_v = VENDOR_BH_MAP.get(vendor, None)

    return (origin_by_b or origin_by_v or "unknown",
            available and origin_by_v == expected and bhsfx != bhsfx_by_v,
            available and origin_by_v != expected,
            not available)


class Package(Base):
    """Package model.
    """
    __tablename__ = "packages"

    # TBD: Which is better?
    # id = Column(sqlalchemy.Integer, sqlalchemy.Sequence("package_id_seq"),
    #            primary_key=True)
    nevra = Column(sqlalchemy.String(150), primary_key=True)
    name = Column(sqlalchemy.String(100))
    epoch = Column(sqlalchemy.Integer)
    version = Column(sqlalchemy.String(20))
    release = Column(sqlalchemy.String(20))
    arch = Column(sqlalchemy.Enum("noarch", "i386", "i686", "x86_64"))
    summary = Column(sqlalchemy.String(150))
    vendor = Column(sqlalchemy.String(100))
    buildhost = Column(sqlalchemy.String(100))
    origin = Column(sqlalchemy.String(20))
    rebuilt = Column(sqlalchemy.Boolean)
    replaced = Column(sqlalchemy.Boolean)
    from_others = Column(sqlalchemy.Boolean)

    def __init__(self, name, version, release, arch, epoch=None, summary='',
                 vendor='', buildhost="localhost", extras=None):
        """
        :param name: Package name
        """
        self.name = name
        self.epoch = 0 if epoch is None else int(epoch)
        self.version = version
        self.release = release
        self.arch = arch
        self.summary = summary
        self.vendor = vendor
        self.buildhost = buildhost
        (self.origin, self.rebuilt, self.replaced, self.from_others) = \
            inspect_origin(name, vendor, buildhost, extras)
        self.nevra = "%s %d:%s-%s %s" % \
            (name, self.epoch, version, release, arch)

    def __repr__(self):
        """repr.
        """
        return "<Package('%s', '%s', '%s', '%s', '%s')>" % self.nevra()

# vim:sw=4:ts=4:et:
