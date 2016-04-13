#
# Copyright (C) 2014 - 2015 Satoru SATOH <ssato redhat.com>
# License: GPLv3+
#
"""Package object defs.
"""
from __future__ import absolute_import

import collections
import operator


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
    """
    if extras is None:
        extras = []

    available = name not in extras
    bhsfx = '.'.join(buildhost.split('.')[-2:])  # ex. www.a.t.co -> t.co
    origin_by_v = VENDORS_MAP.get(vendor, None)
    origin_by_b = BH_ORIGIN_MAP.get(bhsfx, None)
    bhsfx_by_v = VENDOR_BH_MAP.get(vendor, None)

    return dict(origin=(origin_by_b or origin_by_v or "unknown"),
                rebuilt=(available and origin_by_v == expected and
                         bhsfx != bhsfx_by_v),
                replaced=(available and origin_by_v != expected),
                from_others=(not available))


_TPL_KEYS = ("name epoch version release arch summary vendor buildhost "
             "origin rebuilt replaced").split()


def make_pkgtuple(pkg):
    """
    Convert Package object to named tuple to reduce each memory size.
    """
    vals = operator.itemgetter(*_TPL_KEYS)(pkg)
    return collections.namedtuple("PkgTuple", _TPL_KEYS)(*vals)


class Package(dict):
    """Package object holding parameters necessary for analysis.
    """

    def __init__(self, name, version, release, arch, epoch=None, summary=None,
                 vendor=None, buildhost=None, extras=None, **kwargs):
        """
        :param name: Package name
        """
        super(Package, self).__init__()

        self["name"] = name
        self["version"] = version
        self["release"] = release
        self["arch"] = arch
        self["epoch"] = 0 if epoch is None else int(epoch)
        self["summary"] = summary
        self["vendor"] = vendor
        self["buildhost"] = buildhost

        for key, val in kwargs.items():
            self[key] = val

        origin = inspect_origin(name, vendor, buildhost, extras)
        self.update(origin)

    def __str__(self):
        """to string method"""
        return "({name}, {version}, {release}, {epoch}, {arch})".format(**self)

    @classmethod
    def from_dict(cls, pkg):
        """
        Factory method to create a :class:`Package` instance from a dict.

        >>> pkgd = dict(name="foo", version="0.0.1", release="1",
        ...             arch="x86_64", epoch=0, buildhost="localhost")
        >>> pkg = Package.from_dict(pkgd)
        >>> isinstance(pkg, Package)
        True
        """
        kwargs = dict((key, val) for key, val in pkg.items()
                      if key not in ("name", "version", "release", "arch"))
        return cls(pkg["name"], pkg["version"], pkg["release"], pkg["arch"],
                   **kwargs)

# vim:sw=4:ts=4:et:
