#
# Copyright (C) 2014 - 2015 Satoru SATOH <ssato redhat.com>
# License: GPLv3+
#
"""Package object defs.
"""
from __future__ import absolute_import

import collections
import operator


VENDOR_RH = "Red Hat, Inc."
VENDORS_MAP = {VENDOR_RH: ("redhat", "redhat.com"),
               "Fujitsu Limited": ("redhat", "redhat.com"),
               "Symantec Corporation": ("symantec", "veritas.com"),
               "ZABBIX-JP": ("zabbixjp", "zabbix.jp"),
               "Fedora Project": ("fedora", "fedoraproject.org"),
               "CentOS": ("centos", "centos.org")}
BH_ORIGIN_MAP = {ob[1]: ob[0] for ob in VENDORS_MAP.values()}


def inspect_origin(name, vendor, buildhost, extra_names=None):
    """
    Inspect package info and detect its origin, etc.

    - rebuilt: buildhost suffix != the one expected from vendor
    - replaced: origin != the one expected from buildhost suffix

    :param name: Package name
    :param vendor: Package vendor
    :param buildhost: Package buildhost
    :param extra_names: Extra (non-vendor-origin) package names
    """
    rebuilt = replaced = False
    bhsfx = '.'.join(buildhost.split('.')[-2:])  # ex. www.a.t.co -> t.co
    (org_exp, bhsfx_exp) = VENDORS_MAP.get(vendor, ("unknown", None))
    origin = BH_ORIGIN_MAP.get(bhsfx, org_exp)

    rebuilt = bhsfx != bhsfx_exp
    if extra_names is not None and name not in extra_names:
        replaced = origin != org_exp  # Available from any repos.

    return dict(origin=origin, rebuilt=rebuilt, replaced=replaced)


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
                 vendor=None, buildhost=None, extra_names=None, **kwargs):
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

        dic = inspect_origin(name, vendor, buildhost, extra_names)
        self.update(**dic)

        for key, val in kwargs.items():
            self[key] = val

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
