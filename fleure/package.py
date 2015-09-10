#
# Copyright (C) 2014 - 2015 Satoru SATOH <ssato redhat.com>
# License: GPLv3+
#
"""Package object defs.
"""
from __future__ import absolute_import


_VENDOR_RH = "Red Hat, Inc."
_VENDOR_MAPS = {_VENDOR_RH: ("redhat", ".redhat.com"),
                "Symantec Corporation": ("symantec", ".veritas.com"),
                "ZABBIX-JP": ("zabbixjp", ".zabbix.jp"),
                "Fedora Project": ("fedora", ".fedoraproject.org")}


def may_be_rebuilt(vendor, buildhost, vbmap=None):
    """
    >>> may_be_rebuilt("Red Hat, Inc.", "abc.builder.redhat.com")
    False
    >>> may_be_rebuilt("Red Hat, Inc.", "localhost.localdomain")
    True
    >>> may_be_rebuilt("Example, Inc.", "abc.builder.redhat.com")
    False
    >>> may_be_rebuilt("Example, Inc.", "localhost.localdomain")
    False
    """
    if vbmap is None:
        vbmap = _VENDOR_MAPS

    bhsuffix = vbmap.get(vendor, (None, False))[1]
    if bhsuffix:
        return not buildhost.endswith(bhsuffix)

    return False


def inspect_origin(name, vendor, buildhost, extra_names=None,
                   vbmap=None, exp_vendor=_VENDOR_RH):
    """
    Inspect package info and detect its origin, etc.

    :param name: Package name
    :param vendor: Package vendor
    :param buildhost: Package buildhost
    :param extras: Extra packages not available from yum repos
    :param extra_names: Extra (non-vendor-origin) package names
    """
    if vbmap is None:
        vbmap = _VENDOR_MAPS

    origin = vbmap.get(vendor, ("unknown", ))[0]

    # Cases that it may be rebuilt or replaced.
    if extra_names is not None and name not in extra_names:
        rebuilt = may_be_rebuilt(vendor, buildhost, vbmap)
        replaced = vendor != exp_vendor
        return dict(origin=origin, rebuilt=rebuilt, replaced=replaced)

    return dict(origin=origin, rebuilt=False, replaced=False)


class Package(dict):
    """Package object holding parameters necessary for analysis.
    """

    def __init__(self, name, version, release, arch, epoch=0, summary=None,
                 vendor=None, buildhost=None, extra_names=None, **kwargs):
        """
        :param name: Package name
        """
        super(Package, self).__init__()

        self["name"] = name
        self["version"] = version
        self["release"] = release
        self["arch"] = arch
        self["epoch"] = epoch
        self["summary"] = summary
        self["vendor"] = vendor
        self["buildhost"] = buildhost

        dic = inspect_origin(name, vendor, buildhost, extra_names)
        self.update(**dic)

        for key, val in kwargs.items():
            self[key] = val

    def __str__(self):
        return "({name}, {version}, {release}, {epoch}, {arch})".format(**self)

# vim:sw=4:ts=4:et:
