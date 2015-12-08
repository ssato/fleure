#
# Copyright (C) 2014 - 2015 Satoru SATOH <ssato redhat.com>
# License: GPLv3+
#
"""Package object defs.
"""
from __future__ import absolute_import

import collections


_VENDOR_RH = "Red Hat, Inc."
_VENDOR_MAPS = {_VENDOR_RH: ("redhat", ".redhat.com"),
                "Symantec Corporation": ("symantec", ".veritas.com"),
                "ZABBIX-JP": ("zabbixjp", ".zabbix.jp"),
                "Fedora Project": ("fedora", ".fedoraproject.org")}

CACHE = dict()


def may_be_rebuilt(vendor, buildhost, vbmap=None, sfx=".redhat.com"):
    """
    >>> may_be_rebuilt("Red Hat, Inc.", "abc.builder.redhat.com")
    False
    >>> may_be_rebuilt("Red Hat, Inc.", "localhost.localdomain")
    True
    >>> may_be_rebuilt("ZABBIX-JP", "abc.builder.redhat.com")
    False
    >>> may_be_rebuilt("Example, Inc.", "abc.builder.redhat.com")
    False
    >>> may_be_rebuilt("Example, Inc.", "localhost.localdomain")
    False
    """
    if buildhost.endswith(sfx):
        return False

    if vbmap is None:
        vbmap = _VENDOR_MAPS

    bhsuffix = vbmap.get(vendor, (None, False))[1]
    if bhsuffix:
        return not buildhost.endswith(bhsuffix)

    return False


def inspect_origin(name, vendor, buildhost, extra_names=None):
    """
    Inspect package info and detect its origin, etc.

    :param name: Package name
    :param vendor: Package vendor
    :param buildhost: Package buildhost
    :param extra_names: Extra (non-vendor-origin) package names

    :return: A tuple of (origin, rebuilt, replaced)
    """
    origin = _VENDOR_MAPS.get(vendor, ("unknown", ))[0]

    # Cases that it may be rebuilt or replaced.
    if extra_names is not None and name not in extra_names:
        return (origin, may_be_rebuilt(vendor, buildhost, _VENDOR_MAPS),
                vendor != _VENDOR_RH)

    return (origin, False, False)


def norm_nevra(name, epoch, version, release, arch):
    """Normalize epoch to unsigned int and return result (nevra).
    """
    return (name, 0 if epoch is None else int(epoch), version, release, arch)


def factory(nevra, cache=None, **info):
    """
    Factory to create a package info object.

    :param nevra: A tuple of (name, epoch, version, release, arch)
    :param info:
        Other package info such as summary, vendor, buildhost, extra_names
        (extra package names)

    :return:
        An instance of :class:`collections.namedtuple` holding package info
    """
    if cache is None:
        cache = CACHE

    nevra = norm_nevra(*nevra)
    if nevra in cache:
        return cache[nevra]

    vbes = (info["vendor"], info["buildhost"], info.get("extra_names", None))
    orr = inspect_origin(nevra[0], *vbes)

    keys = ("name epoch version release arch summary vendor buildhost "
            "origin rebuilt replaced").split()
    extra_keys = sorted(k for k in info.keys() if k not in keys)
    Package = collections.namedtuple("Package", keys + extra_keys)

    pkg = Package(*(nevra + (info["summary"], vbes[0], vbes[1]) + orr +
                    tuple(info[k] for k in extra_keys)))
    cache[nevra] = pkg
    return pkg

# vim:sw=4:ts=4:et:
