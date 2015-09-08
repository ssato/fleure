#
# Copyright (C) 2014 Satoru SATOH <ssato redhat.com>
# License: GPLv3+
#
"""Base class.
"""
from __future__ import absolute_import

import collections
import logging
import os.path

import fleure.utils


LOG = logging.getLogger(__name__)


class Base(object):
    """Backend engine object
    """
    _name = "base"

    def __init__(self, root='/', repos=None, workdir=None, cachedir=None,
                 **kwargs):
        """
        :param root: RPM DB root dir
        :param repos: A list of repos to enable
        :param workdir: Working dir to save logs and results
        :param cachedir: Working dir to save logs and results, will be
            os.path.join(root, 'var/cache') if None

        >>> base = Base()
        """
        self.root = os.path.abspath(root)
        self.workdir = root if workdir is None else workdir
        self.repos = [] if repos is None else repos
        self._packages = collections.defaultdict(list)

        if cachedir is None:
            self._cachedir = os.path.join(self.root, "var/cache")
        else:
            self._cachedir = cachedir

    @property
    def name(self):
        """Name property"""
        return self._name

    @property
    def cachedir(self):
        """Cache dir property"""
        return self._cachedir

    @cachedir.setter
    def cachedir(self, val):
        """Cache dir property setter"""
        self._cachedir = val

    def is_rpmdb_available(self, readonly=False):
        """
        :return: True if given RPM database is ready to load.
        """
        return fleure.utils.check_rpmdb_root(self.root, readonly)

    def packages(self, pkgnarrow="installed"):
        """
        :return: A list of {installed, updates} packages or errata
        """
        return self._packages[pkgnarrow]

    def list_installed(self, **kwargs):
        """
        List installed RPMs.
        """
        res = self.packages("installed")
        if not res:
            res = self.list_installed_impl(**kwargs)

        return res

    def list_updates(self, **kwargs):
        """
        List update RPMs.
        """
        res = self.packages("updates")
        if not res:
            res = self.list_updates_impl(**kwargs)

        return res

    def list_errata(self, **kwargs):
        """
        List Errata.
        """
        res = self.packages("errata")
        if not res:
            res = self.list_errata_impl(**kwargs)

        return res

    def list_installed_impl(self, **kwargs):
        """Method placeholder (template method).
        """
        raise NotImplementedError("list_installed_impl")

    def list_updates_impl(self, **kwargs):
        """Method placeholder (template method).
        """
        raise NotImplementedError("list_updates_impl")

    def list_errata_impl(self, **kwargs):
        """Method placeholder (template method).
        """
        raise NotImplementedError("list_errata_impl")


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
        return "({name}, {version}, {release}, {epoch}, {arch})" % self

# vim:sw=4:ts=4:et:
