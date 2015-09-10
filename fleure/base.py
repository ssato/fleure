#
# Copyright (C) 2014 Satoru SATOH <ssato redhat.com>
# License: GPLv3+
#
# suppress warns of `kwargs`
# pylint: disable=unused-argument
"""Base class of backends.
"""
from __future__ import absolute_import

import collections
import logging
import os.path

import fleure.utils


LOG = logging.getLogger(__name__)


class BaseNotReadyError(RuntimeError):
    """Exception to be raised if base object is not ready; it's not configured
    nor populated yet.
    """
    pass


class Base(object):
    """Backend engine object
    """
    _name = "base"

    def __init__(self, root='/', repos=None, workdir=None, cachedir=None,
                 cacheonly=False, **kwargs):
        """
        :param root: RPM DB root dir, ex. '/' (var/lib/rpm)
        :param repos: A list of repos to enable
        :param workdir: Working dir to save logs and results
        :param cachedir:
            Dir to save cache, will be <root>/var/cache if None
        :param cacheonly:
            Do not access network to fetch updateinfo data and load them from
            the local cache entirely.
        :param kwargs: Backend specific keyword args
        """
        self.root = os.path.abspath(root)
        self.repos = [] if repos is None else repos
        self.workdir = root if workdir is None else workdir
        self.cacheonly = cacheonly
        self._packages = collections.defaultdict(list)

        if cachedir is None:
            self.cachedir = os.path.join(self.root, "var/cache")
        else:
            self.cachedir = cachedir

        self._configured = False
        self._populated = False

        self._packages = dict(installed=None, updates=None, obsoletes=None,
                              errata=None)

    @property
    def name(self):
        """Name property"""
        return self._name

    def ready(self):
        """Is ready to get updateinfo ?
        """
        return self._populated and self._packages["installed"]

    def configure(self):
        """Setup configurations, repos to access, etc.
        """
        pass

    def populate(self):
        """Populate updateinfo from yum repos.
        """
        pass

    def prepare(self):
        """Configure and populate.

        :note: This method should be called explicitly.
        """
        if not self._configured:
            self.configure()

        if not self._populated:
            if self._configured:
                if fleure.utils.check_rpmdb_root(self.root, readonly=True):
                    self.populate()

    def _make_list_of(self, item):
        """placeholder.

        :param item: Name of the items to return, e.g. 'installed', 'errata'
        """
        raise NotImplementedError("Inherited class must implement this!")

    def _get_list_of(self, item):
        """Make a list of items if not and return it.

        :param item: Name of the items to return, e.g. 'installed', 'errata'
        """
        if not self.ready():
            raise BaseNotReadyError("It's not ready yet! Populate it before "
                                    "getting a list of %s.", item)

        items = self._packages.get(item, None)
        if items is None:  # Indicates it's not initialized.
            items = self._make_list_of(item)

        return items

    def list_installed(self):
        """List installed RPMs.
        """
        return self._get_list_of("installed")

    def list_updates(self, **kwargs):
        """List update RPMs.
        """
        return self._get_list_of("updates")

    def list_errata(self, **kwargs):
        """List Errata.
        """
        return self._get_list_of("errata")


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
