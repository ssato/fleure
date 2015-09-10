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
import os.path

import fleure.utils


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

# vim:sw=4:ts=4:et:
