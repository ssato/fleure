#
# Copyright (C) 2014 - 2016 Red Hat, Inc.
# Author: Satoru SATOH <ssato@redhat.com>
# License: GPLv3+
#
# suppress warns of `kwargs`
# pylint: disable=unused-argument
"""Base class of backends.
"""
from __future__ import absolute_import

import collections
import os.path

import fleure.rpmutils


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
        return self._populated

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
                if fleure.rpmutils.check_rpmdb_root(self.root, readonly=True):
                    self.populate()

    def _make_list_of(self, item, process_fns=None):
        """placeholder.

        :param item: Name of the items to return, e.g. 'installed', 'errata'
        :param process_fns:
            Any callables to process item (transform, modification, etc.), or
            None to do nothing with it.
        """
        raise NotImplementedError("Inherited class must implement this!")

    def _assert_if_not_ready(self, tsk="the task"):
        """
        Raise an exception `BaseNotReadyError` if its' not ready.

        :param tsk: A string explains the task to perform
        """
        if not self.ready():
            raise BaseNotReadyError("Not ready yet! Populate it before " + tsk)

    def _get_list_of(self, item, process_fns=None):
        """Make a list of items if not and return it.

        :param item: Name of the items to return, e.g. 'installed', 'errata'
        :param process_fns:
            Any callables to process item (transform, modification, etc.), or
            None to do nothing with it.
        """
        self._assert_if_not_ready("getting a list of %s." % item)
        items = self._packages.get(item, None)
        if items is None:  # Indicates it's not initialized.
            items = self._make_list_of(item, process_fns=process_fns)

        return items

    def list_installed(self, process_fns=None):
        """List installed RPMs.

        :param process_fns:
            Any callables to process objects represent installed packages or
            None to do nothing with it
        """
        return self._get_list_of("installed", process_fns=process_fns)

    def list_updates(self, process_fns=None, **kwargs):
        """List update RPMs.

        :param process_fns:
            Any callables to process objects represent update packages or None
            to do nothing with it
        """
        return self._get_list_of("updates", process_fns=process_fns)

    def list_errata(self, process_fns=None, **kwargs):
        """List Errata.

        :param process_fns:
            Any callables to process objects represent update packages or None
            to do nothing with it
        """
        return self._get_list_of("errata", process_fns=process_fns)

# vim:sw=4:ts=4:et:
