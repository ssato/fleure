#
# -*- coding: utf-8 -*-
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: GPLv3+
#
"""Fleure central configuration object.
"""
from __future__ import absolute_import

import bunch
import os.path
import uuid

import fleure.globals
import fleure.yumbase


_BACKENDS = dict(yum=fleure.yumbase.Base, )
_DEFAULT_BACKEND = "yum"
try:
    import fleure.dnfbase

    _BACKENDS["dnf"] = fleure.dnfbase.Base
    _DEFAULT_BACKEND = "dnf"  # Prefer this.
except ImportError:  # dnf is not available for RHEL, AFAIK.
    pass


def _normpath(path):
    """
    Normalize given path.

    >>> _normpath("/tmp/../a//b/c")
    '/a/b/c'

    >>> import pwd, random
    >>> uhs = [(x.pw_name, x.pw_dir) for x in pwd.getpwall()
    ...        if x.pw_dir.startswith("/home")]
    >>> (usr, homedir) = random.sample(uhs, 1)[0]
    >>> _normpath("~%s/a/b/.." % usr) == os.path.join(homedir, "a")
    True
    """
    assert path, "Empty path was given!"

    if path.startswith('~'):
        path = os.path.expanduser(path)

    return os.path.normpath(os.path.abspath(path))


class Config(bunch.Bunch):
    """Config object.
    """
    # initialized some of configurations:
    sysconfdir = fleure.globals.FLEURE_SYSCONFDIR
    sysdatadir = fleure.globals.FLEURE_DATADIR
    tpaths = fleure.globals.FLEURE_TEMPLATE_PATHS
    rpmkeys = fleure.globals.RPM_KEYS
    eratta_keywords = fleure.globals.ERRATA_KEYWORDS
    core_rpms = fleure.globals.CORE_RPMS
    rpm_vendor = fleure.globals.RPM_VENDOR
    details = True
    cvss_min_score = 0

    backend = _DEFAULT_BACKEND
    backends = _BACKENDS

    def __init__(self, root_or_arc_path, hostname=None, workdir=None,
                 cachedir=None, repos=None, period=None, refdir=None,
                 **kwargs):
        """
        Initialize some lazy configurations.

        :param root_or_arc_path:
            Path to the root dir of RPM DB files or Archive (tar.xz, tar.gz,
            zip, etc.) of RPM DB files. Path might be a relative path from
            current dir.
        :param hostname:
            Name of the host in which the RPM DB are collected or some ID
            distiguish from others.
        :param workdir: Working dir to keep temporal files and save results
        :param cachedir: Dir to save cache files
        :param repos:
            A list of Yum repositories to fetch metadata. It will be guessed
            from some metadata automatically in given RPM DB files by default.
        :param period:
            Period to fetch and analyze data as a tuple of dates in format of
            YYYY[-MM[-DD]], eg. ("2014-10-01", "2014-11-01").
        :param refdir:
            A dir holding reference data previously generated to compute delta,
            updates since that data generated.
        """
        super(Config, self).__init__(root_or_arc_path=root_or_arc_path,
                                     repos=repos, period=period, refdir=refdir,
                                     **kwargs)

        if os.path.isdir(root_or_arc_path):
            self.root = _normpath(root_or_arc_path)
        else:
            self.root = None

        self.hostname = str(uuid.uuid1()) if hostname is None else hostname
        self.workdir = self.root if workdir is None else _normpath(workdir)

        if cachedir is None:
            self.cachedir = os.path.join(self.root, "var/cache")
        else:
            self.cachedir = _normpath(cachedir)

# vim:sw=4:ts=4:et:
