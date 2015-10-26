#
# -*- coding: utf-8 -*-
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: GPLv3+
#
"""Fleure central configuration object.
"""
from __future__ import absolute_import

import anyconfig
import bunch
import os.path
import tempfile
import uuid

import fleure.globals
import fleure.archive
import fleure.utils
import fleure.yumbase


BACKENDS = dict(yum=fleure.yumbase.Base, )
DEFAULT_BACKEND = "yum"
try:
    import fleure.dnfbase

    BACKENDS["dnf"] = fleure.dnfbase.Base
    DEFAULT_BACKEND = "dnf"  # Prefer this.
except ImportError:  # dnf is not available for RHEL, AFAIK.
    pass


def _normpath(path):
    """
    Normalize given path.

    >>> _normpath("/tmp/../a//b/c")
    '/a/b/c'

    >>> import pwd, random
    >>> uhs = [(x.pw_name, x.pw_dir) for x in pwd.getpwall()]
    >>> (usr, homedir) = random.sample(uhs, 1)[0]
    >>> _normpath("~%s/a/b/.." % usr) == os.path.join(homedir, "a")
    True
    """
    assert path, "Empty path was given!"

    if path.startswith('~'):
        path = os.path.expanduser(path)

    return os.path.normpath(os.path.abspath(path))


def load_config_from_files():
    """
    Load configurations from default sysconfdir.
    """
    cnf_paths = os.path.join(fleure.globals.FLEURE_SYSCONFDIR, "*.yml")
    try:
        cnf = bunch.bunchify(anyconfig.load(cnf_paths))
    except (IOError, OSError):
        return dict()
    try:
        return dict(errata_keywords=cnf.rpm.keywords,
                    core_rpms=cnf.rpm.core_rpms, rpm_vendor=cnf.rpm.vendor,
                    cvss_min_score=cnf.cvss_score, repos_map=cnf.repos_map)
    except (KeyError, AttributeError):
        return dict(errata_keywords=fleure.globals.ERRATA_KEYWORDS,
                    core_rpms=fleure.globals.CORE_RPMS,
                    rpm_vendor=fleure.globals.RPM_VENDOR,
                    cvss_min_score=fleure.globals.CVSS_MIN_SCORE,
                    repos_map=fleure.globals.REPOS_MAP)


class Host(bunch.Bunch):
    """Object holding common configuration and host specific data.
    """
    # initialized some of configurations:
    sysconfdir = fleure.globals.FLEURE_SYSCONFDIR
    sysdatadir = fleure.globals.FLEURE_DATADIR
    tpaths = fleure.globals.FLEURE_TEMPLATE_PATHS
    rpmkeys = fleure.globals.RPM_KEYS
    errata_keywords = fleure.globals.ERRATA_KEYWORDS
    core_rpms = fleure.globals.CORE_RPMS
    rpm_vendor = fleure.globals.RPM_VENDOR
    details = True
    cvss_min_score = 0

    backend = DEFAULT_BACKEND
    backends = BACKENDS

    def __init__(self, root_or_arc_path, hid=None, workdir=None, cachedir=None,
                 repos=None, period=None, refdir=None, **kwargs):
        """
        Initialize some lazy configurations.

        :param root_or_arc_path:
            Path to the root dir of RPM DB files or Archive (tar.xz, tar.gz,
            zip, etc.) of RPM DB files. Path might be a relative path from
            current dir.
        :param hid:
            ID such as name of the host where the RPM DB are collected
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
        defaults = load_config_from_files()
        defaults.update(kwargs)
        super(Host, self).__init__(root_or_arc_path=root_or_arc_path,
                                   repos=repos, period=period, refdir=refdir,
                                   **kwargs)
        for key, val in kwargs.items():
            setattr(self, key, val)

        if os.path.isdir(root_or_arc_path):
            self.root = _normpath(root_or_arc_path)
        else:
            self.root = None

        self.hid = str(uuid.uuid4()).split('-')[0] if hid is None else hid
        self.workdir = self.root if workdir is None else _normpath(workdir)

        if cachedir is None:
            if self.root is not None:
                self.cachedir = os.path.join(self.root, "var/cache")
            # else:  -> cachedir will be set in :meth:`configure` later.
        else:
            self.cachedir = _normpath(cachedir)

        self.tpaths = [_normpath(p) for p in self.get("tpaths", Host.tpaths)]
        self.repos = repos

        # These might be initialized later.
        self.base = None
        self.available = False
        self.errors = []

    def __str__(self):
        return self.toJSON(indent=2)

    def configure(self):
        """
        Setup root, etc.
        """
        if self.root is None:
            if self.workdir is None:
                self.workdir = tempfile.mkdtemp(prefix="fleure-tmp-")

            _extract_fn = fleure.archive.extract_rpmdb_archive
            (root, err) = _extract_fn(self.root_or_arc_path, self.workdir)
            if err:
                self.errors.append(err)
                return

            self.root = root
            self.cachedir = os.path.join(self.root, "var/cache")

        if not fleure.utils.check_rpmdb_root(self.root):
            self.errors.append("Invalid RPM DBs: " + self.root)
            return

        if self.repos is None or not self.repos:
            self.repos = fleure.utils.guess_rhel_repos(self.root, None,
                                                       self.repos_map)

        if not os.path.exists(self.workdir):
            os.makedirs(self.workdir)

    def has_valid_root(self):
        """
        Is root setup and ready?
        """
        return self.root is not None and not self.errors

    def init_base(self):
        """
        Inialized yum/dnf base object.
        """
        assert self.has_valid_root(), "Initialize root at first!"

        backend = self.backends.get(self.backend)
        self.base = backend(self.root, self.repos, workdir=self.workdir,
                            cachedir=self.cachedir)
        return self.base

    def save(self, obj, name, subdir=None):
        """
        :param obj: Object to save
        :param name: File base name to save
        :param subdir: Sub directory relative to workdir
        """
        if subdir is None:
            filepath = os.path.join(self.workdir, "%s.json" % name)
        else:
            filepath = os.path.join(self.workdir, subdir, "%s.json" % name)

        if not os.path.exists(os.path.dirname(filepath)):
            os.makedirs(os.path.dirname(filepath))

        fleure.utils.json_dump(obj, filepath)

# vim:sw=4:ts=4:et:
