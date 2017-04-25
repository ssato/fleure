#
# -*- coding: utf-8 -*-
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2016 Red Hat, Inc.
# License: GPLv3+
#
"""Fleure central configuration object.
"""
from __future__ import absolute_import

import anyconfig
import anyconfig.utils
import bunch
import logging
import os.path
import tempfile
import uuid

import fleure.backends.yumbase
import fleure.globals
import fleure.archive
import fleure.dates
import fleure.rpmutils
import fleure.utils


LOG = logging.getLogger(__name__)

BACKENDS = dict(yum=fleure.backends.yumbase.Base)
BACKEND_MODULES = [fleure.backends.yumbase]
DEFAULT_BACKEND = "yum"
try:
    import fleure.backends.dnfbase

    BACKEND_MODULES.append(fleure.backends.dnfbase)
    BACKENDS["dnf"] = fleure.backends.dnfbase.Base
    DEFAULT_BACKEND = "dnf"  # Prefer this.
except ImportError:  # dnf is not available for RHEL, AFAIK.
    pass

# TBD to switch:
# BACKENDS = {backend.name: backend for backend in
#            (getattr(mod, "Base") for mod in BACKEND_MODULES)}

DEFAULTS = dict(workdir=None,
                repos=None,
                hid=None,
                cvss_min_score=fleure.globals.CVSS_MIN_SCORE,
                errata_keywords=fleure.globals.ERRATA_KEYWORDS,
                errata_pkeywords=fleure.globals.ERRATA_PKEYWORDS,
                core_rpms=fleure.globals.CORE_RPMS,
                rpm_vendor=fleure.globals.RPM_VENDOR,
                tpaths=fleure.globals.FLEURE_TEMPLATE_PATHS,
                repos_map=fleure.globals.REPOS_MAP,
                conf_path=fleure.globals.FLEURE_SYSCONF,
                backend=DEFAULT_BACKEND,
                backends=BACKENDS,
                cachedir=None,
                period=None,
                refdir=None,
                archive=False,
                defails=True,
                rpmkeys=fleure.globals.RPM_KEYS)


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
    if not path:
        raise ValueError("(Maybe) Empty path was given!")

    if path.startswith('~'):
        path = os.path.expanduser(path)

    return os.path.normpath(os.path.abspath(path))


def try_to_load_config_from_files(conf_path=None):
    """
    Load configurations from given `conf_path`.
    """
    cnf = DEFAULTS.copy()

    if conf_path:
        try:
            diff = anyconfig.load(conf_path)
            anyconfig.api.merge(cnf, diff)
        except (IOError, OSError):
            pass

    return cnf


class Host(bunch.Bunch):
    """Object holding common configurations and host specific data.
    """
    def __init__(self, root_or_arc_path, conf_path=None, **kwargs):
        """
        Initialize some lazy configurations.

        :param root_or_arc_path:
            Path to the root dir of RPM DB files or Archive (tar.xz, tar.gz,
            zip, etc.) of RPM DB files. Path might be a relative path from
            current dir.
        :param conf_path: Configuration file[s] path

        :param kwargs: Other options
            - workdir: Working dir to keep temporal files and save results
            - repos: A list of Yum repositories to fetch metadata. It will be
              guessed from some metadata automatically in given RPM DB files by
              default.
            - hid: Host ID like hostname where the RPM DB are collected
            - cvss_min_score: CVSS minimum score
            - errata_keywords: Keywords to filter errata
            - errata_pkeywords: Keywords per packages to filter errata
            - core_rpms: Core RPMs
            - rpm_vendor: RPM Vendor
            - tpaths: A list of template paths
            - repos_map: Repository mappings
            - backend: Backend to get updates and errata.

            - cachedir: Dir to save cache files
            - period: Period to fetch and analyze data as a tuple of dates in
              format of YYYY[-MM[-DD]], eg. ("2014-10-01", "2014-11-01").
            - refdir: A dir holding reference data previously generated to
              compute delta, updates since that data generated.
        """
        if conf_path:
            conf_path = _normpath(conf_path)  # Workaround for anyconfig.

        cnf = try_to_load_config_from_files(conf_path)
        cnf.update(kwargs)  # Override with kwargs may came from CLI options.

        # These parameters need some modifications:
        if cnf["period"]:
            cnf["period"] = fleure.dates.period_to_dates(*cnf["period"])

        super(Host, self).__init__(cnf)

        # post setups:
        self.root_or_arc_path = root_or_arc_path
        if os.path.isdir(root_or_arc_path):
            self.root = _normpath(root_or_arc_path)
        else:
            self.root = None

        if self.workdir is None or not self.workdir:
            self.workdir = self.root

        if not getattr(self, "hid", False):
            self.hid = str(uuid.uuid4()).split('-')[0]

        if not getattr(self, "repos_map", False):
            self.repos_map = fleure.globals.REPOS_MAP

        if not getattr(self, "repos", False):
            self.repos = []

        self.tpaths = [_normpath(p) for p in self.tpaths]

        if self.cachedir is None:
            if self.root is not None:
                self.cachedir = os.path.join(self.root, "var/cache")
            # else:  -> cachedir will be set in :meth:`configure` later.
        else:
            self.cachedir = _normpath(self.cachedir)

        # These will be initialized later.
        self.base = None
        self.available = False
        self.errors = []
        self.details = True

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

        if not fleure.rpmutils.check_rpmdb_root(self.root):
            self.errors.append("Invalid RPM DBs: " + self.root)
            return

        if not getattr(self, "repos", False):
            self.repos = fleure.rpmutils.guess_rhel_repos(self.root, None,
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
        if not self.has_valid_root():
            raise RuntimeError("Root is invalid. Initialize it at first!")

        backend = self.backends.get(self.backend)
        self.base = backend(self.root, self.repos, workdir=self.workdir,
                            cachedir=self.cachedir)
        return self.base

    def save(self, obj, filename, savedir=None, **kwargs):
        """
        :param obj: Object to save
        :param filename: File base name to save
        :param savedir: Directory to save results
        :param kwargs: Extra keyword arguments passed to anyconfig.dump
        """
        if anyconfig.utils.is_iterable(obj):
            obj = dict(data=obj, )  # Top level data should be a dict.

        if savedir is None:
            savedir = self.workdir

        filepath = os.path.join(savedir, "%s.json" % filename)
        anyconfig.dump(obj, filepath, **kwargs)

# vim:sw=4:ts=4:et:
