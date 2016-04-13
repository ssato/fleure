#
# Copyright (C) 2014 - 2015 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato@redhat.com>
# License: GPLv3+
#
"""Yum backend.
"""
from __future__ import absolute_import

import collections
import functools
import itertools
import logging
import operator
import yum

import fleure.base
import fleure.package
import fleure.rpmutils
import fleure.utils

from fleure.globals import _
from fleure.utils import chaincalls


LOG = logging.getLogger(__name__)

_PKG_NARROWS = ("installed", "available", "updates", "extras", "obsoletes",
                "recent")

RHBZ_URL_BASE = "https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id="


def normalize_bz(bzref, urlbase=RHBZ_URL_BASE):
    """
    Normalize bugzilla ticket info dict came from updateinfo.
    """
    bzref["summary"] = bzref["title"]
    bzref["url"] = bzref.get("href", urlbase + str(bzref["id"]))

    return bzref


def normalize_cve(cve):
    """
    Normalize cve dict came from updateinfo.
    """
    cve["cve"] = cve["id"]
    cve["url"] = cve["href"]

    return cve


def _notice_to_errata(notice):
    """
    Notice metadata examples:

    packages:

     'pkglist': [
        {'name': 'Red Hat Enterprise Linux Server (v. 6 for 64-bit x86_64)',
         'packages': [
            {'arch': 'x86_64',
             'epoch': '0',
             'filename': 'xorg-x11-drv-fbdev-0.4.3-16.el6.x86_64.rpm',
             'name': 'xorg-x11-drv-fbdev',
             'release': '16.el6',
             'src': 'xorg-x11-drv-fbdev-0.4.3-16.el6.src.rpm',
             'sum': ('sha256', '8f3da83bb19c3776053c543002c9...'),
             'version': '0.4.3'},
             ...
        },
        ...
     ]

    cve in notice_metadata["references"]:

    {'href': 'https://www.redhat.com/security/data/cve/CVE-2013-1994.html',
     'id': 'CVE-2013-1994',
     'title': 'CVE-2013-1994',
     'type': 'cve'}
    """
    if notice is None:
        return notice

    nmd = notice.get_metadata()

    errata = dict(advisory=nmd["update_id"], synopsis=nmd["title"],
                  description=nmd["description"], update_date=nmd["updated"],
                  issue_date=nmd["issued"], solution=nmd["solution"],
                  type=nmd["type"], severity=nmd.get("severity", "N/A"))

    errata["bzs"] = [normalize_bz(bz) for bz in
                     itertools.ifilter(lambda r: r.get("type") == "bugzilla",
                                       nmd.get("references", []))]
    errata["cves"] = [normalize_cve(cve) for cve in
                      itertools.ifilter(lambda r: r.get("type") == "cve",
                                        nmd.get("references", []))]

    errata["packages"] = fleure.utils.concat(nps["packages"] for nps
                                             in nmd.get("pkglist", []))

    pns = fleure.utils.uniq(p["name"] for p in errata["packages"])
    errata["package_names"] = ','.join(pns)
    errata["url"] = fleure.rpmutils.errata_url(errata["advisory"])

    return errata


def _to_pkg(pkg, extras=None):
    """
    Convert Package object, instance of yum.rpmsack.RPMInstalledPackage,
    yum.sqlitesack..YumAvailablePackageSqlite, etc., to
    fleure.base.Package object.

    :param pkg: Package object which Base.list_installed(), etc. returns
    :param extras: A list of names of extra packages which is installed
        but not available from yum repos available.

    NOTE: Take care of rpm db session.
    """
    if isinstance(pkg, collections.Mapping):
        return pkg

    return fleure.package.Package(pkg.name, pkg.version, pkg.release, pkg.arch,
                                  pkg.epoch, pkg.summary, pkg.vendor,
                                  pkg.buildhost, extras=extras)


class Base(fleure.base.Base):
    """Yum backend.
    """
    _name = "yum"

    def __init__(self, root='/', repos=None, workdir=None, cachedir=None,
                 cacheonly=False, **kwargs):
        """
        Create an initialized yum.YumBase instance.
        Created instance has no enabled repos by default.

        :param root: RPM DB root dir, ex. '/' (var/lib/rpm)
        :param repos: A list of repos to enable
        :param workdir: Working dir to save logs and results
        :param cachedir:
            Dir to save cache, will be <root>/var/cache if None
        :param cacheonly:
            Do not access network to fetch updateinfo data and load them from
            the local cache entirely.

        >>> import os.path
        >>> if os.path.exists("/etc/redhat-release"):
        ...     base = Base()
        ...     assert isinstance(base.base, yum.YumBase)
        """
        super(Base, self).__init__(root, repos, workdir, cachedir, cacheonly,
                                   **kwargs)
        self.base = yum.YumBase()

        # TODO: In some versions of yum, yum.YumBase.preconf.root might needs
        # to be set instead of yum.YumBase.conf.installroot.
        self.base.conf.installroot = self.root
        self.base.conf.cachedir = self.cachedir
        self.base.logger = self.base.verbose_logger = LOG

        if self.cacheonly:
            self.base.conf.cache = 1

    def _activate_repos(self, repos):
        """
        Enable only specified yum repos explicitly with others are disabled.

        :param repos: A list of repo IDs to enable
        :see: :meth:`findRepos` of the :class:`yum.repos.RepoStorage`
        """
        for repo in self.base.repos.findRepos('*'):  # Disale all at first.
            repo.disable()

        if repos is not None:
            for rid in repos:
                for repo in self.base.repos.findRepos(rid):
                    repo.enable()

    def _make_list_of(self, pkgnarrow, process_fns=None):
        """
        List installed or update RPMs similar to
        "repoquery --pkgnarrow=updates --all --plugins --qf '%{nevra}'".

        :param pkgnarrow: Package list narrowing factor or 'errata'
        :param process_fns:
            Any callable objects to process item or None to do nothing with it
        :return: A dict contains lists of dicts of packages
        """
        if pkgnarrow in _PKG_NARROWS:
            ygh = self.base.doPackageLists(pkgnarrow)

            if pkgnarrow == "installed":
                extras = [p["name"] for p in self._make_list_of("extras")]
                calls = (functools.partial(_to_pkg, extras=extras),
                         process_fns)
                objs = [chaincalls(p, *calls) for p in ygh.installed]
            else:
                objs = [chaincalls(p, _to_pkg, process_fns) for p in
                        getattr(ygh, pkgnarrow, [])]

            self._packages[pkgnarrow] = objs

        elif pkgnarrow == "errata":
            # - `oupdates` in :func:`update_minimal` in yum.updateinfo
            # - `data` in ...
            calls = (operator.itemgetter(1),
                     self.base.upinfo.get_applicable_notices)
            nps = itertools.ifilter(None,
                                    (chaincalls(t, *calls) for t in
                                     self.base.up.getUpdatesTuples()))
            calls = (operator.itemgetter(1), _notice_to_errata, process_fns)
            ers = itertools.chain(*((chaincalls(t, *calls) for t in ts)
                                    for ts in nps))
            objs = list(ers)
            self._packages[pkgnarrow] = objs

        else:
            raise ValueError("Invalid list item was given: %s", pkgnarrow)

        return objs

    def configure(self):
        """Configure RPM DB root, yum repos to fetch updateinfo and setup
        cachedir.
        """
        self._activate_repos(self.repos)
        self._configured = True

    def populate(self):
        """
        Populates the package sack from the repositories.

        Network access to yum repos will happen if any non-local repos
        activated and it should be going to take some time to finish.
        """
        if not self._populated:
            LOG.info(_("Loading yum repo metadata from repos: %s"),
                     ','.join(r.id for r in self.base.repos.listEnabled()))
            # self.base._getTs()
            self.base._getSacks()
            self.base._getUpdates()

        self._populated = True  # TBD

# vim:sw=4:ts=4:et:
