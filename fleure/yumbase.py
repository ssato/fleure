#
# Copyright (C) 2014 - 2015 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato@redhat.com>
# License: GPLv3+
#
"""Yum backend.
"""
from __future__ import absolute_import

import collections
import itertools
import logging
import yum

import fleure.base
import fleure.utils


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
    errata["url"] = fleure.utils.errata_url(errata["advisory"])

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

    return fleure.base.Package(pkg.name, pkg.version, pkg.release, pkg.arch,
                               pkg.epoch, pkg.summary, pkg.vendor,
                               pkg.buildhost, extras)


class Base(fleure.base.Base):
    """Yum backend.
    """
    _name = "yum"

    def __init__(self, root='/', repos=None, load_available_repos=True,
                 **kwargs):
        """
        Create an initialized yum.YumBase instance.
        Created instance has no enabled repos by default.

        :param root: RPM DB root dir in absolute path
        :param repos: List of Yum repos to enable
        :param load_available_repos: It will populates the package sack from
            the repositories if True

        >>> import os.path
        >>> if os.path.exists("/etc/redhat-release"):
        ...     base = Base()
        ...     assert isinstance(base.base, yum.YumBase)
        ...     base.base.repos.listEnabled() == []
        True
        """
        super(Base, self).__init__(root, repos, **kwargs)
        self.base = yum.YumBase()

        try:
            self.base.conf.installroot = self.root
        except AttributeError:
            self.base.preconf.root = self.root

        self.base.conf.cachedir = self.cachedir
        self.base.logger = self.base.verbose_logger = LOG

        self._activate_repos(repos)

        self.packages = dict()
        self.load_available_repos = load_available_repos
        self.populated = False

    @property
    def cachedir(self):
        """cachedir property (overridden)"""
        return self.base.conf.cachedir

    def set_cachedir(self, cachedir):
        """setup cachedir"""
        self.base.conf.cachedir = cachedir

    def set_cacheonly(self):
        """make it not using network and only fetch data from local cache.
        """
        self.base.conf.cache = 1

    def _activate_repos(self, repos):
        """
        Enable only given yum repos.

        :param repos: A list of repos to enable
        :see: :meth:`findRepos` of the :class:`yum.repos.RepoStorage`
        """
        # Disale all repos at first.
        for repo in self.base.repos.findRepos('*'):
            repo.disable()

        if repos is not None:
            for repo_name in repos:
                for repo in self.base.repos.findRepos(repo_name):
                    repo.enable()

    def _load_repos(self):
        """
        Populates the package sack from the repositories.  Network access
        happens if any non-local repos activated and it will take some time
        to finish.
        """
        if self.load_available_repos and not self.populated:
            LOG.info("Loading yum repo metadata from repos: %s",
                     ','.join(r.id for r in self.base.repos.listEnabled()))
            # self.base._getTs()
            self.base._getSacks()
            self.base._getUpdates()
            self.populated = True

    def list_packages(self, pkgnarrow="installed"):
        """
        List installed or update RPMs similar to
        "repoquery --pkgnarrow=updates --all --plugins --qf '%{nevra}'".

        :param pkgnarrow: Package list narrowing factor
        :return: A dict contains lists of dicts of packages

        TODO: Find out better and correct ways to activate repo and sacks.
        """
        assert pkgnarrow in _PKG_NARROWS, "Invalid pkgnarrow: " + pkgnarrow

        pkgs = self.packages.get(pkgnarrow)
        if pkgs:
            return pkgs

        self._load_repos()

        ygh = self.base.doPackageLists(pkgnarrow)
        pkgs = [_to_pkg(p) for p in getattr(ygh, pkgnarrow, [])]
        self.packages[pkgnarrow] = pkgs

        return pkgs

    def list_installed(self):
        """
        :return: List of dicts of installed RPMs info

        see also: yum.updateinfo.exclude_updates
        """
        extras = [e["name"] for e in self.list_packages("extras")]

        ygh = self.base.doPackageLists("installed")
        ips = [_to_pkg(p, extras) for p in ygh.installed]
        self.packages["installed"] = ips

        return ips

    def list_updates(self, obsoletes=True):
        """
        Method to mimic "yum check-update".

        :param obsoletes: Include obsoletes in updates list if True
        :return: List of dicts of update RPMs info
        """
        ups = self.list_packages("updates")

        if obsoletes:
            obs = self.list_packages("obsoletes")
            return ups + obs
        else:
            return ups

    def list_errata(self):
        """
        List applicable Errata.

        :param root: RPM DB root dir in absolute path
        :param repos: List of Yum repos to enable
        :param disabled_repos: List of Yum repos to disable

        :return: A dict contains lists of dicts of errata
        """
        self._load_repos()
        oldpkgtups = [t[1] for t in self.base.up.getUpdatesTuples()]
        npss_g = itertools.ifilter(None,
                                   (self.base.upinfo.get_applicable_notices(o)
                                    for o in oldpkgtups))
        ers = itertools.chain(*((_notice_to_errata(t[1]) for t in ts) for ts
                                in npss_g))
        return list(ers)

# vim:sw=4:ts=4:et:
