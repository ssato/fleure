#
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# Author: Satoru SATOH <ssato@redhat.com>
# License: GPLv3+
#
"""DNF backend.
"""
from __future__ import absolute_import

import collections
import dnf.conf
import dnf
import hawkey
import itertools
import logging
import operator
import os.path

import fleure.base
import fleure.package
import fleure.utils


LOG = logging.getLogger(__name__)


def _to_pkg(pkg, extras=None):
    """
    Convert Package object :: hawkey.Package to a dict object
    :: fleure.package.Package object.

    :param pkg: Package object which base.list_installed(), etc. returns
    :param extras:
        A list of dicts represent extra packages which is installed but not
        available from yum repos available.

    .. todo:: Some data is missing in hawkey.Package and we must get them
       anyhow; hawkey.Package.packager != vendor, buildhost is not
       available, etc.
    """
    if extras is None:
        originally_from = "TBD"
    else:
        if pkg.name in (e["name"] for e in extras):
            originally_from = pkg.packager
        else:
            originally_from = "Unknown"

    if isinstance(pkg, collections.Mapping):
        return pkg  # Conversion should be done already.

    return fleure.package.Package(pkg.name, pkg.v, pkg.r, pkg.a, pkg.epoch,
                                  pkg.summary, pkg.packager, "N/A",
                                  originally_from=originally_from)


# see dnf.cli.commands.updateinfo.UpdateInfoCommand.TYPE2LABEL:
HADV_TYPE2LABEL = {hawkey.ADVISORY_BUGFIX: 'bugfix',
                   hawkey.ADVISORY_ENHANCEMENT: 'enhancement',
                   hawkey.ADVISORY_SECURITY: 'security',
                   hawkey.ADVISORY_UNKNOWN: 'unknown'}

HAREF_TYPE2LABEL = {hawkey.REFERENCE_BUGZILLA: "bugzilla",
                    hawkey.REFERENCE_CVE: "cve",
                    hawkey.REFERENCE_VENDOR: "vendor",
                    hawkey.REFERENCE_UNKNOWN: "unknown"}


def type_from_hawkey_adv(hadv):
    """Convert hawkey errata type to advisory type
    """
    return HADV_TYPE2LABEL[hadv.type]


def type_from_hawkey_aref(haref):
    """Convert hawkey errata type to advisory ref label.
    """
    return HAREF_TYPE2LABEL[haref.type]


def get_severity_from_hadv(hadv, default="N/A"):
    """
    Try to detect severity from Security Errata advisory ID.

    :see: https://access.redhat.com/security/updates/classification/
    """
    assert hadv.title, "Not _hawkey.Advisory ?: {}".format(hadv)

    if hadv.type != hawkey.ADVISORY_SECURITY:
        return default

    return hadv.title.split(':')[0]


def _eref_to_pkg(eref):
    """
    Try to convert package info in errata references.

    :eref: _hawkey.AdvisoryPkg object from errata references
    """
    assert eref.evr, "Not _hawkey.AdvisoryPkg ?: {}".format(eref)

    (ver, rel) = eref.evr.rsplit('-')
    if ':' in ver:
        (epoch, ver) = ver.split(':')
    else:
        epoch = '0'

    return dict(name=eref.name, arch=eref.arch, evr=eref.evr,
                epoch=epoch, version=ver, release=rel)


def hadv_to_errata(hadv):
    """
    Make an errata dict from _hawkey.Advisory object.

    :param hadv: A _hawkey.Advisory object
    """
    assert hadv.id, "Not _hawkey.Advisory ?: {}".format(hadv)

    errata = dict(advisory=hadv.id, synopsis=hadv.title,
                  description=hadv.description,
                  update_date=hadv.updated.strftime("%Y-%m-%d"),
                  issue_date=hadv.updated.strftime("%Y-%m-%d"),  # missing?
                  type=type_from_hawkey_adv(hadv),
                  severity=get_severity_from_hadv(hadv))

    errata["bzs"] = [dict(id=r.id, summary=r.title, url=r.url) for r
                     in hadv.references if r.type == hawkey.REFERENCE_BUGZILLA]

    errata["cves"] = [dict(id=r.id, cve=r.id, url=r.url) for r
                      in hadv.references if r.type == hawkey.REFERENCE_CVE]

    errata["packages"] = [_eref_to_pkg(p) for p in hadv.packages]
    errata["package_names"] = fleure.utils.uniq(p.name for p in hadv.packages)
    errata["url"] = fleure.utils.errata_url(str(hadv.id))

    return errata


class Base(fleure.base.Base):
    """Dnf backend.
    """
    _name = "dnf"

    def __init__(self, root='/', repos=None, workdir=None, cachedir=None,
                 cacheonly=False, **kwargs):
        """
        Create and initialize dnf.Base or dnf.cli.cli.BaseCli object.

        :param root: RPM DB root dir
        :param repos: A list of repos to enable
        :param workdir: Working dir to save logs and results
        :param cachedir:
            Dir to save cache, will be <root>/var/cache if None
        :param cacheonly:
            Do not access network to fetch updateinfo data and load them from
            the local cache entirely.

        see also: :function:`dnf.automatic.main.main`

        >>> import os.path
        >>> if os.path.exists("/etc/redhat-release"):
        ...     base = Base()
        ...     assert isinstance(base.base, dnf.Base)
        """
        # setup self.{root, cachedir, ....}
        super(Base, self).__init__(root, repos, **kwargs)

        conf = dnf.conf.Conf()
        if self.root != os.path.sep:
            conf.installroot = self.root
            conf.cachedir = os.path.join(self.root, conf.cachedir[1:])
            conf.logdir = os.path.join(self.root, conf.logdir[1:])
            conf.persistdir = os.path.join(self.root, conf.persistdir[1:])

        self.base = dnf.Base(conf)
        self._hpackages = collections.defaultdict(list)

    def configure(self):
        """Configure repos, etc.
        """
        self.base.read_all_repos()
        for rid, repo in self.base.repos.items():
            getattr(repo, "enable" if rid in self.repos else "disable")()

        self._configured = True

    def _make_list_of(self, item):
        """
        :param item:
            Name of the items to make a list, e.g. 'installed', 'updates',
            'errata'.
        """
        if item in ("installed", "updates", "obsoletes"):  # TODO: others.
            query = self.base.sack.query()

            if item == "installed":
                hpkgs = query.installed()
            elif item == "updates":
                hpkgs = query.upgrades()
            else:  # obsoletes
                hpkgs = query.filter(obsoletes=query.installed())

            if not isinstance(hpkgs, list):
                hpkgs = hpkgs.run()

            self._hpackages[item] = hpkgs
            self._packages[item] = objs = [_to_pkg(p) for p in hpkgs]

        elif item == "errata":
            ips = self._hpackages.get("installed", False)
            if not ips:
                # Make it generated and cached.
                self._make_list_of("installed")
                ips = self._hpackages.get("installed", False)

            advs = itertools.chain(*(p.get_advisories(hawkey.GT) for p in ips))
            advs = fleure.utils.uniq(advs, key=operator.attrgetter("id"))
            self._hpackages["errata"] = advs
            self._packages["errata"] = objs = [hadv_to_errata(a) for a in advs]

        return objs

    def populate(self):
        """
        Initialize RPM DB (sack) and Yum repo metadata (fetch from remote).
        """
        if not self._populated:
            # It will take some time to get metadata from remote repos.
            # see :method:`run` in :class:`dnf.cli.cli.Cli`.
            self.base.fill_sack(load_system_repo='auto')
            self.base.upgrade_all()
            self.base.resolve()

            self._populated = True

# vim:sw=4:ts=4:et:
