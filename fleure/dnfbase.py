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
import fleure.utils


LOG = logging.getLogger(__name__)


def _to_pkg(pkg, extras=None):
    """
    Convert Package object :: hawkey.Package to fleure.base.Package
    object.

    :param pkg: Package object which Base.list_installed(), etc. returns
    :param extras: A list of dicts represent extra packages which is installed
        but not available from yum repos available.

    :todo: Some data is missing in hawkey.Package,
        e.g. hawkey.Package.packager != vendor and buildhost is not available.
    """
    if extras is None:
        originally_from = "TBD"
    else:
        if pkg.name in (e["name"] for e in extras):
            originally_from = pkg.packager
        else:
            originally_from = "Unknown"

    if isinstance(pkg, collections.Mapping):
        return pkg

    return fleure.base.Package(pkg.name, pkg.v, pkg.r, pkg.a, pkg.epoch,
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

    def __init__(self, root='/', repos=None, workdir=None, **kwargs):
        """
        Create and initialize dnf.Base or dnf.cli.cli.BaseCli object.

        :param root: RPM DB root dir
        :param repos: A list of repos to enable
        :param disabled_repos: A list of repos to disable
        :param workdir: Working dir to save logs and results

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

        self._repo_md_ready = False
        self._hpackages = collections.defaultdict(list)

    def _list_dnf_installed(self):
        """
        Compute the installed packages list and cache it internally if not.

        Please note that this private method expects initialization (see
        :meth:`prepare`) has been done already.

        :return: A list of installed hawkey.Package
        """
        if not self._hpackages["installed"]:
            res = self.base.sack.query().installed()
            if not isinstance(res, list):
                res = res.run()
            self._hpackages["installed"] = res

        return self._hpackages["installed"]

    def _list_dnf_upgrades(self):
        """
        Compute the update packages list and cache it internally if not like
        :meth:`_list_dnf_installed`.

        Please note that this private method expects initialization (see
        :meth:`prepare`) has been done already.

        :return: A list of update hawkey.Package
        """
        if not self._hpackages["updates"]:
            res = self.base.sack.query().upgrades()
            if not isinstance(res, list):
                res = res.run()
            self._hpackages["updates"] = res

        return self._hpackages["updates"]

    def _list_dnf_obsoletes(self):
        """
        Compute the obsolete packages list and cache it internally if not like
        :meth:`_list_dnf_upgrades`. The results should be a sub set of upgrade
        packages.

        Please note that this private method expects initialization (see
        :meth:`prepare`) has been done already.

        :return: A list of update hawkey.Package
        """
        if not self._hpackages["obsoletes"]:
            qry = self.base.sack.query()
            res = self.base.sack.query().filter(obsoletes=qry.installed())
            if not isinstance(res, list):
                res = res.run()
            self._hpackages["obsoletes"] = res

        return self._hpackages["obsoletes"]

    def prepare(self):
        """
        Initialize RPM DB (sack) and Yum repo metadata (fetch from remote).
        """
        if not self._repo_md_ready:
            self.base.read_all_repos()
            for rid in self.base.repos.keys():
                if rid in self.repos:
                    self.base.repos[rid].enable()
                else:
                    self.base.repos[rid].disable()

            # It will take some time to get metadata from remote repos.
            # see :method:`run` in :class:`dnf.cli.cli.Cli`.
            self.base.fill_sack(load_system_repo='auto')
            self.base.upgrade_all()
            self.base.resolve()

            self._repo_md_ready = True

    def list_installed_impl(self, **kwargs):
        """
        List installed packages.

        >>> import os.path
        >>> if os.path.exists("/etc/redhat-release"):
        ...     base = Base()
        ...     ipkgs = base.list_installed_impl()
        ...     assert len(ipkgs) > 0
        """
        self.prepare()
        if not self._packages["installed"]:
            ips = self._list_dnf_installed()
            self._packages["installed"] = [_to_pkg(p) for p in ips]

        return self._packages["installed"]

    def list_errata_impl(self, **kwargs):
        """
        List errata.
        """
        self.prepare()
        if not self._hpackages["errata"]:
            ips = self._list_dnf_installed()
            advs = itertools.chain(*(pkg.get_advisories(hawkey.GT) for pkg
                                     in ips))
            advs = fleure.utils.uniq(advs, key=operator.attrgetter("id"))
            self._hpackages["errata"] = advs
            self._packages["errata"] = [hadv_to_errata(a) for a in advs]

        return self._packages["errata"]

    def list_updates_impl(self, obsoletes=True, **kwargs):
        """
        :param obsoletes: Include obsoletes in updates list if True
        """
        self.prepare()
        if not self._packages["updates"]:
            res = self._list_dnf_upgrades()
            self._packages["updates"] = [_to_pkg(p) for p in res]

            res = self._list_dnf_obsoletes()
            self._packages["obsoletes"] = [_to_pkg(p) for p in res]

        return self._packages["updates"]  # obosletes in updates.

# vim:sw=4:ts=4:et:
