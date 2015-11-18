#
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# Author: Satoru SATOH <ssato@redhat.com>
# License: GPLv3+
#
# Suppress warning of dnf.base.sack.add_excludes call:
# pylint: disable=no-member
"""DNF backend.
"""
from __future__ import absolute_import

import collections
import dnf
import hawkey
import itertools
import logging
import operator
import os.path

import fleure.base
import fleure.globals
import fleure.package
import fleure.utils


LOG = logging.getLogger(__name__)
Package = collections.namedtuple("Package", "name epoch version release arch")


def _inspect(ipkg, extra_names=None):
    """
    Inspect ipkg and update it.
    """
    ret = fleure.package.inspect_origin(ipkg["name"], ipkg["vendor"],
                                        ipkg["buildhost"], extra_names)
    ipkg.update(**ret)
    return ipkg


def _list_installed(root, enames=None):
    """
    DNF (hawkey) does not provide some RPM info for installed RPMs such like
    buildhost, vendor. This is an workaround for that.

    :param root: Root dir of RPM DBs
    :param enames: A list of extra packages not availabe from given repos
    :return: A list of packages :: [dict]
    """
    # see :class:`~fleure.package.Package`
    keys = list(fleure.globals.RPM_KEYS) + ["summary", "vendor", "buildhost"]
    ips = fleure.utils.list_installed_rpms(root, keys)

    return [fleure.package.Package.from_dict(_inspect(p, enames)) for p in ips]


def _to_pkg(pkg):
    """
    Convert Package object :: hawkey.Package to a dict object
    :: fleure.package.Package object.

    :param pkg: Package object which base.list_installed(), etc. returns
    :param extras:
        True if given package is extras, not available from given yum repos.
    """
    if isinstance(pkg, collections.Mapping):
        return pkg  # Conversion should be done already.

    originally_from = "Unknown"

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
    if not hadv.title:
        raise ValueError("Not _hawkey.Advisory ?: {}".format(hadv))

    if hadv.type != hawkey.ADVISORY_SECURITY:
        return default

    return hadv.title.split(':')[0]


def _eref_to_pkg(eref):
    """
    Try to convert package info in errata references.

    :eref: _hawkey.AdvisoryPkg object from errata references
    """
    if not eref.evr:
        raise ValueError("Not _hawkey.AdvisoryPkg ?: {}".format(eref))

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
    if not hadv.id:
        raise ValueError("Not _hawkey.Advisory ?: {}".format(hadv))

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


def _pathjoin(*paths):
    """
    :param paths: A list of paths to join

    >>> _pathjoin('/', 'a/b/c')
    '/a/b/c'
    >>> _pathjoin('/', 'a', 'b', 'c')
    '/a/b/c'
    >>> _pathjoin('/', '/a/b/c')
    '/a/b/c'
    """
    if not paths:
        return os.path.sep

    ret = paths[0]
    for subpath in paths[1:]:
        if not subpath:
            return ret

        if subpath.startswith(os.path.sep):
            subpath = subpath[1:]

        ret = os.path.join(ret, subpath)

    return ret


class Base(fleure.base.Base):
    """Dnf backend.

    TODO: Implement cacheonly mode.
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
        super(Base, self).__init__(root, repos, workdir, cachedir,
                                   cacheonly, **kwargs)

        conf = dnf.conf.Conf()
        if self.root != os.path.sep:
            conf.installroot = self.root
            conf.logdir = _pathjoin(self.root, conf.logdir)
            conf.persistdir = _pathjoin(self.root, conf.persistdir)

        # :see: https://bugzilla.redhat.com/show_bug.cgi?id=1184943
        if cachedir is None:
            conf.cachedir = _pathjoin(self.root, conf.cachedir)
            self.cachedir = conf.cachedir
        else:
            self.cachedir = conf.cachedir = cachedir

        self.base = dnf.Base(conf)
        # self.base.conf.cachedir = self.cachedir   # Required?
        self._hpackages = collections.defaultdict(list)

    def _make_list_of(self, item):
        """
        :param item:
            Name of the items to make a list, e.g. 'installed', 'updates',
            'errata'.
        """
        if item in ("installed", "updates", "obsoletes"):  # TODO: others.
            query = self.base.sack.query()

            if item == "installed":
                hpkgs = query.installed()  # These lack of buildhost, etc.
                self._hpackages[item] = hpkgs  # Just to cache for errata.

                havails = query.available()
                extras = [p for p in hpkgs if p not in havails]
                ens = fleure.utils.uniq(e.name for e in extras)

                self._packages[item] = objs = _list_installed(self.root, ens)
                return objs
            elif item == "updates":
                hpkgs = query.upgrades().latest()
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

    def configure(self):
        """Configure repos, etc.
        """
        self.base.read_all_repos()
        for rid, repo in self.base.repos.items():
            getattr(repo, "enable" if rid in self.repos else "disable")()
            # :see: :meth:`md_only_cached` of the :class:`dnf.repo.Repo`
            if self.cacheonly:
                repo.md_only_cached = True

        self._configured = True

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

    def compute_removed(self, pkgspecs, excludes=None):
        """
        Compute packages to remove (uninstall) in consideration of excludes.

        :param pkgspecs: Names or wildcards of packages trying to remove
        :param excludes:
            Names or wildcards specifying packages must not be removed

        :return:
            A tuple of excludes ([name]) and packages [(N, E, V, R, A)] to
            remove (uninstall)
        """
        if not pkgspecs:
            return ([], [])  # Nothing to do.

        if excludes is None:
            excludes = []

        def _excludes_from_removed(excls):
            """
            see :method:`dnf.base.Base._setup_excludes`.
            """
            for excl in excls:
                pkgs = self.base.sack.query().filter_autoglob(name=excl)
                if pkgs:
                    self.base.sack.add_excludes(pkgs)
                    yield excl

        def _trans_to_pkg(trans):
            """Convert transaction object (erased) to a pkg tuple
            """
            return Package(trans.name, trans.e, trans.v, trans.r, trans.a)

        self._assert_if_not_ready("excluding ...")
        excls = list(_excludes_from_removed(excludes))
        removes = []
        for pspec in pkgspecs:
            try:
                self.base.remove(pspec)
                self.base.resolve(allow_erasing=True)
                ers = [_trans_to_pkg(x.erased) for x in
                       self.base.transaction.get_items(dnf.transaction.ERASE)]
                removes.extend(ers)

            except dnf.exceptions.PackagesNotInstalledError:
                logging.info("Excluded or no package matched: %s", pspec)

            except dnf.exceptions.DepsolveError:
                logging.warn("Depsolv error! Make it excluded: %s", pspec)
                excls.extend(list(_excludes_from_removed([pspec])))

        return (sorted(set(removes)), sorted(set(excls)))

# vim:sw=4:ts=4:et:
