#
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: AGPLv3+
#
# pylint: disable=too-many-arguments,too-many-locals,no-member
"""Fleure's main module
"""
from __future__ import absolute_import
from operator import itemgetter

# Available in EPEL for RHELs:
# https://apps.fedoraproject.org/packages/python-bunch
import bunch
import datetime
import functools
import itertools
import logging
import os.path
import os
import tablib

import fleure.cveinfo
import fleure.globals
import fleure.datasets
import fleure.utils

from fleure.globals import _
from fleure.datasets import (
    make_dataset, list_updates_from_errata, list_latest_errata_by_updates,
    NEVRA_KEYS,
)

import fleure.yumbase

BACKENDS = dict(yum=fleure.yumbase.Base, )
DEFAULT_BACKEND = "yum"
try:
    import fleure.dnfbase

    BACKENDS["dnf"] = fleure.dnfbase.Base
    DEFAULT_BACKEND = "dnf"  # Prefer this.
except ImportError:  # dnf is not available for RHEL, AFAIK.
    pass

if os.environ.get("FLEURE_MEMORY_DEBUG", False):
    try:
        from memory_profiler import profile
    except ImportError:
        def profile(fnc):
            """memory profile decorator"""
            def wrapper(*args, **kwargs):
                """memory profile wrapper"""
                return fnc(*args, **kwargs)
            return functools.wraps(fnc)(wrapper)
else:
    def profile(fnc):
        """memory profile decorator"""
        def wrapper(*args, **kwargs):
            """memory profile wrapper"""
            return fnc(*args, **kwargs)
        return functools.wraps(fnc)(wrapper)


LOG = logging.getLogger("fleure")

ERRATA_KEYWORDS = ("crash", "panic", "hang", "SEGV", "segmentation fault",
                   "data corruption")
CORE_RPMS = ("kernel", "glibc", "bash", "openssl", "zlib")


def errata_matches_keywords_g(ers, keywords=ERRATA_KEYWORDS):
    """
    :param ers: A list of errata
    :param keywords: Keyword list to filter 'important' RHBAs
    :return: A generator to yield errata of which description contains any of
        given keywords
    """
    for ert in ers:
        mks = [k for k in keywords if k in ert["description"]]
        if mks:
            ert["keywords"] = mks
            yield ert


_ERT_KFN = lambda e: (len(e["update_names"]), itemgetter("issue_date"))


def errata_of_rpms(ers, rpms=None, kfn=_ERT_KFN):
    """
    :param ers: A list of errata
    :param rpms: RPM names to select relevant errata
    :return: A list of errata relevant to any of given RPMs
    """
    if rpms is None:
        return []

    return sorted((e for e in ers if any(n in e["update_names"] for n
                                         in rpms)),
                  key=kfn, reverse=True)


def list_num_of_es_for_updates(ers):
    """
    List number of specific type of errata for each package names.

    :param ers: List of reference errata of specific type (and severity)
    :return: [(package_name :: str, num_of_relevant_errata :: Int)]
    """
    unes = fleure.utils.uconcat([(u["name"], e) for u in e["updates"]] for e
                                in ers)
    uess = [(k, [ue[1]["advisory"] for ue in g]) for k, g in
            itertools.groupby(unes, itemgetter(0))]

    return sorted(((un, len(ers)) for un, ers in uess), key=itemgetter(1),
                  reverse=True)


def mk_update_name_vs_advs_map(ers):
    """
    Make a list of a dict {name: [adv]} where name is name of update
    package relevant to an errata and [adv] is a list of its advisories.

    :param ers: A list of applicable errata sorted by severity
        if it's RHSA and advisory in ascending sequence
    """
    def un_adv_pairs(ers):
        """pair name of updates and errata advisories"""
        for ert in ers:
            for uname in ert.get("update_names", []):
                yield (uname, ert["advisory"])

    un_advs_list = sorted(un_adv_pairs(ers), key=itemgetter(0))
    return sorted(((k, [t[1] for t in g]) for k, g in
                   itertools.groupby(un_advs_list, key=itemgetter(0))),
                  key=lambda t: len(t[1]), reverse=True)


def analyze_errata(ers, score=0, keywords=ERRATA_KEYWORDS,
                   core_rpms=CORE_RPMS):
    """
    :param ers: A list of applicable errata sorted by severity
        if it's RHSA and advisory in ascending sequence
    :param score: CVSS base metrics score
    :param keywords: Keyword list to filter 'important' RHBAs
    :param core_rpms: Core RPMs to filter errata by them
    """
    rhsa = [e for e in ers if e["advisory"][2] == 'S']
    cri_rhsa = [e for e in rhsa if e.get("severity") == "Critical"]
    imp_rhsa = [e for e in rhsa if e.get("severity") == "Important"]
    latest_cri_rhsa = list_latest_errata_by_updates(cri_rhsa)
    latest_imp_rhsa = list_latest_errata_by_updates(imp_rhsa)

    us_of_cri_rhsa = list_updates_from_errata(cri_rhsa)
    us_of_imp_rhsa = list_updates_from_errata(imp_rhsa)

    rhba = [e for e in ers if e["advisory"][2] == 'B']

    kfn = lambda e: (len(e.get("keywords", [])), e["issue_date"],
                     e["update_names"])
    rhba_by_kwds = sorted(errata_matches_keywords_g(rhba, keywords),
                          key=kfn, reverse=True)
    rhba_of_rpms_by_kwds = errata_of_rpms(rhba_by_kwds, core_rpms, kfn)
    rhba_of_rpms = errata_of_rpms(rhba, core_rpms,
                                  itemgetter("update_names"))
    latest_rhba_of_rpms = list_latest_errata_by_updates(rhba_of_rpms)

    if score > 0:
        hsce_fn = fleure.datasets.higher_score_cve_errata_g
        rhsa_by_score = list(hsce_fn(rhsa, score))
        rhba_by_score = list(hsce_fn(rhba, score))
        us_of_rhsa_by_score = list_updates_from_errata(rhsa_by_score)
        us_of_rhba_by_score = list_updates_from_errata(rhba_by_score)
    else:
        rhsa_by_score = []
        rhba_by_score = []
        us_of_rhsa_by_score = []
        us_of_rhba_by_score = []

    us_of_rhba_by_kwds = list_updates_from_errata(rhba_by_kwds)

    rhea = [e for e in ers if e["advisory"][2] == 'E']

    rhsa_rate_by_sev = [("Critical", len(cri_rhsa)),
                        ("Important", len(imp_rhsa)),
                        ("Moderate",
                         len([e for e in rhsa
                              if e.get("severity") == "Moderate"])),
                        ("Low",
                         len([e for e in rhsa
                              if e.get("severity") == "Low"]))]

    n_rhsa_by_pns = list_num_of_es_for_updates(rhsa)
    n_cri_rhsa_by_pns = list_num_of_es_for_updates(cri_rhsa)
    n_imp_rhsa_by_pns = list_num_of_es_for_updates(imp_rhsa)

    n_rhba_by_pns = list_num_of_es_for_updates(rhba)

    return dict(rhsa=dict(list=rhsa,
                          list_critical=cri_rhsa,
                          list_important=imp_rhsa,
                          list_latest_critical=latest_cri_rhsa,
                          list_latest_important=latest_imp_rhsa,
                          list_higher_cvss_score=rhsa_by_score,
                          list_critical_updates=us_of_cri_rhsa,
                          list_important_updates=us_of_imp_rhsa,
                          list_higher_cvss_updates=us_of_rhsa_by_score,
                          rate_by_sev=rhsa_rate_by_sev,
                          list_n_by_pnames=n_rhsa_by_pns,
                          list_n_cri_by_pnames=n_cri_rhsa_by_pns,
                          list_n_imp_by_pnames=n_imp_rhsa_by_pns,
                          list_by_packages=mk_update_name_vs_advs_map(rhsa)),
                rhba=dict(list=rhba,
                          list_by_kwds=rhba_by_kwds,
                          list_of_core_rpms=rhba_of_rpms,
                          list_latests_of_core_rpms=latest_rhba_of_rpms,
                          list_by_kwds_of_core_rpms=rhba_of_rpms_by_kwds,
                          list_higher_cvss_score=rhba_by_score,
                          list_updates_by_kwds=us_of_rhba_by_kwds,
                          list_higher_cvss_updates=us_of_rhba_by_score,
                          list_n_by_pnames=n_rhba_by_pns,
                          list_by_packages=mk_update_name_vs_advs_map(rhba)),
                rhea=dict(list=rhea,
                          list_by_packages=mk_update_name_vs_advs_map(rhea)),
                rate_by_type=[("Security", len(rhsa)),
                              ("Bug", len(rhba)),
                              ("Enhancement", len(rhea))])


def padding_row(row, mcols):
    """
    :param rows: A list of row data :: [[]]

    >>> padding_row(['a', 1], 3)
    ['a', 1, '']
    >>> padding_row([], 2)
    ['', '']
    """
    return row + [''] * (mcols - len(row))


def mk_overview_dataset(data, score=0, keywords=ERRATA_KEYWORDS,
                        core_rpms=None):
    """
    :param data: RPMs, Update RPMs and various errata data summarized
    :param score: CVSS base metrics score limit
    :param core_rpms: Core RPMs to filter errata by them

    :return: An instance of tablib.Dataset becomes a worksheet represents the
        overview of analysys reuslts
    """
    rows = [[_("Critical or Important RHSAs (Security Errata)")],
            [_("# of Critical RHSAs"),
             len(data["errata"]["rhsa"]["list_critical"])],
            [_("# of Critical RHSAs (latests only)"),
             len(data["errata"]["rhsa"]["list_latest_critical"])],
            [_("# of Important RHSAs"),
             len(data["errata"]["rhsa"]["list_important"])],
            [_("# of Important RHSAs (latests only)"),
             len(data["errata"]["rhsa"]["list_latest_important"])],
            [_("Update RPMs by Critical or Important RHSAs at minimum")],
            [_("# of Update RPMs by Critical RHSAs at minimum"),
             len(data["errata"]["rhsa"]["list_critical_updates"])],
            [_("# of Update RPMs by Important RHSAs at minimum"),
             len(data["errata"]["rhsa"]["list_important_updates"])],
            [],
            [_("RHBAs (Bug Errata) by keywords: %s") % ", ".join(keywords)],
            [_("# of RHBAs by keywords"),
             len(data["errata"]["rhba"]["list_by_kwds"])],
            [_("# of Update RPMs by RHBAs by keywords at minimum"),
             len(data["errata"]["rhba"]["list_updates_by_kwds"])]]

    if core_rpms is not None:
        rows += [[],
                 [_("RHBAs of core rpms: %s") % ", ".join(core_rpms)],
                 [_("# of RHBAs of core rpms (latests only)"),
                  len(data["errata"]["rhba"]["list_latests_of_core_rpms"])]]

    if score > 0:
        rows += [[],
                 [_("RHSAs and RHBAs by CVSS score")],
                 [_("# of RHSAs of CVSS Score >= %.1f") % score,
                  len(data["errata"]["rhsa"]["list_higher_cvss_score"])],
                 [_("# of Update RPMs by the above RHSAs at minimum"),
                  len(data["errata"]["rhsa"]["list_higher_cvss_updates"])],
                 [_("# of RHBAs of CVSS Score >= %.1f") % score,
                  len(data["errata"]["rhba"]["list_higher_cvss_score"])],
                 [_("# of Update RPMs by the above RHBAs at minimum"),
                  len(data["errata"]["rhba"]["list_higher_cvss_updates"])]]

    rows += [[],
             [_("# of RHSAs"), len(data["errata"]["rhsa"]["list"])],
             [_("# of RHBAs"), len(data["errata"]["rhba"]["list"])],
             [_("# of RHEAs (Enhancement Errata)"),
              len(data["errata"]["rhea"]["list"])],
             [_("# of Update RPMs"), len(data["updates"]["list"])],
             [_("# of Installed RPMs"), len(data["installed"]["list"])],
             [],
             [_("Origin of Installed RPMs")],
             [_("# of Rebuilt RPMs"), len(data["installed"]["list_rebuilt"])],
             [_("# of Replaced RPMs"),
              len(data["installed"]["list_replaced"])],
             [_("# of RPMs from other vendors (non Red Hat)"),
              len(data["installed"]["list_from_others"])]]

    headers = (_("Item"), _("Value"), _("Notes"))
    dataset = tablib.Dataset(headers=headers)
    dataset.title = _("Overview of analysis results")

    mcols = len(headers)
    for row in rows:
        if row and len(row) == 1:  # Special case: separator
            dataset.append_separator(row[0])
        else:
            dataset.append(padding_row(row, mcols))

    return dataset


def dump_xls(dataset, filepath):
    """XLS dump function"""
    book = tablib.Databook(dataset)
    with open(filepath, 'wb') as out:
        out.write(book.xls)


def dump_results(workdir, rpms, errata, updates, score=0,
                 keywords=ERRATA_KEYWORDS, core_rpms=None, details=True,
                 rpmkeys=NEVRA_KEYS, vendor="redhat"):
    """
    :param workdir: Working dir to dump the result
    :param rpms: A list of installed RPMs
    :param errata: A list of applicable errata
    :param updates: A list of update RPMs
    :param score: CVSS base metrics score
    :param keywords: Keyword list to filter 'important' RHBAs
    :param core_rpms: Core RPMs to filter errata by them
    :param details: Dump details also if True
    """
    rpms_rebuilt = [p for p in rpms if p.get("rebuilt", False)]
    rpms_replaced = [p for p in rpms if p.get("replaced", False)]
    rpms_from_others = [p for p in rpms if p.get("origin", '') != vendor]
    rpms_by_vendor = [p for p in rpms if p.get("origin", '') == vendor and
                      not p.get("rebuilt", False) and
                      not p.get("replaced", False)]
    nps = len(rpms)
    nus = len(updates)

    data = dict(errata=analyze_errata(errata, score, keywords, core_rpms),
                installed=dict(list=rpms,
                               list_rebuilt=rpms_rebuilt,
                               list_replaced=rpms_replaced,
                               list_from_others=rpms_from_others,
                               list_by_vendor=rpms_by_vendor),
                updates=dict(list=updates,
                             rate=[(_("packages need updates"), nus),
                                   (_("packages not need updates"),
                                    nps - nus)]))

    fleure.utils.json_dump(data, os.path.join(workdir, "summary.json"))

    # TODO: Keep DRY principle.
    lrpmkeys = [_("name"), _("epoch"), _("version"), _("release"), _("arch")]

    rpmdkeys = list(rpmkeys) + ["summary", "vendor", "buildhost"]
    lrpmdkeys = lrpmkeys + [_("summary"), _("vendor"), _("buildhost")]

    sekeys = ("advisory", "severity", "synopsis", "url", "update_names")
    lsekeys = (_("advisory"), _("severity"), _("synopsis"), _("url"),
               _("update_names"))
    bekeys = ("advisory", "keywords", "synopsis", "url", "update_names")
    lbekeys = (_("advisory"), _("keywords"), _("synopsis"), _("url"),
               _("update_names"))

    mds = [mk_overview_dataset(data, score, keywords, core_rpms),
           make_dataset((data["errata"]["rhsa"]["list_latest_critical"] +
                         data["errata"]["rhsa"]["list_latest_important"]),
                        _("Cri-Important RHSAs (latests)"), sekeys, lsekeys),
           make_dataset(sorted(data["errata"]["rhsa"]["list_critical"],
                               key=itemgetter("update_names")) +
                        sorted(data["errata"]["rhsa"]["list_important"],
                               key=itemgetter("update_names")),
                        _("Critical or Important RHSAs"), sekeys, lsekeys),
           make_dataset(data["errata"]["rhba"]["list_by_kwds_of_core_rpms"],
                        _("RHBAs (core rpms, keywords)"), bekeys, lbekeys),
           make_dataset(data["errata"]["rhba"]["list_by_kwds"],
                        _("RHBAs (keyword)"), bekeys, lbekeys),
           make_dataset(data["errata"]["rhba"]["list_latests_of_core_rpms"],
                        _("RHBAs (core rpms, latests)"), bekeys, lbekeys),
           make_dataset(data["errata"]["rhsa"]["list_critical_updates"],
                        _("Update RPMs by RHSAs (Critical)"), rpmkeys,
                        lrpmkeys),
           make_dataset(data["errata"]["rhsa"]["list_important_updates"],
                        _("Updates by RHSAs (Important)"), rpmkeys, lrpmkeys),
           make_dataset(data["errata"]["rhba"]["list_updates_by_kwds"],
                        _("Updates by RHBAs (Keyword)"), rpmkeys, lrpmkeys)]

    if score > 0:
        cvss_ds = [
            make_dataset(data["errata"]["rhsa"]["list_higher_cvss_score"],
                         _("RHSAs (CVSS score >= %.1f)") % score,
                         ("advisory", "severity", "synopsis",
                          "cves", "cvsses_s", "url"),
                         (_("advisory"), _("severity"), _("synopsis"),
                          _("cves"), _("cvsses_s"), _("url"))),
            make_dataset(data["errata"]["rhsa"]["list_higher_cvss_score"],
                         _("RHBAs (CVSS score >= %.1f)") % score,
                         ("advisory", "synopsis", "cves", "cvsses_s", "url"),
                         (_("advisory"), _("synopsis"), _("cves"),
                          _("cvsses_s"), _("url")))]
        mds.extend(cvss_ds)

    if data["installed"]["list_rebuilt"]:
        mds.append(make_dataset(data["installed"]["list_rebuilt"],
                                _("Rebuilt RPMs"), rpmdkeys, lrpmdkeys))

    if data["installed"]["list_replaced"]:
        mds.append(make_dataset(data["installed"]["list_replaced"],
                                _("Replaced RPMs"), rpmdkeys, lrpmdkeys))

    if data["installed"]["list_from_others"]:
        mds.append(make_dataset(data["installed"]["list_from_others"],
                                _("RPMs from other vendors"), rpmdkeys,
                                lrpmdkeys))

    dump_xls(mds, os.path.join(workdir, "errata_summary.xls"))

    if details:
        dds = [make_dataset(errata, _("Errata Details"),
                            ("advisory", "type", "severity", "synopsis",
                             "description", "issue_date", "update_date", "url",
                             "cves", "bzs", "update_names"),
                            (_("advisory"), _("type"), _("severity"),
                             _("synopsis"), _("description"), _("issue_date"),
                             _("update_date"), _("url"), _("cves"),
                             _("bzs"), _("update_names"))),
               make_dataset(updates, _("Update RPMs"), rpmkeys, lrpmkeys),
               make_dataset(rpms, _("Installed RPMs"), rpmdkeys, lrpmdkeys)]

        dump_xls(dds, os.path.join(workdir, "errata_details.xls"))


def get_backend(backend, backends=None):
    """Get backend.
    """
    if backends is None:
        backends = BACKENDS

    return backends.get(backend, DEFAULT_BACKEND)


@profile
def prepare(root, workdir=None, repos=None, did=None, cachedir=None,
            backend="dnf", nevra_keys=NEVRA_KEYS):
    """
    :param root: Root dir of RPM db, ex. / (/var/lib/rpm)
    :param workdir: Working dir to save results
    :param repos: List of yum repos to get updateinfo data (errata and updtes)
    :param did: Identity of the data (ex. hostname) or empty str
    :param cachedir: A dir to save metadata cache of yum repos
    :param backend: Name of backend to resolve updates and errata

    :return: A bunch.Bunch object of (Base, workdir, installed_rpms_list)
    """
    root = os.path.abspath(root)  # Ensure it's absolute path.

    if repos is None:
        repos = fleure.utils.guess_rhel_repos(root)
        LOG.info(_("%s: Use guessed repos %s"), did, ', '.join(repos))

    if workdir is None:
        LOG.info(_("%s: Set workdir to root %s"), did, root)
        workdir = root
    else:
        if not os.path.exists(workdir):
            LOG.debug(_("%s: Creating working dir %s"), did, workdir)
            os.makedirs(workdir)

    host = bunch.bunchify(dict(id=did, root=root, workdir=workdir,
                               repos=repos, available=False,
                               cachedir=cachedir))

    if not fleure.utils.check_rpmdb_root(root):
        LOG.warn(_("%s: RPM DB not available and don't analyze %s"),
                 host.id, root)
        return host

    base = get_backend(backend)(host.root, host.repos, workdir=host.workdir,
                                cachedir=cachedir)
    base.prepare()
    LOG.debug(_("%s: Initialized backend %s"), host.id, base.name)
    host.base = base

    LOG.debug(_("%s: Dump Installed RPMs list loaded from %s"),
              host.id, host.root)
    host.installed = sorted(host.base.list_installed(),
                            key=itemgetter(*nevra_keys))
    LOG.info(_("%s: Found %d (rebuilt=%d, replaced=%d) Installed RPMs"),
             host.id, len(host.installed),
             len([p for p in host.installed if p.get("rebuilt", False)]),
             len([p for p in host.installed if p.get("replaced", False)]))

    fleure.utils.json_dump(dict(data=host.installed, ),
                           fleure.globals.rpm_list_path(host.workdir))
    if base.ready():
        host.available = True

    return host


@profile
def analyze(host, score=0, keywords=ERRATA_KEYWORDS, core_rpms=None,
            period=None, refdir=None, nevra_keys=NEVRA_KEYS):
    """
    :param host: host object function :function:`prepare` returns
    :param score: CVSS base metrics score
    :param keywords: Keyword list to filter 'important' RHBAs
    :param core_rpms: Core RPMs to filter errata by them
    :param period: Period of errata in format of YYYY[-MM[-DD]],
        ex. ("2014-10-01", "2014-11-01")
    :param refdir: A dir holding reference data previously generated to
        compute delta (updates since that data)
    """
    base = host.base
    workdir = host.workdir

    timestamp = datetime.datetime.now().strftime("%F %T")
    metadata = bunch.bunchify(dict(id=host.id, root=host.root,
                                   workdir=host.workdir, repos=host.repos,
                                   backend=host.base.name, score=score,
                                   keywords=keywords,
                                   installed=len(host.installed),
                                   hosts=[host.id, ],
                                   generated=timestamp))
    LOG.debug(_("%s: Dump metadata for %s"), host.id, host.root)
    fleure.utils.json_dump(metadata.toDict(),
                           os.path.join(workdir, "metadata.json"))

    ups = fleure.utils.uniq(base.list_updates(), key=itemgetter(*nevra_keys))
    ers = base.list_errata()
    ers = fleure.utils.uniq(fleure.datasets.errata_complement_g(ers, ups,
                                                                score),
                            key=itemgetter("id"), reverse=True)
    LOG.info(_("%s: %d Errata, %d Update RPMs"), host.id, len(ers), len(ups))

    LOG.debug(_("%s: Dump Errata and Update RPMs list..."), host.id)
    fleure.utils.json_dump(dict(data=ers, ),
                           fleure.globals.errata_list_path(workdir))
    fleure.utils.json_dump(dict(data=ups, ),
                           fleure.globals.updates_list_path(workdir))

    host.errata = ers
    host.updates = ups
    ips = host.installed

    LOG.info(_("%s: Analyze and dump results of errata data in %s"),
             host.id, workdir)
    dump_results(workdir, ips, ers, ups, score, keywords, core_rpms)

    if period is not None:
        (start_date, end_date) = fleure.datasets.period_to_dates(*period)
        LOG.info(_("%s: Analyze errata in period: %s ~ %s"),
                 host.id, start_date, end_date)
        pes = [e for e in ers
               if fleure.datasets.errata_in_period(e, start_date, end_date)]

        pdir = os.path.join(workdir, "%s_%s" % (start_date, end_date))
        if not os.path.exists(pdir):
            LOG.debug(_("%s: Creating period working dir %s"), host.id, pdir)
            os.makedirs(pdir)

        dump_results(pdir, ips, pes, ups, score, keywords, core_rpms, False)

    if refdir:
        LOG.debug(_("%s [delta]: Analyze delta errata data by refering %s"),
                  host.id, refdir)
        (ers, ups) = fleure.datasets.compute_delta(refdir, ers, ups)
        LOG.info(_("%s [delta]: %d Errata, %d Update RPMs"), host.id,
                 len(ers), len(ups))

        deltadir = os.path.join(workdir, "delta")
        if not os.path.exists(deltadir):
            LOG.debug(_("%s: Creating delta working dir %s"),
                      host.id, deltadir)
            os.makedirs(deltadir)

        fleure.utils.json_dump(dict(data=ers, ),
                               fleure.globals.errata_list_path(deltadir))
        fleure.utils.json_dump(dict(data=ups, ),
                               fleure.globals.updates_list_path(deltadir))

        LOG.info(_("%s: Analyze and dump results of delta errata in %s"),
                 host.id, deltadir)
        dump_results(workdir, ips, ers, ups, score, keywords, core_rpms)


def set_loglevel(verbosity=0, backend=False):
    """
    :param verbosity: Verbosity level = 0 | 1 | 2
    :param backend: Set backend's log level also if True
    """
    if verbosity in (0, 1, 2):
        llvl = [logging.WARN, logging.INFO, logging.DEBUG][verbosity]
    else:
        LOG.warn("Wrong verbosity: %d", verbosity)
        llvl = logging.WARN

    LOG.setLevel(llvl)

    if not backend:
        llvl = logging.WARN

    fleure.yumbase.LOG.setLevel(llvl)
    fleure.dnfbase.LOG.setLevel(llvl)


def main(root, workdir=None, repos=None, did=None, score=0,
         keywords=ERRATA_KEYWORDS, rpms=CORE_RPMS, period=None,
         cachedir=None, refdir=None, verbosity=0, backend="dnf"):
    """
    :param root: Root dir of RPM db, ex. / (/var/lib/rpm)
    :param workdir: Working dir to save results
    :param repos: List of yum repos to get updateinfo data (errata and updtes)
    :param did: Identity of the data (ex. hostname) or empty str
    :param score: CVSS base metrics score
    :param keywords: Keyword list to filter 'important' RHBAs
    :param rpms: Core RPMs to filter errata by them
    :param period: Period of errata in format of YYYY[-MM[-DD]],
        ex. ("2014-10-01", "2014-11-01")
    :param cachedir: A dir to save metadata cache of yum repos
    :param refdir: A dir holding reference data previously generated to
        compute delta (updates since that data)
    :param verbosity: Verbosity level: 0 (default), 1 (verbose), 2 (debug)
    :param backend: Backend module to use to get updates and errata
    """
    set_loglevel(verbosity)
    host = prepare(root, workdir, repos, did, cachedir, backend)

    if host.available:
        LOG.info("Anaylize the host: %s", host.id)
        analyze(host, score, keywords, rpms, period, refdir)

# vim:sw=4:ts=4:et:
