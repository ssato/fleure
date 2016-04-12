#
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2016 Red Hat, Inc.
# License: AGPLv3+
#
# pylint: disable=too-many-arguments,too-many-locals,no-member
"""Fleure's main module
"""
from __future__ import absolute_import
from operator import itemgetter

import datetime
import functools
import logging
import os.path
import os
import tablib

import fleure.analysis
import fleure.archive
import fleure.config
import fleure.depgraph
import fleure.globals
import fleure.datasets
import fleure.utils
import fleure.yumbase

from fleure.globals import _, profile
from fleure.datasets import make_dataset


LOG = logging.getLogger("fleure")


def dump_xls(dataset, filepath):
    """XLS dump function"""
    book = tablib.Databook(dataset)
    with open(filepath, 'wb') as out:
        out.write(book.xls)


def analyze_and_dump_results(host, rpms, errata, updates, dumpdir=None):
    """
    Analyze and dump package level static analysis results.

    :param host: host object function :function:`prepare` returns
    :param rpms: A list of installed RPMs
    :param errata: A list of applicable errata
    :param updates: A list of update RPMs
    :param dumpdir: Dir to save results
    """
    if dumpdir is None:
        dumpdir = host.workdir

    dargs = dict(score=host.cvss_min_score, keywords=host.errata_keywords,
                 pkeywords=host.errata_pkeywords, core_rpms=host.core_rpms)
    rpmkeys = host.rpmkeys

    installed = dict(list=rpms, list_rebuilt=[], list_replaced=[],
                     list_from_others=[])
    for pkg in rpms:
        for key in ("rebuilt", "replaced"):
            if pkg.get(key, False):
                installed["list_" + key].append(pkg)

        if pkg.get("origin", None) != host.rpm_vendor:
            installed["list_from_others"].append(pkg)

    nps = len(rpms)
    nus = len(updates)

    ers = fleure.analysis.analyze_errata(errata, **dargs)
    data = dict(errata=ers,
                installed=installed,
                updates=dict(list=updates,
                             rate=[(_("packages need updates"), nus),
                                   (_("packages not need updates"),
                                    nps - nus)]))

    host.save(data, "summary", dumpdir)
    fleure.depgraph.dump_depgraph(host.root, ers, host.workdir,
                                  tpaths=host.tpaths)
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

    mds = [fleure.analysis.mk_overview_dataset(data, **dargs),
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

    score = host.cvss_min_score
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

    for key, title in (("list_rebuilt", _("Rebuilt RPMs")),
                       ("list_replaced", _("Replaced RPMs")),
                       ("list_from_others", _("RPMs from other vendors"))):
        if data["installed"][key]:
            mds.append(make_dataset(data["installed"][key], title, rpmdkeys,
                                    lrpmdkeys))

    dump_xls(mds, os.path.join(dumpdir, "errata_summary.xls"))

    if host.details:
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

        dump_xls(dds, os.path.join(dumpdir, "errata_details.xls"))


@profile
def configure(root_or_arc_path, hid=None, **kwargs):
    """
    :param root_or_arc_path:
        Path to the root dir of RPM DB files or Archive (tar.xz, tar.gz, zip,
        etc.) of RPM DB files. Path might be a relative path from current dir.
    :param hid:
        Some identification info of the target host where original RPM DB data
        was collected.
    :param kwargs:
        Extra keyword arguments other than `root_or_arc_path` passed to make an
        instance of :class:`fleure.config.Host`

    :return: An instance of :class:`fleure.config.Host`
    """
    host = fleure.config.Host(root_or_arc_path, hid=hid, **kwargs)
    host.configure()  # Extract archive, setup root and repos, etc.

    if not host.has_valid_root():
        LOG.error(_("Root dir is not ready. Error was: %s"), host.error)
        return None

    return host


@profile
def prepare(host):
    """
    :param host: Configured host, an instance of :class:`fleure.config.Host`
    :return: An instance of :class:`fleure.config.Host`
    """
    if not host.has_valid_root():
        LOG.error(_("Root dir is not ready. Error was: %s"), host.error)
        return

    LOG.info(_("%s: Start to initialize: root=%s, backend=%s"),
             host.hid, host.root, host.backend)
    base = host.init_base()
    base.prepare()
    LOG.info(_("%s[%s]: Initialization completed, start to analyze ..."),
             host.hid, base.name)

    host.installed = sorted(base.list_installed(),
                            key=itemgetter(*host.rpmkeys))
    LOG.info(_("%s: Found %d (rebuilt=%d, replaced=%d) installed RPMs"),
             host.hid, len(host.installed),
             len([p for p in host.installed if p.get("rebuilt", False)]),
             len([p for p in host.installed if p.get("replaced", False)]))

    host.save(host.installed, "packages")

    if base.ready():
        host.available = True


@profile
def analyze(host):
    """
    :param host: host object function :function:`prepare` returns
    """
    metadata = dict(id=host.hid, root=host.root, workdir=host.workdir,
                    repos=host.repos, backend=host.base.name,
                    score=host.cvss_min_score, keywords=host.errata_keywords,
                    installed=len(host.installed), hosts=[host.hid, ],
                    generated=datetime.datetime.now().strftime("%F %T"),
                    period=host.period, refdir=host.refdir)
    host.save(metadata, "metadata")

    LOG.info(_("%s: Analyzing errata and packages ..."), host.hid)
    host.updates = ups = host.base.list_updates()

    p2na = itemgetter("name", "arch")
    calls = (functools.partial(fleure.datasets.complement_an_errata,
                               updates=set(p2na(u) for u in ups),
                               to_update_fn=p2na,
                               score=host.cvss_min_score))
    host.errata = ers = host.base.list_errata(calls)

    host.save(ers, "errata")
    host.save(ups, "updates")
    LOG.info(_("%s: Found %d errata and %d updates, saved the lists"),
             host.hid, len(ers), len(ups))

    ips = host.installed
    analyze_and_dump_results(host, ips, ers, ups)
    LOG.info(_("%s: Saved analysis results in %s"), host.workdir)

    if host.period:
        (start, end) = host.period
        LOG.info(_("%s: Analyzing errata and packages [%s ~ %s]"),
                 host.hid, start, end)
        pdir = os.path.join(host.workdir, "%s_%s" % (start, end))
        if not os.path.exists(pdir):
            LOG.debug(_("%s: Creating period working dir %s"), host.hid, pdir)
            os.makedirs(pdir)

        pes = [e for e in ers
               if fleure.dates.in_period(e["issue_date"], start, end)]
        analyze_and_dump_results(host, ips, pes, ups, pdir)
        LOG.info(_("%s [%s ~ %s]: Found %d errata and saved"),
                 host.hid, start, end, len(pes))

    if host.refdir:
        LOG.debug(_("%s [delta]: Analyze delta errata data by refering %s"),
                  host.hid, host.refdir)
        (ers, ups) = fleure.datasets.compute_delta(host.refdir, ers, ups)
        host.save(ers, "errata", subdir="delta")
        host.save(ups, "updates", subdir="delta")
        LOG.info(_("%s [delta]: Found %d errata and %d updates, save the "
                   "lists"), host.hid, len(ers), len(ups))

        LOG.info(_("%s: Analyzing delta errata and packages ..."), host.hid)
        analyze_and_dump_results(host, ips, ers, ups)
        LOG.info(_("%s: Saved delta analysis results in %s"), host.workdir)


def set_loglevel(verbosity=0, backend=False):
    """
    :param verbosity: Verbosity level = 0 | 1 | 2
    :param backend: Set backend's log level also if True
    """
    if verbosity in (0, 1, 2):
        llvl = [logging.WARN, logging.INFO, logging.DEBUG][verbosity]
    else:
        LOG.warn(_("Wrong verbosity: %d"), verbosity)
        llvl = logging.WARN

    LOG.setLevel(llvl)

    if not backend:
        llvl = logging.WARN

    fleure.yumbase.LOG.setLevel(llvl)
    fleure.dnfbase.LOG.setLevel(llvl)


def archive_report(reportdir, output):
    """Archive analysis report.

    :reportdir: Dir where generated report files exist
    :output: Output filename
    :return:
        Absolute path of archive file made or None might indicates some
        failures before/during making archive.
    """
    filenames = fleure.globals.REPORT_FILES
    if all(os.path.exists(os.path.join(reportdir, fn)) for fn in filenames):
        arcpath = fleure.archive.archive_report(reportdir, output)
        LOG.info(_("Archived results: %s"), arcpath)
        return arcpath

    LOG.warn(_("Reprot files (%s) do not exist. Do no make a report "
               "archives"), ", ".join(filenames))
    return None


def main(root_or_arc_path, hid=None, verbosity=0, **kwargs):
    """
    :param root_or_arc_path:
        Path to the root dir of RPM DB files or Archive (tar.xz, tar.gz, zip,
        etc.) of RPM DB files. Path might be a relative path from current dir.
    :param hid:
        Some identification info of the target host where original RPM DB data
        was collected.
    :param verbosity: Verbosity level: 0 (default), 1 (verbose), 2 (debug)
    :param kwargs:
        Extra keyword arguments other than `root_or_arc_path` passed to make an
        instance of :class:`fleure.config.Host`

    :return: Workdir where results exist or path to archive of results
    """
    set_loglevel(verbosity)
    host = configure(root_or_arc_path, hid, **kwargs)
    if host is None:
        LOG.error(_("Failed to configure the host: root=%s"),
                  root_or_arc_path)
        return None

    prepare(host)

    if host.available:
        LOG.info(_("Anaylize the host: %s"), host.hid)
        analyze(host)

    if kwargs.get("archive", False):
        outname = "report-%s-%s.zip" % (host.hid, fleure.globals.TODAY)
        return archive_report(host.workdir, outname)
    else:
        return host.workdir

# vim:sw=4:ts=4:et:
