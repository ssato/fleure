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

import datetime
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

from fleure.globals import _
from fleure.datasets import make_dataset


if os.environ.get("FLEURE_MEMORY_DEBUG", False):
    try:
        from memory_profiler import profile
    except ImportError:
        from fleure.decorators import noop as profile
else:
    from fleure.decorators import noop as profile


LOG = logging.getLogger("fleure")


def dump_xls(dataset, filepath):
    """XLS dump function"""
    book = tablib.Databook(dataset)
    with open(filepath, 'wb') as out:
        out.write(book.xls)


def dump_results(host, rpms, errata, updates, dumpdir=None):
    """
    Dump package level static analysis results.

    :param host: host object function :function:`prepare` returns
    :param rpms: A list of installed RPMs
    :param errata: A list of applicable errata
    :param updates: A list of update RPMs
    :param dumpdir: Dir to save results
    """
    dargs = (host.cvss_min_score, host.errata_keywords, host.core_rpms)
    rpmkeys = host.rpmkeys

    rpms_rebuilt = [p for p in rpms if p.get("rebuilt", False)]
    rpms_replaced = [p for p in rpms if p.get("replaced", False)]
    rpms_from_others = [p for p in rpms
                        if p.get("origin", '') != host.rpm_vendor]
    rpms_by_vendor = [p for p in rpms
                      if p.get("origin", '') == host.rpm_vendor and
                      not p.get("rebuilt", False) and
                      not p.get("replaced", False)]
    nps = len(rpms)
    nus = len(updates)

    ers = fleure.analysis.analyze_errata(errata, *dargs)
    data = dict(errata=ers,
                installed=dict(list=rpms,
                               list_rebuilt=rpms_rebuilt,
                               list_replaced=rpms_replaced,
                               list_from_others=rpms_from_others,
                               list_by_vendor=rpms_by_vendor),
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

    mds = [fleure.analysis.mk_overview_dataset(data, *dargs),
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

    dump_xls(mds, os.path.join(host.workdir if dumpdir is None else dumpdir,
                               "errata_summary.xls"))

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

        dump_xls(dds,
                 os.path.join(host.workdir if dumpdir is None else dumpdir,
                              "errata_details.xls"))


@profile
def prepare(root_or_arc_path, hid=None, **kwargs):
    """
    :param root_or_arc_path:
        Path to the root dir of RPM DB files or Archive (tar.xz, tar.gz, zip,
        etc.) of RPM DB files. Path might be a relative path from current dir.
    :param hid:
        Some identification info of the target host where original RPM DB data
        was collected.
    :param kwargs:
        Extra keyword arguments other than `root_or_arc_path` passed to make an
        instance of :class:`fleure.config.Config`

    :return: An instance of :class:`fleure.config.Host`
    """
    host = fleure.config.Host(root_or_arc_path, hid=hid, **kwargs)
    host.configure()  # Extract archive, setup root and repos, etc.

    if not host.has_valid_root():
        LOG.error(_("Root dir is not ready. Error was: %s"), host.error)
        return host

    LOG.info(_("%s: Start to initialize: root=%s, backend=%s"),
             host.hid, host.root, kwargs.get("backend", "maybe yum"))
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

    host.save(dict(data=host.installed, ), "packages")

    if base.ready():
        host.available = True

    return host


@profile
def analyze(host):
    """
    :param host: host object function :function:`prepare` returns
    """
    metadata = dict(id=host.hid, root=host.root, workdir=host.workdir,
                    repos=host.repos, backend=host.base.name,
                    score=host.cvss_min_score, keywords=host.errata_keywords,
                    installed=len(host.installed), hosts=[host.hid, ],
                    generated=datetime.datetime.now().strftime("%F %T"))
    host.save(metadata, "metadata")

    ups = fleure.utils.uniq(host.base.list_updates(),
                            key=itemgetter(*host.rpmkeys))
    ers = host.base.list_errata()
    ers = fleure.datasets.complement_errata(ers, ups, host.cvss_min_score)
    host.save(dict(data=ers, ), "errata")
    host.save(dict(data=ups, ), "updates")
    LOG.info(_("%s: Found %d errata and %d updates, saved the lists"),
             host.hid, len(ers), len(ups))

    host.errata = ers
    host.updates = ups
    ips = host.installed

    LOG.info(_("%s: Analyzing errata and packages ..."), host.hid)
    dump_results(host, ips, ers, ups)
    LOG.info(_("%s: Saved analysis results in %s"), host.workdir)

    if host.period:
        (start_date, end_date) = fleure.datasets.period_to_dates(*host.period)
        LOG.info(_("%s: Analyzing errata and packages [%s ~ %s]"),
                 host.hid, start_date, end_date)
        pes = [e for e in ers
               if fleure.datasets.errata_in_period(e, start_date, end_date)]

        pdir = os.path.join(host.workdir, "%s_%s" % (start_date, end_date))
        if not os.path.exists(pdir):
            LOG.debug(_("%s: Creating period working dir %s"), host.hid, pdir)
            os.makedirs(pdir)

        dump_results(host, ips, pes, ups, pdir)
        LOG.info(_("%s: Saved analysis results [%s ~ %s] in %s"),
                 host.hid, start_date, end_date, pdir)

    if host.refdir:
        LOG.debug(_("%s [delta]: Analyze delta errata data by refering %s"),
                  host.hid, host.refdir)
        (ers, ups) = fleure.datasets.compute_delta(host.refdir, ers, ups)
        host.save(dict(data=ers, ), "errata", subdir="delta")
        host.save(dict(data=ups, ), "updates", subdir="delta")
        LOG.info(_("%s [delta]: Found %d errata and %d updates, save the "
                   "lists"), host.hid, len(ers), len(ups))

        LOG.info(_("%s: Analyzing delta errata and packages ..."), host.hid)
        dump_results(host, ips, ers, ups)
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

    LOG.warn("Reprot files (%s) do not exist. Do no make a report archives",
             ", ".join(filenames))
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
        instance of :class:`fleure.config.Config`

    :return: Workdir where results exist or path to archive of results
    """
    set_loglevel(verbosity)
    host = prepare(root_or_arc_path, hid, **kwargs)

    if host.available:
        LOG.info(_("Anaylize the host: %s"), host.hid)
        analyze(host)

    if kwargs.get("archive", False):
        outname = "report-%s-%s.zip" % (host.hid, fleure.globals.TODAY)
        return archive_report(host.workdir, outname)
    else:
        return host.workdir

# vim:sw=4:ts=4:et:
