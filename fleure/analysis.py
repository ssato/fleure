#
# -*- coding: utf-8 -*-
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: AGPLv3+
#
# pylint: disable=too-many-locals,no-member
"""Fleure's main module
"""
from __future__ import absolute_import
from operator import itemgetter

import itertools
import logging
import nltk
import tablib

import fleure.globals
import fleure.datasets
import fleure.utils

from fleure.globals import _
from fleure.datasets import (
    list_updates_from_errata, list_latest_errata_by_updates,
)


LOG = logging.getLogger("fleure")


def errata_of_keywords_g(ers, keywords=fleure.globals.ERRATA_KEYWORDS,
                         strict=False):
    """
    :param ers: A list of errata
    :param keywords: Keyword list to filter 'important' RHBAs
    :strict: Strict matching of keywords with using NLTK stemmer
    :return:
        A generator to yield errata of which description contains any of
        given keywords

    >>> ert0 = dict(advisory="RHSA-2015:XXX1",  # +NORMALIZE_WHITESPACE
    ...             description="system hangs, or crash...")
    >>> ert1 = dict(advisory="RHEA-2015:XXX2",  # +NORMALIZE_WHITESPACE
    ...             description="some enhancement and changes")
    >>> ers = list(errata_of_keywords_g([ert0, ert1], ("hang", "crash")))
    >>> ert0 in ers
    True
    >>> ers[0]["keywords"]  # 'hangs' does not match with 'hang'.
    ['crash']
    >>> ert1 in ers
    False
    >>> ers = list(errata_of_keywords_g([ert0], ("hang", ), True))
    >>> ert0 in ers
    True
    >>> ers[0]["keywords"]  # 'hangs' matches after stemming.
    ['hang']
    """
    if strict:
        _stemmer = nltk.PorterStemmer()
        _stem = _stemmer.stem

    for ert in ers:
        tokens = set(nltk.wordpunct_tokenize(ert["description"]))
        if strict:
            tokens = set(_stem(w) for w in tokens)

        mks = [k for k in keywords if k in tokens]
        if mks:
            ert["keywords"] = mks
            yield ert


def errata_of_rpms_g(ers, rpms=fleure.globals.CORE_RPMS):
    """
    :param ers: A list of errata
    :param rpms: A list of RPM names to select relevant errata
    :return: A generator to yield errata relevant to any of given RPM names

    >>> ert0 = dict(advisory="RHSA-2015:XXX1",  # +NORMALIZE_WHITESPACE
    ...             update_names=["kernel", "tzdata"])
    >>> ert1 = dict(advisory="RHSA-2015:XXX2",  # +NORMALIZE_WHITESPACE
    ...             update_names=["glibc", "tzdata"])
    >>> ers = errata_of_rpms_g([ert0, ert1], ("kernel", ))
    >>> ert0 in ers
    True
    >>> ert1 in ers
    False
    """
    for ert in ers:
        if any(n in ert["update_names"] for n in rpms):
            yield ert


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


def analyze_errata(ers, score=fleure.globals.DEFAULT_CVSS_SCORE,
                   keywords=fleure.globals.ERRATA_KEYWORDS,
                   core_rpms=fleure.globals.CORE_RPMS):
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
    rhba_by_kwds = sorted(errata_of_keywords_g(rhba, keywords),
                          key=kfn, reverse=True)
    rhba_of_core_rpms_by_kwds = \
        sorted(errata_of_rpms_g(rhba_by_kwds, core_rpms),
               key=kfn, reverse=True)
    rhba_of_rpms = sorted(errata_of_rpms_g(rhba, core_rpms,
                          key=itemgetter("update_names"), reverse=True)
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
                          list_by_kwds_of_core_rpms=rhba_of_core_rpms_by_kwds,
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


def mk_overview_dataset(data, score=fleure.globals.DEFAULT_CVSS_SCORE,
                        keywords=fleure.globals.ERRATA_KEYWORDS,
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

# vim:sw=4:ts=4:et:
