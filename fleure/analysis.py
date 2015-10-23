#
# -*- coding: utf-8 -*-
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: AGPLv3+
#
# pylint: disable=no-member
"""Fleure's main module
"""
from __future__ import absolute_import
from operator import itemgetter

import itertools
import logging
import nltk
import tablib

import fleure.globals
import fleure.utils

from fleure.globals import _


LOG = logging.getLogger("fleure")


def _sgroupby(items, kfn, kfn2=None):
    """
    :param items: Iterable object, e.g. a list, a tuple, etc.
    :param kfn: Key function to sort `items` and group it
    :param kfn2: Key function to sort each group in result

    :return: A generator to yield items in `items` grouped by `kf`

    >>> items = [(1, 2, 10), (3, 4, 2), (3, 2, 1), (1, 10, 5)]
    >>> list(_sgroupby(items, itemgetter(0)))
    [[(1, 2, 10), (1, 10, 5)], [(3, 4, 2), (3, 2, 1)]]
    >>> list(_sgroupby(items, itemgetter(0), itemgetter(2)))
    [[(1, 10, 5), (1, 2, 10)], [(3, 2, 1), (3, 4, 2)]]
    """
    return (list(g) if kfn2 is None else sorted(g, key=kfn2) for _k, g
            in itertools.groupby(sorted(items, key=kfn), kfn))


def list_latest_errata_by_updates(ers):
    """
    :param ers: A list of errata dict
    :return: A list of items in `ers` grouped by update names
    """
    ung = lambda e: sorted(set(u["name"] for u in e.get("updates", [])))
    return [xs[-1] for xs in _sgroupby(ers, ung, itemgetter("issue_date"))]


def list_updates_from_errata(ers):
    """
    :param ers: A list of errata dict
    """
    ups = sorted(fleure.utils.uconcat(e.get("updates", []) for e in ers),
                 key=itemgetter("name"))
    return [sorted(g, cmp=fleure.utils.pcmp, reverse=True)[0] for g
            in _sgroupby(ups, itemgetter("name"))]


def errata_of_keywords_g(ers, keywords=fleure.globals.ERRATA_KEYWORDS,
                         strict=False):
    """
    :param ers: A list of errata
    :param keywords: Keyword list to filter 'important' RHBAs
    :strict: Strict matching of keywords with using NLTK stemmer
    :return:
        A generator to yield errata of which description contains any of
        given keywords

    >>> ert0 = dict(advisory="RHSA-2015:XXX1",
    ...             description="system hangs, or crash...")
    >>> ert1 = dict(advisory="RHEA-2015:XXX2",
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

    >>> ert0 = dict(advisory="RHSA-2015:XXX1",
    ...             update_names=["kernel", "tzdata"])
    >>> ert1 = dict(advisory="RHSA-2015:XXX2",
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


def list_update_errata_pairs(ers):
    """
    :param ers: A list of errata dict
    :return: A list of (update_name, [errata_advisory])

    >>> ers = [dict(advisory="RHSA-2015:XXX1",
    ...             update_names=["kernel", "tzdata"]),
    ...        dict(advisory="RHSA-2014:XXX2",
    ...             update_names=["glibc", "tzdata"])
    ...        ]
    >>> list_update_errata_pairs(ers) == [
    ...     ('glibc', ['RHSA-2014:XXX2']),
    ...     ('kernel', ['RHSA-2015:XXX1']),
    ...     ('tzdata', ['RHSA-2015:XXX1', 'RHSA-2014:XXX2'])
    ... ]
    True
    """
    ues = fleure.utils.uconcat([(u, e["advisory"]) for u in e["update_names"]]
                               for e in ers)
    return [(u, sorted((t[1] for t in g), reverse=True)) for u, g
            in itertools.groupby(ues, itemgetter(0))]


def list_updates_by_num_of_errata(uess):
    """
    List number of specific type of errata for each package names.

    :param uess: A list of (update, [errata_advisory]) pairs
    :return: [(package_name :: str, num_of_relevant_errata :: Int)]

    >>> ers = [{'advisory': u'RHSA-2015:1623',
    ...         'update_names': ['kernel-headers', 'kernel']},
    ...        {'advisory': 'RHSA-2015:1513',
    ...         'update_names': ['bind-utils']},
    ...        {'advisory': 'RHSA-2015:1081',
    ...         'update_names': ['kernel-headers', 'kernel']}
    ...        ]
    >>> list_updates_by_num_of_errata(list_update_errata_pairs(ers))
    [('kernel', 2), ('kernel-headers', 2), ('bind-utils', 1)]
    >>>
    """
    return sorted(((u, len(es)) for u, es in uess), key=itemgetter(1),
                  reverse=True)


def analyze_rhsa(rhsa):
    """
    Compute and return statistics of RHSAs from some view points.

    :param rhsa: A list of security errata (RHSA) dicts
    :return: RHSA analized data and metrics
    """
    cri_rhsa = [e for e in rhsa if e["severity"] == "Critical"]
    imp_rhsa = [e for e in rhsa if e["severity"] == "Important"]

    rhsa_rate_by_sev = [("Critical", len(cri_rhsa)),
                        ("Important", len(imp_rhsa)),
                        ("Moderate",
                         len([e for e in rhsa
                              if e["severity"] == "Moderate"])),
                        ("Low",
                         len([e for e in rhsa
                              if e["severity"] == "Low"]))]

    rhsa_ues = list_update_errata_pairs(rhsa)
    _ups_by_nes = lambda es: \
        list_updates_by_num_of_errata(list_update_errata_pairs(es))

    return {'list': rhsa,
            'list_critical': cri_rhsa,
            'list_important': imp_rhsa,
            'list_latest_critical': list_latest_errata_by_updates(cri_rhsa),
            'list_latest_important': list_latest_errata_by_updates(imp_rhsa),
            'list_critical_updates': list_updates_from_errata(cri_rhsa),
            'list_important_updates': list_updates_from_errata(imp_rhsa),
            'rate_by_sev': rhsa_rate_by_sev,
            'list_n_by_pnames': list_updates_by_num_of_errata(rhsa_ues),
            'list_n_cri_by_pnames': _ups_by_nes(cri_rhsa),
            'list_n_imp_by_pnames': _ups_by_nes(imp_rhsa),
            'list_by_packages': rhsa_ues}


def analyze_rhba(rhba, keywords=fleure.globals.ERRATA_KEYWORDS,
                 core_rpms=fleure.globals.CORE_RPMS):
    """
    Compute and return statistics of RHBAs from some view points.

    :param rhba: A list of bug errata (RHBA) dicts
    :param keywords: Keyword list to filter 'important' RHBAs
    :param core_rpms: Core RPMs to filter errata by them
    :return: RHSA analized data and metrics
    """
    kfn = lambda e: (len(e.get("keywords", [])), e["issue_date"],
                     e["update_names"])
    rhba_by_kwds = sorted(errata_of_keywords_g(rhba, keywords),
                          key=kfn, reverse=True)
    rhba_of_core_rpms_by_kwds = \
        sorted(errata_of_rpms_g(rhba_by_kwds, core_rpms),
               key=kfn, reverse=True)
    rhba_of_rpms = sorted(errata_of_rpms_g(rhba, core_rpms),
                          key=itemgetter("update_names"), reverse=True)
    latest_rhba_of_rpms = list_latest_errata_by_updates(rhba_of_rpms)
    rhba_ues = list_update_errata_pairs(rhba)

    return {'list': rhba,
            'list_by_kwds': rhba_by_kwds,
            'list_of_core_rpms': rhba_of_rpms,
            'list_latests_of_core_rpms': latest_rhba_of_rpms,
            'list_by_kwds_of_core_rpms': rhba_of_core_rpms_by_kwds,
            'list_updates_by_kwds': list_updates_from_errata(rhba_by_kwds),
            'list_n_by_pnames': list_updates_by_num_of_errata(rhba_ues),
            'list_by_packages': rhba_ues}


def _cve_socre_ge(cve, score=0, default=False):
    """
    :param cve: A dict contains CVE and CVSS info.
    :param score: Lowest score to select CVEs (float). It's Set to 4.0 (PCIDSS
        limit) by default:

        * NVD Vulnerability Severity Ratings: http://nvd.nist.gov/cvss.cfm
        * PCIDSS: https://www.pcisecuritystandards.org

    :param default: Default value if failed to get CVSS score to compare with
        given score

    :return: True if given CVE's socre is greater or equal to given score.
    """
    if "score" not in cve:
        LOG.warn(_("CVE %(cve)s lacks of CVSS base metrics and score"), cve)
        return default
    try:
        return float(cve["score"]) >= float(score)
    except (KeyError, ValueError):
        LOG.warn(_("Failed to compare CVE's score: %s, score=%.1f"),
                 str(cve), score)

    return default


def higher_score_cve_errata_g(ers, score=0):
    """
    :param ers: A list of errata
    :param score: CVSS base metrics score
    """
    for ert in ers:
        # NOTE: Skip older CVEs do not have CVSS base metrics and score.
        cves = [c for c in ert.get("cves", []) if "score" in c]
        if cves and any(_cve_socre_ge(cve, score) for cve in cves):
            cvsses_s = ", ".join("{cve} ({score}, {metrics})".format(**c)
                                 for c in cves)
            cves_s = ", ".join("{cve} ({url})".format(**c) for c in cves)
            ert["cvsses_s"] = cvsses_s
            ert["cves_s"] = cves_s

            yield ert


def analyze_errata(ers, score=fleure.globals.CVSS_MIN_SCORE,
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
    rhba = [e for e in ers if e["advisory"][2] == 'B']
    rhea = [e for e in ers if e["advisory"][2] == 'E']

    rhsa_data = analyze_rhsa(rhsa)
    rhba_data = analyze_rhba(rhba, keywords, core_rpms)

    if score > 0:
        rhba_by_score = list(higher_score_cve_errata_g(rhba, score))
        us_of_rhba_by_score = list_updates_from_errata(rhba_by_score)
    else:
        rhsa_by_score = []
        rhba_by_score = []
        us_of_rhsa_by_score = []
        us_of_rhba_by_score = []

    rhsa_data["list_higher_cvss_score"] = rhsa_by_score
    rhba_data["list_higher_cvss_score"] = rhba_by_score
    rhsa_data["list_higher_cvss_updates"] = us_of_rhsa_by_score
    rhba_data["list_higher_cvss_updates"] = us_of_rhba_by_score

    return dict(rhsa=rhsa_data,
                rhba=rhba_data,
                rhea=dict(list=rhea,
                          list_by_packages=list_update_errata_pairs(rhea)),
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


def mk_overview_dataset(data, score=fleure.globals.CVSS_MIN_SCORE,
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
