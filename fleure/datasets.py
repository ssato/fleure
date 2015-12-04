#
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: GPLv3+
#
"""Functions to make datasets.
"""
from __future__ import absolute_import

import collections
import logging
import operator
import os.path
import re
import tablib

import fleure.cveinfo
import fleure.dates
import fleure.utils

from fleure.globals import _


LOG = logging.getLogger(__name__)


def _cve_details(cve, cve_cvss_map=None):
    """
    :param cve: A dict represents CVE :: {id:, url:, ...}
    :param cve_cvss_map: A dict :: {cve: cve_and_cvss_data}

    :return: A dict represents CVE and its CVSS metrics
    """
    cveid = cve.get("id", cve.get("cve"))

    if cve_cvss_map is not None:
        dcve = cve_cvss_map.get(cveid)

    if dcve:
        cve.update(**dcve)
        return cve

    dcve = fleure.cveinfo.get_cvss_for_cve(cveid)

    if dcve is None:
        dcve = dict(cve=cveid, )
    else:
        dcve["nvd_url"] = dcve["url"]
        dcve["url"] = cve["url"]
        cve.update(**dcve)

    return cve


def _fmt_cve(cve):
    """CVE formatter"""
    if 'score' in cve:
        return '%(cve)s (score=%(score)s, metrics=%(metrics)s, url=%(url)s)'
    else:
        return '%(cve)s (CVSS=N/A)'


def _fmt_cvess(cves):
    """
    :param cves: List of CVE dict {cve, score, url, metrics} or str "cve".
    :return: List of CVE strings
    """
    try:
        cves = [_fmt_cve(c) % c for c in cves]
    except KeyError:
        pass
    except Exception as exc:
        raise RuntimeError("Wrong CVEs: %s, exc=%s" % (str(cves), str(exc)))

    return cves


def _fmt_bzs(bzs, summary=False):
    """
    :param cves: List of CVE dict {cve, score, url, metrics} or str "cve".
    :return: List of CVE strings
    """
    def fmt(bze):
        """bugzilla entry formatter"""
        return ("bz#%(id)s: "
                "%(summary)s " if summary and "summary" in bze else ""
                "(%(url)s)")
    try:
        bzs = [fmt(bz) % bz for bz in bzs]
    except KeyError:
        LOG.warn(_("BZ Key error: %s"), str(bzs))

    return bzs


def _make_cell_data(obj, key, default="N/A"):
    """Make up cell data.
    """
    if key == "cves":
        cves = obj.get("cves", [])
        try:
            return ", ".join(_fmt_cvess(cves)) if cves else default
        except Exception as exc:
            raise RuntimeError("Wrong CVEs: %s, exc=%s" % (str(cves),
                                                           str(exc)))
    elif key == "bzs":
        bzs = obj.get("bzs", [])
        return ", ".join(_fmt_bzs(bzs)) if bzs else default

    else:
        val = obj.get(key, default)
        return ", ".join(val) if isinstance(val, (list, tuple)) else val


def make_dataset(list_data, title=None, headers=None, lheaders=None):
    """
    :param list_data: List of data
    :param title: Dataset title to be used as worksheet's name
    :param headers: Dataset headers to be used as column headers, etc.
    :param lheaders: Localized version of `headers`

    TODO: Which is better?
        - tablib.Dataset(); [tablib.append(vals) for vals in list_data]
        - tablib.Dataset(*list_data, header=...)
    """
    # .. note::
    #    We need to check title as valid worksheet name, length <= 31, etc.
    #    See also xlwt.Utils.valid_sheet_name.
    if headers is not None:
        headers = headers if lheaders is None else lheaders
        tdata = [[_make_cell_data(val, h) for h in headers] for val in
                 list_data]
    else:
        tdata = [val.values() for val in list_data]

    return tablib.Dataset(*tdata, title=title[:30], headers=headers)


def _assert_if_not_exist(path, desc):
    """Tiny helper function to check if given path (dir or file) exists.
    """
    if not os.path.exists(path):
        raise IOError("Reference %s not found: %s" % (desc, path))


def compute_delta(refdir, ers, updates, nevra_keys=fleure.globals.RPM_KEYS):
    """
    :param refdir: Dir has reference data files: packages.json, errata.json
        and updates.json
    :param ers: A list of errata
    :param updates: A list of update packages
    """
    _assert_if_not_exist(refdir, "data dir")

    ref_es_file = os.path.join(refdir, "errata.json")
    ref_us_file = os.path.join(refdir, "updates.json")
    _assert_if_not_exist(ref_es_file, "errata file")
    _assert_if_not_exist(ref_us_file, "updates file")

    ref_es_data = fleure.utils.json_load(ref_es_file)
    ref_us_data = fleure.utils.json_load(ref_us_file)
    LOG.debug(_("Loaded reference errata and updates file"))

    ref_eadvs = set(e["advisory"] for e in ref_es_data["data"])
    ref_nevras = set((p[k] for k in nevra_keys) for p in ref_us_data["data"])

    return ([e for e in ers if e["advisory"] not in ref_eadvs],
            [u for u in updates
             if (u[k] for k in nevra_keys) not in ref_nevras])


def _errata_to_int(errata):
    """
    Generate an int represents an errata to used as comparison key.

    - RHSA > RHBA > RHEA (type)
    - RHSA: Critical > Important > Moderate > Low (severity)
    - RHBA-2013:0212 > RHBA-2012:1422 (year)
    - RHBA-2013:0212 > RHBA-2013:0210 (sequential id)
    - RHBA-2013:0212-1 > RHBA-2013:0212 (revision)

    :param errata: A dict represents an errata

    >>> _errata_to_int(dict(advisory="RHBA-2012:1422-1", ))
    202012142201
    >>> _errata_to_int(dict(advisory="RHSA-2014:0422", severity="Moderate"))
    342014042200
    """
    echars = dict(E=1, B=2, S=3)
    sevs = collections.defaultdict(int, dict(Low=2, Moderate=4, Important=6,
                                             Critical=8))
    reg = re.compile(r"^RH(?P<echar>(E|B|S))A-(?P<year>\d{4}):"
                     r"(?P<seq>\d{4,5})(?:-(?P<rev>\d+))?$")

    match = reg.match(errata["advisory"])
    if not match:
        LOG.warn("Not an errata advisory ? : %(advisory)s", errata)
        return 0

    dic = match.groupdict()
    rev = 0 if dic["rev"] is None else int(dic["rev"])
    return int("%d%d%s%s%02d" % (echars[dic["echar"]],
                                 sevs[errata.get("severity", 0)],
                                 dic["year"], dic["seq"], rev))


def complement_an_errata(ert, updates=None, to_update_fn=None, score=-1):
    """
    TBD: What should be complemented?

    :param ert: An errata dict
    :param updates: A list of update packages
    :param to_update_fn:
        A callable to convert pacakge object to compare with update packages
    :param score: CVSS score
    """
    if updates is None:
        updates = []

    if to_update_fn is None:
        to_update_fn = operator.itemgetter("name", "arch")

    ert["id"] = _errata_to_int(ert)  # It will be used as sorting key
    ert["updates"] = fleure.utils.uniq(p for p in ert.get("packages", [])
                                       if to_update_fn(p) in updates)
    ert["update_names"] = list(set(u["name"] for u in ert["updates"]))

    # NOTE: Quick hack to strip extra white spaces at the top and the end
    # of synopsis of some errata just in case.
    ert["synopsis"] = ert["synopsis"].strip()

    if score > 0:
        ert["cves"] = [_cve_details(cve) for cve in ert.get("cves", [])]

    return ert

# vim:sw=4:ts=4:et:
