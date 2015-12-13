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


def _make_cell_data(obj, key, default="N/A"):
    """Make up cell data.
    """
    if isinstance(obj, tuple) and hasattr(obj, "_asdict"):
        _get = lambda obj, key, default: getattr(obj, key, default)
    else:
        _get = lambda obj, key, default: obj.get(key, default)

    if key in ("cves", "bzs"):
        vals = getattr(obj, key, None)
        if vals is None or not vals:
            ret = default
        ret = ", ".join(str(v) for v in vals)
    else:
        val = _get(obj, key, default)
        ret = ", ".join(val) if isinstance(val, (list, tuple)) else val
    try:
        return ret.encode("utf-8")
    except Exception as exc:
        return str(ret)


def make_dataset(list_data, title=None, headers=None, lheaders=None):
    """
    :param list_data: List of data, may be consists of [[namedtuple]]
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
        tdata = [[_make_cell_data(val, h) for h in headers] for val
                 in list_data]
        headers = headers if lheaders is None else lheaders
    else:
        tdata = [val.values() for val in list_data]

    return tablib.Dataset(*tdata, title=title[:30], headers=headers)


def _assert_if_not_exist(path, desc):
    """Tiny helper function to check if given path (dir or file) exists.
    """
    if not os.path.exists(path):
        raise IOError("Reference %s not found: %s" % (desc, path))


def compute_delta(host, refdir, ers, updates):
    """
    :param refdir: Dir has reference data files: packages.json, errata.json
        and updates.json
    :param ers: A list of errata :: [namedtuple]
    :param updates: A list of update packages :: [namedtuple]
    """
    _assert_if_not_exist(refdir, "data dir")
    nevra_keys = fleure.globals.RPM_KEYS

    ref_es = host.load("errata", refdir)["data"]  # :: [dict]
    ref_us = host.load("updates", refdir)["data"]  # :: [dict]
    LOG.debug(_("Loaded reference errata and updates files in %s"), refdir)

    ref_eadvs = set(e["advisory"] for e in ref_es)
    ref_nevras = set((u[k] for k in nevra_keys) for u in ref_us)

    return ([e for e in ers if e.advisory not in ref_eadvs],
            [u for u in updates
             if (getattr(u, k) for k in nevra_keys) not in ref_nevras])


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
        LOG.warn(_("Not an errata advisory ? : %(advisory)s"), errata)
        return 0

    dic = match.groupdict()
    rev = 0 if dic["rev"] is None else int(dic["rev"])
    return int("%d%d%s%s%02d" % (echars[dic["echar"]],
                                 sevs[errata.get("severity", 0)],
                                 dic["year"], dic["seq"], rev))


def complement_an_errata(ert, updates=None, score=-1):
    """
    TBD: What should be complemented?

    :param ert: An errata dict
    :param updates: A list of update packages
    :param score: CVSS score
    """
    if updates is None:
        updates = []

    p2na = operator.itemgetter("name", "arch")
    ert["id"] = _errata_to_int(ert)  # It will be used as sorting key
    ert["updates"] = fleure.utils.uniq(p for p in ert.get("packages", [])
                                       if p2na(p) in updates)
    ert["update_names"] = list(set(u["name"] for u in ert["updates"]))

    # NOTE: Quick hack to strip extra white spaces at the top and the end
    # of synopsis of some errata just in case.
    ert["synopsis"] = ert["synopsis"].strip()

    if score > 0:
        ert["cves"] = [_cve_details(cve) for cve in ert.get("cves", [])]

    return ert

# vim:sw=4:ts=4:et:
