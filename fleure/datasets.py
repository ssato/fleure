#
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: GPLv3+
#
"""Functions to make datasets.
"""
from __future__ import absolute_import

import logging
import os.path
import tablib

import fleure.cveinfo
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
    if key in ("cves", "bzs", "keywords"):
        vals = getattr(obj, key, None)
        if vals is None or not vals:
            ret = default
        else:
            ret = ", ".join(str(v) for v in vals)
    else:
        val = getattr(obj, key, default)
        ret = ", ".join(val) if isinstance(val, (list, tuple)) else val
    try:
        if ret is None or isinstance(ret, int):
            ret = str(ret)

        return ret.encode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        LOG.debug("error when encoding: %r, exc=%r", ret, exc)
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

# vim:sw=4:ts=4:et:
