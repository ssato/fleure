#
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: GPLv3+
#
"""Functions to make datasets.
"""
from __future__ import absolute_import

import calendar
import collections
import logging
import os.path
import re
import tablib

import fleure.yumbase
import fleure.dnfbase
import fleure.utils
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
    """
    tds = tablib.Dataset()

    # NOTE: We need to check title as valid worksheet name (length <= 31, etc.)
    # See also xlwt.Utils.valid_sheet_name.
    if title:
        tds.title = title[:30]

    if headers is not None:
        tds.headers = headers if lheaders is None else lheaders
        for val in list_data:
            tds.append([_make_cell_data(val, h) for h in headers])
    else:
        for val in list_data:
            tds.append(val.values())

    return tds


def compute_delta(refdir, ers, updates, nevra_keys=fleure.globals.RPM_KEYS):
    """
    :param refdir: Dir has reference data files: packages.json, errata.json
        and updates.json
    :param ers: A list of errata
    :param updates: A list of update packages
    """
    emsg = "Reference %s not found: %s"
    assert os.path.exists(refdir), emsg % ("data dir", refdir)

    ref_es_file = os.path.join(refdir, "errata.json")
    ref_us_file = os.path.join(refdir, "updates.json")
    assert os.path.exists(ref_es_file), emsg % ("errata file", ref_es_file)
    assert os.path.exists(ref_us_file), emsg % ("updates file", ref_us_file)

    ref_es_data = fleure.utils.json_load(ref_es_file)
    ref_us_data = fleure.utils.json_load(ref_us_file)
    LOG.debug(_("Loaded reference errata and updates file"))

    ref_eadvs = set(e["advisory"] for e in ref_es_data["data"])
    ref_nevras = set((p[k] for k in nevra_keys) for p in ref_us_data["data"])

    return ([e for e in ers if e["advisory"] not in ref_eadvs],
            [u for u in updates
             if (u[k] for k in nevra_keys) not in ref_nevras])


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
                     r"(?P<seq>\d{4})(?:-(?P<rev>\d+))?$")

    match = reg.match(errata["advisory"])
    if not match:
        LOG.warn("Not an errata advisory ? : %(advisory)s", errata)
        return 0

    dic = match.groupdict()
    rev = 0 if dic["rev"] is None else int(dic["rev"])
    return int("%d%d%s%s%02d" % (echars[dic["echar"]],
                                 sevs[errata.get("severity", 0)],
                                 dic["year"], dic["seq"], rev))


def errata_complement_g(ers, updates, score=0):
    """
    TODO: What should be complemented?

    :param ers: A list of errata
    :param updates: A list of update packages
    :param score: CVSS score
    """
    p2na = lambda pkg: (pkg["name"], pkg["arch"])

    unas = set(p2na(u) for u in updates)
    for ert in ers:
        ert["id"] = _errata_to_int(ert)  # Sorting key
        ert["updates"] = fleure.utils.uniq(p for p in ert.get("packages", [])
                                           if p2na(p) in unas)
        ert["update_names"] = list(set(u["name"] for u in ert["updates"]))

        # NOTE: Quick hack to strip extra white spaces at the top and the end
        # of synopsis of some errata just in case.
        ert["synopsis"] = ert["synopsis"].strip()

        if score > 0:
            ert["cves"] = [_cve_details(cve) for cve in ert.get("cves", [])]

        yield ert


def _d2i(day):
    """
    >>> _d2i((2014, 10, 1))
    20141001
    """
    return day[0] * 10000 + day[1] * 100 + day[2]


def _errata_date(date_s):
    """
    NOTE: Errata issue_date and update_date format: month/day/year,
        e.g. 12/16/10.

    >>> _errata_date("12/16/10")
    (2010, 12, 16)
    >>> _errata_date("2014-10-14 00:00:00")
    (2014, 10, 14)
    """
    if '-' in date_s:
        (year, month, day) = date_s.split()[0].split('-')
        return (int(year), int(month), int(day))
    else:
        (month, day, year) = date_s.split('/')
        return (int("20" + year), int(month), int(day))


def _round_ymd(year, mon, day, roundout=False):
    """
    :param roundout: Round out given date to next year, month, day if this
        parameter is True

    >>> _round_ymd(2014, None, None, True)
    (2015, 1, 1)
    >>> _round_ymd(2014, 11, None, True)
    (2014, 12, 1)
    >>> _round_ymd(2014, 12, 24, True)
    (2014, 12, 25)
    >>> _round_ymd(2014, 12, 31, True)
    (2015, 1, 1)
    >>> _round_ymd(2014, None, None)
    (2014, 1, 1)
    >>> _round_ymd(2014, 11, None)
    (2014, 11, 1)
    >>> _round_ymd(2014, 12, 24)
    (2014, 12, 24)
    """
    if mon is None:
        return (year + 1 if roundout else year, 1, 1)

    elif day is None:
        if roundout:
            return (year + 1, 1, 1) if mon == 12 else (year, mon + 1, 1)
        else:
            return (year, mon, 1)
    else:
        if roundout:
            last_day = calendar.monthrange(year, mon)[1]
            if day == last_day:
                return (year + 1, 1, 1) if mon == 12 else (year, mon + 1, 1)
            else:
                return (year, mon, day + 1)
        else:
            return (year, mon, day)


def _ymd_to_date(ymd, roundout=False):
    """
    :param ymd: Date string in YYYY[-MM[-DD]]
    :param roundout: Round out to next year, month if True and day was not
        given; ex. '2014' -> (2015, 1, 1), '2014-11' -> (2014, 12, 1)
        '2014-12-24' -> (2014, 12, 25), '2014-12-31' -> (2015, 1, 1) if True
        and '2014' -> (2014, 1, 1), '2014-11' -> (2014, 11, 1) if False.
    :param datereg: Date string regex

    :return: A tuple of (year, month, day) :: (int, int, int)

    >>> _ymd_to_date('2014-12-24')
    (2014, 12, 24)
    >>> _ymd_to_date('2014-12')
    (2014, 12, 1)
    >>> _ymd_to_date('2014')
    (2014, 1, 1)
    >>> _ymd_to_date('2014-12-24', True)
    (2014, 12, 25)
    >>> _ymd_to_date('2014-12-31', True)
    (2015, 1, 1)
    >>> _ymd_to_date('2014-12', True)
    (2015, 1, 1)
    >>> _ymd_to_date('2014', True)
    (2015, 1, 1)
    """
    match = re.match(r"^(\d{4})(?:.(\d{2})(?:.(\d{2}))?)?$", ymd)
    if not match:
        LOG.error("Invalid input for normalize_date(): %s", ymd)

    dic = match.groups()
    int_ = lambda x: x if x is None else int(x)
    return _round_ymd(int(dic[0]), int_(dic[1]), int_(dic[2]), roundout)


def period_to_dates(start_date, end_date=fleure.globals.TODAY):
    """
    :param period: Period of errata in format of YYYY[-MM[-DD]],
        ex. ("2014-10-01", "2014-11-01")

    >>> today = _d2i(_ymd_to_date(fleure.globals.TODAY, True))
    >>> (20141001, today) == period_to_dates("2014-10-01")
    True
    >>> period_to_dates("2014-10-01", "2014-12-31")
    (20141001, 20150101)
    """
    return (_d2i(_ymd_to_date(start_date)), _d2i(_ymd_to_date(end_date, True)))


def errata_in_period(errata, start_date, end_date):
    """
    :param errata: A dict represents errata
    :param start_date, end_date: Start and end date of period,
        (year :: int, month :: int, day :: int)
    """
    day = _d2i(_errata_date(errata["issue_date"]))
    return start_date <= day and day < end_date

# vim:sw=4:ts=4:et:
