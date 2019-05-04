#
# cve related functions from rpmkit.swapi
#
# Copyright (C) 2010 Satoru SATOH <satoru.satoh at gmail.com>
# Copyright (C) 2011 - 2017 Satoru SATOH <ssato at redhat.com>
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#
# pylint: disable=no-name-in-module
"""CVE/CVSS related utility routines originally from rpmkit.swapi
"""
from __future__ import absolute_import

import logging
import re
import bs4 as beautifulsoup

try:
    import urllib.request as urllib2  # python 3
    from urllib.error import HTTPError, URLError
except ImportError:
    import urllib2
    from urllib2 import HTTPError, URLError

from fleure.globals import _


LOG = logging.getLogger(__name__)

# @see http://www.first.org/cvss/cvss-guide.html
# AV:L/AC:N/Au:N/C:N/I:N/A:C
# AC:N/Au:N/C:N/I:N/A:C
CVSSS_METRICS_MAP = dict(
    AV=dict(
        label="Access Vector",
        metrics=dict(  # Larger values cause higher risk.
            L=1,  # Local
            A=2,  # Adjacent Network, e.g. LAN
            N=3   # Network
        ),
    ),
    AC=dict(
        label="Access Complexity",
        metrics=dict(
            H=1,  # High
            M=2,  # Medium
            L=3,  # Low
        ),
    ),
    Au=dict(
        label="Authentication",
        metrics=dict(
            M=1,  # Multiple
            S=2,  # Single
            N=3,  # None
        ),
    ),
    C=dict(
        label="Confidentiality Impact",
        metrics=dict(
            N=1,  # None
            P=2,  # Partial
            C=3,  # Complete
        ),
    ),
    I=dict(  # flake8: noqa
             # It's needed to suppress 'ambiguous variable name' warn.
        label="Integrity Impact",
        metrics=dict(
            N=1,  # None
            P=2,  # Partial
            C=3,  # Complete
        ),
    ),
    A=dict(
        label="Availability Impact",
        metrics=dict(
            N=1,  # None
            P=2,  # Partial
            C=3,  # Complete
        ),
    ),
)


def urlread(url, data=None, headers=None):
    """
    Open given url and return its contents or None.

    :param url: URL string to read
    :param data: Data to send
    :param headers: Optional http headers to be passed

    :return: Content (:: str) or None
    """
    if headers is None:
        headers = {}

    req = urllib2.Request(url=url, data=data, headers=headers)
    try:
        return urllib2.urlopen(req).read()
    except (HTTPError, URLError, IOError, OSError):
        return None


def cve2url(cve):
    """
    :param cve: A CVE ID string
    :return: URL of CVE in Red Hat CVE database on the web

    >>> url = "https://access.redhat.com/security/cve/CVE-2010-1585?lang=en"
    >>> assert url == cve2url("CVE-2010-1585")
    """
    return "https://access.redhat.com/security/cve/%s?lang=en" % cve


def cvss_metrics(cvss, metrics_map=None):
    """
    TODO: Some of CVEs in Red Hat CVE database look having wrong CVSS
    metrics data.

    :param cvss: A string represents CVSS metrics,
        ex. "AV:N/AC:H/Au:N/C:N/I:P/A:N"
    :param metrics_map: CVSS metrics mappings :: dict

    >>> ms_ref = [
    ...     ("Access Vector", 3), ("Access Complexity", 1),
    ...     ("Authentication", 3), ("Confidentiality Impact", 1),
    ...     ("Integrity Impact", 2), ("Availability Impact", 1),
    ... ]
    >>> ms0 = cvss_metrics("AV:N/AC:H/Au:N/C:N/I:P/A:N")
    >>> assert ms0 == ms_ref, str(ms0)

    >>> ms1 = cvss_metrics("AV:N/AC:H/AU:N/C:N/I:P/A:N")  # CVE-2012-3406
    >>> assert ms1 == ms_ref, str(ms1)

    >>> ms2 = cvss_metrics("AV:N/AC:H/Au/N/C:N/I:P/A:N")  # CVE-2012-5077
    >>> assert ms2 == ms_ref, str(ms2)

    >>> ms3 = cvss_metrics("AV:N/AC:N/Au/N/C:P/I:N/A:N")  # CVE-2012-3375
    >>> assert ms3 != ms_ref, str(ms3)
    """
    if metrics_map is None:
        metrics_map = CVSSS_METRICS_MAP

    metrics = []

    if "/AU:" in cvss:
        cvss = cvss.replace("/AU:", "/Au:")

    if "/Au/" in cvss:
        cvss = cvss.replace("/Au/", "/Au:")

    for lms in cvss.split("/"):
        (key, val) = lms.split(":")
        metric = metrics_map.get(key, False)

        if not metric:
            LOG.error(_("Unknown CVSS metric abbrev: %s"), key)
            return metrics

        label = metric["label"]
        val = metric["metrics"].get(val, False)

        if not val:
            LOG.error(_("Uknown value for CVSS metric '%s': %s"), metric, val)
            return metrics

        metrics.append((label, val))

    return metrics


def get_cvss_for_cve(cve):
    """
    Get CVSS data for given cve from the Red Hat www site.

    :param cve: CVE name, e.g. "CVE-2010-1585" :: str
    :return:  {"metrics": base_metric :: str, "score": base_score :: str}

    See the HTML source of CVE www page for its format, e.g.
    https://www.redhat.com/security/data/cve/CVE-2010-1585.html.
    """
    match = re.match(r"CVE-(?P<year>\d{4})-(?P<id>\d{4})", cve)
    if match:
        year = int(match.groupdict()["year"])
        if year < 2009:  # No CVSS
            return None
    else:
        LOG.warning(_("Invalid CVE: %s"), cve)
        return None

    def has_cvss_link(tag):
        """Does CVE has a link to CVSS base metrics?
        """
        return tag.get("href", "").startswith("http://nvd.nist.gov/cvss.cfm")

    def is_base_score(tag):
        """Is it CVSS base score?
        """
        return tag.string == "Base Score:"

    url_fmt = "http://nvd.nist.gov/cvss.cfm?version=2&name=%s&vector=(%s)"
    try:
        data = urlread(cve2url(cve))
        soup = beautifulsoup.BeautifulSoup(data)

        cvss_base_metrics = soup.findAll(has_cvss_link)[0].string
        cvss_base_score = soup.findAll(is_base_score)[0].parent.td.string

        # may fail to parse `cvss_base_metrics`
        cvss_base_metrics_vec = cvss_metrics(cvss_base_metrics)

        return dict(cve=cve,
                    metrics=cvss_base_metrics,
                    metrics_v=cvss_base_metrics_vec,
                    score=cvss_base_score,
                    url=url_fmt % (cve, cvss_base_metrics))

    except Exception as exc:
        LOG.warning(_("Could not get CVSS data: err=%s"), str(exc))

    return None

# vim:sw=4:ts=4:et:
