#
# Copyright (C) 2014 - 2015 Satoru SATOH <ssato redhat.com>
# License: GPLv3+
#
"""Package object defs.
"""
from __future__ import absolute_import

import collections
import logging
import re

import fleure.rpmutils
from fleure.globals import _


CACHE = dict()
LOG = logging.getLogger(__name__)

_ERRATA_CHARS = dict(E=1, B=2, S=3)
_ERRATA_SEVS = collections.defaultdict(int, dict(Low=2, Moderate=4,
                                                 Important=6, Critical=8))
_ERRATA_ADV_RE = re.compile(r"^RH(?P<echar>(E|B|S))A-(?P<year>\d{4}):"
                            r"(?P<seq>\d{4,5})(?:-(?P<rev>\d+))?$")

Bugzilla = collections.namedtuple("Bugzilla", "id summary url")
CVE = collections.namedtuple("CVE", "id cve url score")


def _to_int(advisory, severity=False):
    """
    Generate an int represents an errata to used as comparison key.

    - RHSA > RHBA > RHEA (type)
    - RHSA: Critical > Important > Moderate > Low (severity)
    - RHBA-2013:0212 > RHBA-2012:1422 (year)
    - RHBA-2013:0212 > RHBA-2013:0210 (sequential id)
    - RHBA-2013:0212-1 > RHBA-2013:0212 (revision)

    .. note::
       It cannot process non-RH errata such as fedroa's, e.g.
       FEDORA-2015-18fa1c54ef.

    :param advisory: Errata advisory
    :param severity: Severity of security errata if given

    >>> _to_int("RHBA-2012:1422-1")
    202012142201
    >>> _to_int("RHSA-2014:0422", "Moderate")
    342014042200
    """
    match = _ERRATA_ADV_RE.match(advisory)
    if not match:
        LOG.warn(_("Not an errata advisory ? : %s"), advisory)
        return 0

    dic = match.groupdict()
    params = (_ERRATA_CHARS[dic["echar"]],
              _ERRATA_SEVS[severity] if severity else 0,
              dic["year"], dic["seq"],
              0 if dic["rev"] is None else int(dic["rev"]))

    return int("%d%d%s%s%02d" % params)


def factory(advisory, updates=None, cache=None, **info):
    """
    TBD: What should be a member of errata?

    :param advisory: Advisory name
    :param updates: Update packages relevant to this errata :: [namedtuple]
    :param bzs:
        List of Bugzilla tickets relevant to this errata :: [namedtuple]
    :param cache: Global errata cache
    :param info: Other basic errata info such as

        - type: Errata type, security | bugfix | enhanement | unknown
        - severity: Severity level if it's security errata or N/A
        - synopsis: short description
        - description: long description
        - issue_date: Issued date
        - update_date: Last updated date
        - bzs: List of relevant Bugzilla tickets :: [namedtuple]
        - cves: List of relevant CVEs :: [namedtuple]

    :return:
        An instance of :class:`collections.namedtuple` holding errata info
    """
    if updates is None:
        updates = []

    if cache is None:
        cache = CACHE

    if advisory in cache:
        return cache[advisory]  # TBD: if update_date was updated?

    eid = _to_int(advisory, info.get("severity", False))  # sorting key
    url = fleure.rpmutils.errata_url(advisory)
    uns = list(set(u.name for u in updates))

    # TODO: How to update fields later ?
    keys = ("id advisory url synopsis description update_date issue_date "
            "type severity bzs cves updates update_names").split()
    extra_keys = sorted(k for k in info.keys() if k not in keys)

    errata = collections.namedtuple("errata", keys + extra_keys)
    ert = errata(eid, advisory, url,
                 info["synopsis"].strip(), info["description"].strip(),
                 info["update_date"], info["issue_date"], info["type"],
                 info.get("severity", "N/A"),
                 info.get("bzs", []), info.get("cves", []),
                 updates, uns, *[info[k] for k in extra_keys])

    cache[advisory] = ert
    return ert

# vim:sw=4:ts=4:et:
