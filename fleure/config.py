#
# -*- coding: utf-8 -*-
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: GPLv3+
#
"""Fleure central configuration object.
"""
from __future__ import absolute_import

import bunch
import fleure.globals


BACKENDS = dict(yum=fleure.yumbase.Base, )
DEFAULT_BACKEND = "yum"
try:
    import fleure.dnfbase

    BACKENDS["dnf"] = fleure.dnfbase.Base
    DEFAULT_BACKEND = "dnf"  # Prefer this.
except ImportError:  # dnf is not available for RHEL, AFAIK.
    pass


class Config(bunch.Bunch):
    """Config object.
    """
    # static configurations:
    sysconfdir = fleure.globals.FLEURE_SYSCONFDIR
    sysdatadir = fleure.globals.FLEURE_DATADIR
    tpaths = fleure.globals.FLEURE_TEMPLATE_PATHS
    root = None
    cachedir = None
    workdir = None
    repos = None
    hid = None
    cvss_min_score = 0
    rpmkeys = fleure.globals.RPM_KEYS
    eratta_keywords = fleure.globals.ERRATA_KEYWORDS
    core_rpms = fleure.globals.CORE_RPMS
    rpm_vendor = fleure.globals.RPM_VENDOR
    details = True
    period = None
    refdir = None
    backend = DEFAULT_BACKEND
    backends = BACKENDS

    def __init__(self):
        """Initialize some dynamic configurations.
        """
        vendor = fleure.globals.RPM_VENDOR

# vim:sw=4:ts=4:et:
