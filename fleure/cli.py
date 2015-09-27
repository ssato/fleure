#
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: GPLv3+
#
"""fleure's CLI frontend.
"""
from __future__ import absolute_import

import datetime
import logging
import optparse
import os.path

import fleure.globals
import fleure.config
import fleure.main
import fleure.multihosts


LOG = logging.getLogger(__name__)
_TODAY = datetime.datetime.now().strftime("%F")
_DEFAULTS = dict(path=None, workdir="/tmp/fleure-{}".format(_TODAY),
                 repos=None, imultiproc=False, hid=None, multihost=False,
                 score=fleure.globals.DEFAULT_CVSS_SCORE,
                 keywords=fleure.globals.ERRATA_KEYWORDS,
                 rpms=fleure.globals.CORE_RPMS,
                 period='', cachedir=None, refdir=None, tpaths=[],
                 backend=fleure.config.DEFAULT_BACKEND,
                 backends=fleure.config.BACKENDS, verbosity=0)
_USAGE = """\
%prog [Options...] ROOT

    where ROOT = RPM DB root having var/lib/rpm from the target host or
                 top dir to hold RPM DB roots of some hosts
                 [multihosts mode]"""


def parse_args():
    """Parse arguments.
    """
    defaults = _DEFAULTS
    backends = defaults["backends"]

    psr = optparse.OptionParser(_USAGE)
    psr.set_defaults(**defaults)

    psr.add_option("-w", "--workdir", help="Working dir [%default]")
    psr.add_option("-r", "--repo", dest="repos", action="append",
                   help="Yum repo to fetch errata info, e.g. "
                        "'rhel-x86_64-server-6'. It can be given multiple "
                        "times to specify multiple yum repos. If any repos "
                        "are not given by this option, repos are guess from "
                        "data in RPM DBs automatically, and please not that "
                        "any other repos are disabled if this option was set.")
    psr.add_option("-I", "--hid", help="Host (Data) ID [None]")
    psr.add_option("-M", "--multihost", help="Multihost mode")
    # TODO: Disabled until issue of yum vs. multiprocessing module is fixed.
    # p.add_option("-M", "--multiproc", action="store_true",
    #             help="Specify this option if you want to analyze data "
    #                  "in parallel (disabled currently)")
    psr.add_option("-B", "--backend", choices=backends.keys(),
                   help="Specify backend to get updates and errata. Choices: "
                        "%s [%%default]" % ', '.join(backends.keys()))
    psr.add_option("-S", "--score", type="float",
                   help="CVSS base metrics score to filter 'important' "
                        "security errata [%default]. "
                        "Specify -1 if you want to disable this.")
    psr.add_option("-k", "--keyword", dest="keywords", action="append",
                   help="Keyword to select more 'important' bug errata. "
                        "You can specify this multiple times. "
                        "[%s]" % ', '.join(defaults["keywords"]))
    psr.add_option('', "--rpm", dest="rpms", action="append",
                   help="RPM names to filter errata relevant to given RPMs")
    psr.add_option('', "--period",
                   help="Period to filter errata in format of "
                        "YYYY[-MM[-DD]][,YYYY[-MM[-DD]]], "
                        "ex. '2014-10-01,2014-12-31', '2014-01-01'. "
                        "If end date is omitted, Today will be used instead")
    psr.add_option("-C", "--cachedir",
                   help="Specify yum repo metadata cachedir [root/var/cache]")
    psr.add_option("-R", "--refdir",
                   help="Output 'delta' result compared to the data "
                        "in this dir")
    psr.add_option("-T", "--tpath", action="append", dest="tpaths",
                   help="Specify additional template path one by one. These "
                        "paths will have higher priority than default paths.")
    psr.add_option("-v", "--verbose", action="count", dest="verbosity",
                   help="Verbose mode")
    psr.add_option("-D", "--debug", action="store_const", dest="verbosity",
                   const=2, help="Debug mode (same as -vv)")

    return psr.parse_args()


def main():
    """Cli main.
    """
    (options, args) = parse_args()

    root = args[0] if args else raw_input("Host[s] data dir (root) > ")
    assert os.path.exists(root), "Not found RPM DB Root: %s" % root

    period = options.period.split(',') if options.period else None
    if not options.tpaths:
        options.tpaths = fleure.globals.FLEURE_TEMPLATE_PATHS

    cnf = dict(workdir=options.workdir, cachedir=options.cachedir,
               repos=options.repos, verbosity=options.verbosity,
               cvss_min_score=options.score, errata_keywords=options.keywords,
               core_rpms=options.rpms, period=period, refdir=options.refdir,
               backend=options.backend, tpaths=options.tpaths)

    if os.path.exists(os.path.join(root, "var/lib/rpm")):
        options.multihost = False
        LOG.info("Found a data of single host. Switch backed to single host mode.")

    if options.multihost:
        # NOTE: multiproc mode is disabled and options.multiproc is not passed
        # to RUMS.main until the issue of yum that its thread locks conflict w/
        # multiprocessing module is fixed.
        fleure.multihosts.main(root, **cnf)
    else:
        fleure.main.main(root, hid=options.hid, **cnf)

if __name__ == '__main__':
    main()

# vim:sw=4:ts=4:et:
