#
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2016 Red Hat, Inc.
# License: GPLv3+
#
"""fleure's CLI frontend.
"""
from __future__ import absolute_import
from __future__ import print_function

import argparse
import errno
import itertools
import logging
import operator
import os.path
import pprint
import re
import sys

import fleure.globals
import fleure.config
import fleure.main
import fleure.multihosts


LOG = logging.getLogger(__name__)

DEFAULTS = fleure.config.DEFAULTS.copy()
DEFAULTS.update(multiproc=False, multihost=False, verbosity=0)


def period_type(period_s):
    """
    :param period_s:
        A string represents date period such as
        "YYYY[-MM[-DD]][,YYYY[-MM[-DD]]], ex. " "'2014-10-01,2014-12-31',
        '2014-01-01'.

    .. seealso:: :func:`period_to_dates` and its friends in fleure.dates
    """
    if not period_s:
        return []

    reg = r"^((\d{4})(?:.(\d{2})(?:.(\d{2}))?))?$"
    if ',' in period_s:
        (start, end) = period_s.split(',')
        (start, end) = (start.strip(), end.strip())

        if re.match(reg, start) and re.match(reg, end):
            return [start, end]
    else:
        if re.match(reg, period_s):
            return [period_s]

    raise argparse.ArgumentTypeError("Given string '%s' does not match with "
                                     "required format, "
                                     "YYYY[-MM[-DD]][,YYYY[-MM[-DD]]]")


def parse_keywords(kwds, sep=':'):
    """
    Parse keyword option strings and return a errata keywords info dict.

    :param kwds: A list of keyword strings, e.g. ['kernel:kvm', 'ntp:crash']
    :param sep: Separator char between name of RPM and keyword

    :return: A dict, {rpm_name: [keyword :: str]}

    >>> rkwds = parse_keywords(['ntp:hang', 'ntp:crash', 'kernel:kvm'])
    >>> [(key, sorted(val)) for key, val in sorted(rkwds.items())]
    [('kernel', ['kvm']), ('ntp', ['crash', 'hang'])]
    """
    fst = operator.itemgetter(0)
    snd = operator.itemgetter(1)
    itr = (kwd.split(sep)[:2] for kwd in kwds if sep in kwd)

    return {p: [snd(k) for k in g] for p, g in itertools.groupby(itr, fst)}


def parse_args(argv):
    """Parse arguments.
    """
    psr = argparse.ArgumentParser()

    add_arg = psr.add_argument  # or (optparse.OptionParser).add_argion

    defaults = DEFAULTS
    backends = defaults["backends"]

    add_arg("-c", "--conf", dest="conf_path",
            help="Configuration file[s] path [%(conf_path)s]" % defaults)
    add_arg("-w", "--workdir", help="Working dir [%(workdir)s]" % defaults)
    add_arg("-r", "--repo", dest="repos", action="append",
            help="Yum repo to fetch errata info, e.g. 'rhel-x86_64-server-6'. "
                 "It can be given multiple times to specify multiple yum "
                 "repos. If any repos are not given by this option, repos are "
                 "guess from data in RPM DBs automatically, and please not "
                 "that any other repos are disabled if this option was set.")
    add_arg("-I", "--hid", help="Host (Data) ID [None]")
    add_arg("-A", "--archive", action="store_true",
            help="Archive report files generated")
    add_arg("-M", "--multihost", action="store_true", help="Multihost mode")
    # ..note:: Disabled until issue of yum vs. multiprocessing module is fixed.
    # add_arg("-M", "--multiproc", action="store_true",
    #         help="Specify this option to analyze data in parallel")
    add_arg("-B", "--backend", choices=backends.keys(),
            help="Specify backend to get updates and errata. Choices: "
                 "%s [%s]" % (', '.join(backends.keys()), defaults["backend"]))
    add_arg("-S", "--score", type=float, dest="cvss_min_score",
            help="CVSS base metrics score to filter 'important' security "
                 "errata [%(cvss_min_score)s]. Specify -1 if you want to "
                 "disable this." % defaults)
    add_arg("-k", "--keyword", dest="errata_keywords", action="append",
            help="Keyword to select more 'important' bug errata. You can "
                 "specify this option multiple times to pass multiple "
                 "keywords. [%s]" % ', '.join(defaults["errata_keywords"]))
    add_arg("-K", "--pkeyword", dest="errata_pkeywords", action="append",
            help="Keyword to select more 'important' bug errata of RPMs. "
                 "You can specify this option multiple times to pass multiple "
                 "keywords. The format is 'rpm_name:keyword', "
                 "'kernel:bnx2x' for example")
    add_arg("--rpm", dest="core_rpms", action="append",
            help="RPM names to filter errata relevant to given RPMs "
                 "[%s]" % ', '.join(defaults["core_rpms"]))
    add_arg("--period", type=period_type,
            help="Period to filter errata in format of "
                 "YYYY[-MM[-DD]][,YYYY[-MM[-DD]]], ex. "
                 "'2014-10-01,2014-12-31', '2014-01-01'. If end date is "
                 "omitted, Today will be used instead")
    add_arg("-C", "--cachedir",
            help="Specify yum repo metadata cachedir [root/var/cache]")
    add_arg("-R", "--refdir",
            help="Output 'delta' result compared to the data in this dir")
    add_arg("-T", "--tpath", action="append", dest="tpaths",
            help="Specify additional template path one by one. These paths "
                 "will have higher priority than default paths. "
                 "%s" % ', '.join(defaults["tpaths"]))
    add_arg("-v", "--verbose", action="count", dest="verbosity",
            help="Verbose mode")
    add_arg("-D", "--debug", action="store_const", dest="verbosity",
            const=2, help="Debug mode (same as -vv)")

    add_arg("root_or_archive",
            help="RPM DB root contains var/lib/rpm/[A-Z]* gotten from "
                 "target host, or its archive made with "
                 "tar zcf rpmdb.tar.gz /var/lib/rpm/[A-Z]* for example "
                 "[single host mode], or top dir holding RPM DB root dirs "
                 "of target hosts [multihost mode]")

    return psr.parse_args(argv)


def main(argv=None):
    """Cli main.
    """
    if argv is None:
        argv = sys.argv[1:]

    args = parse_args(argv)
    fleure.main.set_loglevel(args.verbosity)

    if not os.path.exists(args.root_or_archive):
        print("Not found: %s" % args.root_or_archive, file=sys.stderr)
        sys.exit(errno.ENOENT)

    if not args.tpaths:
        args.tpaths = fleure.globals.FLEURE_TEMPLATE_PATHS

    if not args.conf_path:
        args.conf_path = fleure.globals.FLEURE_SYSCONF

    if args.errata_pkeywords:
        args.errata_pkeywords = parse_keywords(args.errata_pkeywords)

    LOG.debug("Loading config from: %s", args.conf_path)
    cnf = fleure.config.try_to_load_config_from_files(args.conf_path)

    for key in ("workdir", "repos", "hid", "archive", "backend",
                "cvss_min_score", "errata_keywords", "errata_pkeywords",
                "core_rpms", "period", "cachedir", "refdir", "tpaths",
                "verbosity"):
        val = getattr(args, key, None)
        if val is not None:
            cnf[key] = val  # CLI options > configs from file[s].

        if key not in cnf:  # In case not in config file[s]
            if not val:
                val = DEFAULTS[key]
            cnf[key] = val

    rpath = os.path.join(args.root_or_archive, fleure.globals.RPMDB_SUBDIR)
    if args.multihost and os.path.exists(rpath):
        LOG.warn(fleure.globals._("Found a RPM data of a host, go back "
                                  "to single host mode."))
        args.multihost = False

    fnc = fleure.multihosts.main if args.multihost else fleure.main.main
    fnc(args.root_or_archive, **cnf)

if __name__ == '__main__':
    main()

# vim:sw=4:ts=4:et:
