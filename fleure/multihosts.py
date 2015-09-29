#
# -*- coding: utf-8 -*-
#
# Copyright (C) 2013, 2014 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2014 - 2015 Red Hat, Inc.
# License: GPLv3+
#
# pylint: disable=unused-variable
"""
A module to extend fleure.main for multiple host analysis.
"""
from __future__ import absolute_import

# Available in EPEL for RHELs:
# https://apps.fedoraproject.org/packages/python-bunch
import bunch
import glob
import itertools
import logging
import multiprocessing
import operator
import os.path
import os
import shutil

from fleure.globals import _

import fleure.main
import fleure.utils


LOG = logging.getLogger(__name__)


def hosts_rpmroot_g(hosts_datadir):
    """
    List system names from assessment datadir.

    This function expects that assessment data (rpm db files) of each hosts are
    found under $host_identity/ in `datadir`, that is,
    `datadir`/<host_identity>/var/lib/rpm/Packages exists. If rpm db file[s]
    are not found for a host, that host will be simply ignored.

    <host_identity> may be a hostname, host id, fqdn or something to
    identify that host.

    :param hosts_datadir: Dir in which rpm db roots of hosts exist
    :return: A generator to yield a tuple,
        (host_identity, host_rpmroot or None)
    """
    for hostdir in glob.glob(os.path.join(hosts_datadir, '*')):
        if fleure.utils.check_rpmdb_root(hostdir):
            yield (os.path.basename(hostdir), hostdir)
        else:
            LOG.warn(_("Failed to find RPM DBs under %s"), hostdir)
            yield (os.path.basename(hostdir), None)


def touch(filepath):
    """
    'touch' function.
    """
    open(filepath, 'w').write()


def prepare(hosts_datadir, workdir=None, **kwargs):
    """
    Scan and collect hosts' basic data (installed rpms list, etc.).

    :param hosts_datadir: Dir in which rpm db roots of hosts exist
    :param workdir: Working dir to save results

    :return: A generator to yield a tuple,
        (host_identity, host_rpmroot or None)
    """
    if workdir is None:
        LOG.info(_("Set workdir to hosts_datadir: %s"), hosts_datadir)
        workdir = hosts_datadir
    else:
        if not os.path.exists(workdir):
            LOG.debug(_("Creating working dir: %s"), workdir)
            os.makedirs(workdir)

    for hid, root in hosts_rpmroot_g(hosts_datadir):
        hworkdir = os.path.join(workdir, hid)
        if not hworkdir:
            os.makedirs(hworkdir)

        if root is None:
            touch(os.path.join(hworkdir, "RPMDB_NOT_AVAILABLE"))
            yield bunch.Bunch(hid=hid, workdir=hworkdir, available=False)
        else:
            yield fleure.main.prepare(root, hid=hid, workdir=hworkdir,
                                      **kwargs)


def p2nevra(pkg):
    """
    :param pkg: A dict represents package info including N, E, V, R, A
    """
    return operator.itemgetter("name", "epoch", "version", "release",
                               "arch")(pkg)


def mk_symlinks_to_ref(href, hsrest):
    """
    :param href: Reference host object
    :param hsrest: A list of hosts having same installed rpms as `href`
    """
    orgdir = os.path.abspath(os.curdir)
    for hst in hsrest:
        os.chdir(hst.workdir)
        href_workdir = os.path.join('..', href.hid)  # TODO: Keep consistency.
        LOG.info(_("%s: Make symlinks to results in %s/"),
                 hst.hid, href_workdir)
        for src in glob.glob(os.path.join(href_workdir, '*.*')):
            dst = os.path.basename(src)
            if not os.path.exists(dst):
                LOG.debug("Make a symlink to %s", src)
                os.symlink(src, dst)

        metadatafile = os.path.join(href_workdir, "metadata.json")
        shutil.copy2(metadatafile, metadatafile + ".save")
        metadata = fleure.utils.json_load(metadatafile)
        metadata["hosts"].append(hst.hid)
        fleure.utils.json_dump(metadata, metadatafile)

        os.chdir(orgdir)


def analyze(args):
    """An wrapper to run fleure.main.analyze() in parallel.
    """
    fleure.main.analyze(*args)


def main(hosts_datadir, workdir=None, verbosity=0, multiproc=False, **kwargs):
    """
    :param hosts_datadir:
        Path to dir in which rpm db roots or its archive of hosts exist

    :param workdir: Working dir to save results
    :param verbosity: Verbosity level: 0 (default), 1 (verbose), 2 (debug)
    :param multiproc: Utilize multiprocessing module to compute results
        in parallel as much as possible if True
    """
    fleure.main.set_loglevel(verbosity)
    all_hosts = list(prepare(hosts_datadir, workdir=workdir, **kwargs))
    hosts = [h for h in all_hosts if h.available]

    LOG.info(_("Analyze %d/%d hosts"), len(hosts), len(all_hosts))
    ilen = lambda h: len(h.installed)
    hps = lambda h: [p2nevra(p) for p in h.installed]
    gby = lambda xs, kf: itertools.groupby(sorted(xs, key=kf), kf)

    # Group hosts by installed rpms to degenerate these hosts and avoid to
    # analyze for same installed RPMs more than once. his :: [[[h]]]
    his = [[list(g2) for _k2, g2 in gby(g, hps)] for _k, g in gby(hosts, ilen)]

    for hss in his:
        hset = [(hs[0], hs[1:]) for hs in hss]
        hsdata = [hs[0] for hs in hset]

        if multiproc:
            pool = multiprocessing.Pool(multiprocessing.cpu_count())
            pool.map(fleure.main.analyze, hsdata)
        else:
            for host in hsdata:
                fleure.main.analyze(host)

        for hid, hsrest in hset:
            if hsrest:
                LOG.info(_("Skip to analyze %s as its installed RPMs are "
                           "exactly same as %s's"),
                         ','.join(x.hid for x in hsrest), hid)
                mk_symlinks_to_ref(hid, hsrest)

# vim:sw=4:ts=4:et:
