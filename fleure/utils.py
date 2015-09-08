#
# Copyright (C) 2014 - 2015 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato@redhat.com>
#
# This software is licensed to you under the GNU General Public License,
# version 3 (GPLv3). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. You should have received a copy of GPLv3 along with this
# software; if not, see http://www.gnu.org/licenses/gpl.html
#
"""
Misc utility routines for fleure.
"""
from __future__ import absolute_import

import logging
import os.path
import os
import re
import rpm

try:
    import bsddb
except ImportError:
    bsddb = None


LOG = logging.getLogger(__name__)
RPMDB_SUBDIR = "var/lib/rpm"

# It may depends on the versions of rpm:
RPMDB_FILENAMES = ("Packages", "Basenames", "Dirnames", "Installtid", "Name",
                   "Obsoletename", "Providename", "Requirename")

_RHERRATA_RE = re.compile(r"^RH[SBE]A-\d{4}[:-]\d{4}(?:-\d+)?$")


def uniq(vals, sort=True, key=None, reverse=False, use_set=False):
    """
    Returns new list of no duplicated items.
    If ``sort`` is True, result list will be sorted.

    :param vals: Any valss such as a list, tuple and generator.
    :param key: Key to compare items passed to :function:`sorted`
        if ``sort`` is True.
    :param reverse: Sorted result list reversed if ``sort`` is True.
    :param use_set: Use :function:`set` to make unique items set if True.
        It's much faster than naive implementation but items must be hash-able
        objects as :function:`set` requires this as its inputs. Also, result
        list will be sorted even if ``sort`` is not True in this case.

    >>> uniq([])
    []
    >>> uniq([0, 3, 1, 2, 1, 0, 4, 5])
    [0, 1, 2, 3, 4, 5]
    >>> uniq([0, 3, 1, 2, 1, 0, 4, 5], reverse=True)
    [5, 4, 3, 2, 1, 0]
    >>> uniq([0, 3, 1, 2, 1, 0, 4, 5], sort=False)
    [0, 3, 1, 2, 4, 5]
    >>> uniq((0, 3, 1, 2, 1, 0, 4, 5), sort=False)
    [0, 3, 1, 2, 4, 5]
    """
    if use_set:
        return sorted(set(vals), key=key, reverse=reverse)

    acc = []
    for val in vals:
        if val not in acc:
            acc.append(val)

    return sorted(acc, key=key, reverse=reverse) if sort else acc


def _is_bsd_hashdb(dbpath):
    """
    TODO: Is this enough to check if given file ``dbpath`` is RPM DB file ?
    And also, maybe some db files should be opened w/ bsddb.btopen instead of
    bsddb.hashopen.

    >>> if os.path.exists("/etc/redhat-release"):
    ...     _is_bsd_hashdb("/var/lib/rpm/Packages")
    True
    """
    try:
        if bsddb is None:
            return True  # bsddb is not avialable in python3.

        bsddb.hashopen(dbpath, 'r')
    except (OSError, IOError):
        LOG.warn("Not a Berkley DB?: %s", dbpath)
        return False

    return True


def check_rpmdb_root(root, readonly=True, dbnames=RPMDB_FILENAMES):
    """
    :param root: The pivot root directry where target's RPM DB files exist.
    :param readonly: Ensure RPM DB files readonly.
    :return: True if necessary setup was done w/ success else False
    """
    assert root != "/", "Do not run this for host system's RPM DB!"

    rpmdbdir = os.path.join(root, RPMDB_SUBDIR)

    if not os.path.exists(rpmdbdir):
        LOG.error("RPM DB dir %s does not exist!", rpmdbdir)
        return False

    pkgdb = os.path.join(rpmdbdir, "Packages")
    if not _is_bsd_hashdb(pkgdb):
        LOG.error("%s does not look a RPM DB (Packages) file!", pkgdb)
        return False

    for dbn in dbnames:
        dbpath = os.path.join(rpmdbdir, dbn)

        if not os.path.exists(dbpath):
            # NOTE: It's not an error at once.
            LOG.info("RPM DB %s looks missing", dbn)

        if readonly and os.access(dbpath, os.W_OK):
            LOG.info("Drop write access perm from %s ", dbn)
            os.chmod(dbpath, 0o444)

    return True


def errata_url(advisory):
    """
    :param errata: Red Hat Errata Advisory name :: str

    >>> errata_url("RHSA-2011:1073")
    'http://rhn.redhat.com/errata/RHSA-2011-1073.html'
    >>> errata_url("RHSA-2007:0967-2")
    'http://rhn.redhat.com/errata/RHSA-2007-0967.html'
    """
    assert isinstance(advisory, str), "Not a string: %s" % str(advisory)
    assert _RHERRATA_RE.match(advisory), "Not a errata advisory: %s" % advisory

    if advisory[-2] == "-":  # degenerate advisory names
        advisory = advisory[:-2]

    return "http://rhn.redhat.com/errata/%s.html" % advisory.replace(':', '-')


def rpm_transactionset(root='/', readonly=True):
    """
    Return rpm.TransactionSet object.

    :param root: RPM DB root dir
    :param readonly: Return read-only transaction set to pure query purpose

    :return: An instance of rpm.TransactionSet
    """
    if not root.startswith('/'):
        root = os.path.abspath(root)

    trs = rpm.TransactionSet(root)

    if readonly:
        # pylint: disable=protected-access
        # see also: rpmUtils/transaction.py:initReadOnlyTransaction()
        trs.setVSFlags((rpm._RPMVSF_NOSIGNATURES | rpm._RPMVSF_NODIGESTS))
        # pylint: enable=protected-access

    return trs


def guess_rhel_version_simple(root):
    """
    Guess RHEL major version from RPM database. It's similar to the above
    :function:`guess_rhel_version` but does not process RHEL 3 cases.

    - RHEL 4 => rpm.RPMTAG_RPMVERSION = '4.3.3'
    - RHEL 5 => rpm.RPMTAG_RPMVERSION = '4.4.2' or '4.4.2.3'
    - RHEL 6 => rpm.RPMTAG_RPMVERSION >= '4.7.0-rc1'
    - RHEL 7 => rpm.RPMTAG_RPMVERSION >= '4.11.1'

    :param root: RPM DB root dir
    :param maybe_rhel_4:
    """
    trs = rpm_transactionset(root, True)
    # pylint: disable=no-member
    rpmver = [h for h in trs.dbMatch()][0][rpm.RPMTAG_RPMVERSION]
    # pylint: enable=no-member
    del trs

    irpmver = int(''.join(rpmver.split('.')[:4])[:4])

    if irpmver in (433, 432, 431):
        osver = 4
    elif irpmver == 442:
        osver = 5
    elif irpmver >= 470 and irpmver < 4110:
        osver = 6
    elif irpmver >= 4110:
        osver = 7
    else:
        osver = 0

    return osver


def guess_rhel_repos(root, with_extras=False):
    """
    Guess RHEL yum repo IDs.

    :param root: RPM DB root dir may be in relative path
    :param with_extras: Include extra yum repos if True
    :return: A list of yum repos
    """
    rhelver = guess_rhel_version_simple(root)
    assert rhelver in (5, 6, 7), "Not supported RHEL version: %d" % rhelver

    if rhelver == 5:
        # Yum repos for RHEL 5, requires RHN Classic registration:
        repos = ["rhel-x86_64-server-5", ]
        if with_extras:
            repos += ["rhel-x86_64-server-cluster-5",
                      "rhel-x86_64-server-cluster-storage-5",
                      "rhel-x86_64-server-productivity-5",
                      "rhel-x86_64-server-supplementary-5"]
    elif rhelver == 6:
        # Yum repos for RHEL 6, requires RHN Classic registration:
        repos = ["rhel-x86_64-server-6",
                 "rhel-x86_64-server-optional-6"]
        if with_extras:
            repos += ["rhel-x86_64-server-ha-6",
                      "rhel-x86_64-server-rs-6",
                      "rhel-x86_64-server-sfs-6",
                      "rhel-x86_64-server-supplementary-6"]
    else:
        # RHN yum repos:
        repos = ["rhel-7-server-rpms",
                 "rhel-7-server-optional-rpms"]
        if with_extras:
            repos += ["rhel-7-server-rh-common-rpms",
                      "rhel-7-server-extras-rpms",
                      "rhel-ha-for-rhel-7-server-rpms",
                      "rhel-rs-for-rhel-7-server-rpms",
                      "rhel-7-server-supplementary-rpms"]
    return repos

# vim:sw=4:ts=4:et:
