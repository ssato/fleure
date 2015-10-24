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

import codecs
import itertools
import json
import logging
import operator
import os.path
import os
import re
import rpm
import subprocess
import yum

try:
    import bsddb
except ImportError:
    bsddb = None

# from fleure.decorators import async  # TBD
import fleure.globals


LOG = logging.getLogger(__name__)

_RHERRATA_RE = re.compile(r"^RH[SBE]A-\d{4}[:-]\d{4}(?:-\d+)?$")


def concat(xss):
    """
    Concatenates a list of lists.

    >>> concat([[]])
    []
    >>> concat((()))
    []
    >>> concat([[1,2,3],[4,5]])
    [1, 2, 3, 4, 5]
    >>> concat([[1,2,3],[4,5,[6,7]]])
    [1, 2, 3, 4, 5, [6, 7]]
    >>> concat(((1,2,3),(4,5,[6,7])))
    [1, 2, 3, 4, 5, [6, 7]]
    >>> concat(((1,2,3),(4,5,[6,7])))
    [1, 2, 3, 4, 5, [6, 7]]
    >>> concat((i, i*2) for i in range(3))
    [0, 0, 1, 2, 2, 4]
    """
    return list(itertools.chain.from_iterable(xs for xs in xss))


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


def uconcat(xss, **uniq_options):
    """uniq + concat
    """
    return uniq(concat(xss), **uniq_options)


def copen(path, flag='r', encoding="utf-8"):
    """An wrapper of codecs.open
    """
    return codecs.open(path, flag, encoding)


def json_load(filepath, encoding="utf-8"):
    """
    Load ``filepath`` in JSON format and return data.

    :param filepath: Output file path
    """
    return json.load(copen(filepath, encoding=encoding))


def json_dump(data, filepath):
    """
    Dump given ``data`` into ``filepath`` in JSON format.

    :param data: Data to dump
    :param filepath: Output file path
    """
    json.dump(data, copen(filepath, 'w'))


def all_eq(iterable):
    """
    :param iterable: An iterable object such as a list, generator, etc.
    :return: True if all items in iterable `iterable` equals each other.

    >>> all_eq([])
    False
    >>> all_eq(["a", "a", "a"])
    True
    >>> all_eq(c for c in "")
    False
    >>> all_eq(c for c in "aaba")
    False
    >>> all_eq(c for c in "aaaa")
    True
    >>> all_eq([c for c in "aaaa"])
    True
    """
    if not isinstance(iterable, list):
        iterable = list(iterable)  # iterable may be a generator...

    return all(x == iterable[0] for x in iterable[1:]) if iterable else False


def longest_common_prefix(*args):
    """
    Variant of LCS = Longest Common Sub-sequence. For LCS, see
    http://en.wikipedia.org/wiki/Longest_common_substring_problem

    >>> longest_common_prefix("abc", "ab", "abcd")
    'ab'
    >>> longest_common_prefix("abc", "bc")
    ''
    """
    return ''.join(x[0] for x
                   in itertools.takewhile(all_eq, itertools.izip(*args)))


# @fleure.decorators.async (TBD)
def subproc_call(cmd_s, cwd=os.curdir, timeout=None, **kwargs):
    """
    :func:`subprocess.Popen.communicate` + :func:`subprocess.check_call`.

    :param cmd_s: Command string to run
    :param cwd: Dir in which cd to run command
    :param timeout: Timeout to expect command finishes in seconds
    :param kwargs: Keyword arguments passed to subprocess.Popen
    """
    rcode = -1
    if timeout is not None:
        cmd_s = "timeout %d %s" % (timeout, cmd_s)
    try:
        proc = subprocess.Popen(cmd_s, shell=True, cwd=cwd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rcode = proc.wait()
        (out, err) = proc.communicate()
        return (rcode, out, err)

    except subprocess.CalledProcessError as exc:
        return (rcode, None, str(exc))


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


def check_rpmdb_root(root, readonly=True, system=False,
                     dbnames=fleure.globals.RPMDB_FILENAMES):
    """
    :param root: The pivot root directry where target's RPM DB files exist
    :param readonly: Ensure RPM DB files readonly
    :param system: Allow accessing system RPM DB in /var/lib/rpm
    :return: True if necessary setup was done w/ success else False
    """
    if system:
        readonly = True
    else:
        assert root != "/", "Do not run this for host system's RPM DB!"

    rpmdbdir = os.path.join(root, fleure.globals.RPMDB_SUBDIR)

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

        if readonly and os.access(dbpath, os.W_OK) and not system:
            os.chmod(dbpath, 0o444)

    return True


def pcmp(lhs, rhs):
    """
    Compare packages by these NVRAEs.

    :param lhs, rhs: dict(name, version, release, epoch, arch)

    :note: It does not utilize rpm.versionCompare even if yum is not available.

    >>> lhs = dict(name="gpg-pubkey", version="00a4d52b", release="4cb9dd70",
    ...           arch="noarch", epoch=0,
    ... )
    >>> rhs = dict(name="gpg-pubkey", version="069c8460", release="4d5067bf",
    ...           arch="noarch", epoch=0,
    ... )
    >>> pcmp(lhs, lhs) == 0
    True
    >>> pcmp(lhs, rhs) < 0
    True

    >>> p3 = dict(name="kernel", version="2.6.38.8", release="32",
    ...           arch="x86_64", epoch=0,
    ... )
    >>> p4 = dict(name="kernel", version="2.6.38.8", release="35",
    ...           arch="x86_64", epoch=0,
    ... )
    >>> pcmp(p3, p4) < 0
    True

    >>> p5 = dict(name="rsync", version="2.6.8", release="3.1",
    ...           arch="x86_64", epoch=0,
    ... )
    >>> p6 = dict(name="rsync", version="3.0.6", release="4.el5",
    ...           arch="x86_64", epoch=0,
    ... )
    >>> pcmp(p3, p4) < 0
    True
    """
    p2evr = operator.itemgetter("epoch", "version", "release")

    assert lhs["name"] == rhs["name"], "Trying to compare different packages!"
    return yum.compareEVR(p2evr(lhs), p2evr(rhs))


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


def guess_rhel_repos(root=None, rhelver=None, repos_map=None,
                     with_extras=False):
    """
    Guess RHEL yum repo IDs.

    :param root: RPM DB root dir may be in relative path
    :param rhelver: RHEL version or None to determine it automatically
    :param repos_map: A map of dist name and yum repos
    :param with_extras: Include extra yum repos if True

    :return: A list of yum repos or []

    >>> rmap = dict(rhel_5=["aaa"], rhel_6=["bbb"], rhel_6_extras=["ccc"])
    >>> guess_rhel_repos(rhelver=6, repos_map=rmap)
    ['bbb']
    >>> guess_rhel_repos(rhelver=6, repos_map=rmap, with_extras=True)
    ['bbb', 'ccc']
    """
    if root is None:
        assert rhelver is not None, "root or rhelver must be given!"
        assert isinstance(rhelver, int), \
            "rhelver must be a int!: %s" % str(rhelver)
    else:
        if rhelver is None:
            rhelver = guess_rhel_version_simple(root)
        else:
            assert isinstance(rhelver, int), \
                "rhelver must be a int!: %s" % str(rhelver)
        assert rhelver in (5, 6, 7), "Not supported RHEL version: %d" % rhelver

    if repos_map is None:
        repos_map = fleure.globals.REPOS_MAP

    dist = "rhel_%d" % rhelver
    repos = repos_map.get(dist, [])

    if with_extras:
        repos += repos_map.get(dist + "_extras", [])

    return repos

# vim:sw=4:ts=4:et:
