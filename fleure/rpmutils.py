#
# Copyright (C) 2014 - 2017 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato@redhat.com>
#
# This software is licensed to you under the GNU General Public License,
# version 3 (GPLv3). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. You should have received a copy of GPLv3 along with this
# software; if not, see http://www.gnu.org/licenses/gpl.html
#
# pylint: disable=no-member
"""
Misc RPM/Yum related utility routines for fleure.
"""
from __future__ import absolute_import

import logging
import operator
import os.path
import os
import re
import rpm

try:
    import bsddb
except ImportError:
    bsddb = None

import fleure.globals
import fleure.decorators
import fleure.utils

from fleure.globals import _


LOG = logging.getLogger(__name__)

_RHERRATA_RE = re.compile(r"^RH[SBE]A-\d{4}[:-]\d{4,5}(?:-\d+)?$")
_PKG_KEY_FN = operator.itemgetter("name", "version", "release")


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
        LOG.warning(_("Not a Berkley DB?: %s"), dbpath)
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
        LOG.error(_("RPM DB dir %s does not exist!"), rpmdbdir)
        return False

    pkgdb = os.path.join(rpmdbdir, "Packages")
    if not _is_bsd_hashdb(pkgdb):
        LOG.error(_("%s does not look a RPM DB (Packages) file!"), pkgdb)
        return False

    for dbn in dbnames:
        dbpath = os.path.join(rpmdbdir, dbn)

        if not os.path.exists(dbpath):
            # NOTE: It's not an error at once.
            LOG.info(_("RPM DB %s looks missing"), dbn)

        if readonly and os.access(dbpath, os.W_OK) and not system:
            os.chmod(dbpath, 0o444)

    return True


def _compare_evr(evr1, evr2):
    """Stolen from yum (rpmUtils.miscutils.compareEVR) (yum: GPLv2+).

    :param evr1: A tuple of (Epoch, Version, Release)
    :param evr2: Likewise
    :return:
        1 if evr1 is newer than evr2, 0 if these are same version and -1 if
        evr2 is newer than evr1.
    """
    epoch1 = '0' if evr1[0] is None else str(evr1[0])
    epoch2 = '0' if evr2[0] is None else str(evr2[0])

    return rpm.labelCompare((epoch1, str(evr1[1]), str(evr1[2])),
                            (epoch2, str(evr2[1]), str(evr2[2])))


def pcmp(lhs, rhs):
    """
    Compare packages by these NVRAEs.

    :param lhs, rhs: dict(name, version, release, epoch, arch)

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
    return _compare_evr(p2evr(lhs), p2evr(rhs))


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


def rpm_transactionset(root=None, readonly=True):
    """
    Return rpm.TransactionSet object.

    :param root: RPM DB root dir
    :param readonly: Return read-only transaction set to pure query purpose

    :return: An instance of rpm.TransactionSet
    """
    if root is None:
        root = '/'
    elif not root.startswith('/'):
        root = os.path.abspath(root)

    trs = rpm.TransactionSet(root)

    if readonly:
        # pylint: disable=protected-access
        # see also: rpmUtils/transaction.py:initReadOnlyTransaction()
        trs.setVSFlags((rpm._RPMVSF_NOSIGNATURES | rpm._RPMVSF_NODIGESTS))
        # pylint: enable=protected-access

    return trs


def _normalize_val_from_rpmh(val):
    """Normalize the value gotten from RPM DB headers.
    """
    if isinstance(val, bytes):
        return val.decode('utf-8')

    return val


def rpm_search(root=None, key_val=None, pred=None,
               keys=fleure.globals.RPM_KEYS):
    """
    :param root: RPM DB root dir
    :param key_val:
        A tuple of key and value to search RPMs for, e.g. ("name", "kernel")
    :param pred: A callable to select resutls ( :: hdr -> bool)
    :param keys: Tag names, e.g. ("name", "version", "epoch", "release")

    :return: A list of packages :: [dict]
    """
    rts = rpm_transactionset(root)
    dbi = rts.dbMatch() if key_val is None else rts.dbMatch(*key_val)

    if callable(pred):
        hdrs = (h for h in dbi if pred(h))
    else:
        hdrs = (h for h in dbi)

    res = [dict(zip(keys, [_normalize_val_from_rpmh(h[k]) for k in keys]))
           for h in hdrs]
    del rts

    return res


def rpm_resolve_reqs(subject, root=None, keys=fleure.globals.RPM_KEYS):
    """Find a list of packages providing `subject`

    :param subject: A str maybe a package name, filename or provide name
    :param root: RPM DB root dir
    :param keys: RPM Package dict keys
    """
    subject = subject.decode('utf-8')
    if subject.startswith('/'):  # filename
        key = "basenames"
    elif '(' in subject:  # provide name
        key = "provides"
    else:
        key = "name"

    return rpm_search(root, key_val=(key, subject), keys=keys)


def rpm_find_reqs(pkg, root=None, keys=fleure.globals.RPM_KEYS):
    """
    Find a list of requirements resolved to packages.

    :param pkg: A dict represents a package that must have key "requires"
    :param root: RPM DB root dir
    :param keys: RPM Package dict keys
    """
    _find = fleure.decorators.memoize(rpm_resolve_reqs)
    return fleure.utils.uconcat((_find(x) for x in pkg["requires"]),
                                key=_PKG_KEY_FN)


def _find_reqd(root, req, keys):
    """Find a list of packages requiring `req`.
    """
    return rpm_search(root, ("requires", req), keys)


find_reqd = fleure.decorators.memoize(_find_reqd)


def rpm_find_reqd(pkg, root=None, keys=fleure.globals.RPM_KEYS):
    """
    Find a list of packages requiring given package `pkg`. This is a 'reversed'
    version of :func:`rpm_find_reqs`.

    :param pkg:
        A dict represents a package that must have keys, "name", "provides" and
        "filenames".
    :param root: RPM DB root dir
    :param keys: RPM Package dict keys
    """
    return fleure.utils.uconcat((find_reqd(root, p, keys) for p
                                 in pkg["provides"]), key=_PKG_KEY_FN)


def _filter_out_self(pkg, pkgs):
    """Fitler out `pkg` from `pkgs`
    """
    return [x for x in pkgs if x["name"] != pkg["name"]]


def list_installed_rpms_itr(root=None):
    """
    List installed RPMs :: [dict]

    :param root: Root dir of RPM DBs.
    :return: A list of packages :: [dict]

    >>> list_installed_rpms()  # doctest: +ELLIPSIS
    [{...}, ...]
    """
    keys = list(fleure.globals.RPM_KEYS) + ["requires", "provides"]
    ips = rpm_search(root, keys=keys)
    for pkg in ips:
        pkg["requires"] = _filter_out_self(pkg, rpm_find_reqs(pkg, root))
        pkg["required"] = _filter_out_self(pkg, rpm_find_reqd(pkg, root))

        if pkg["name"] == "gpg-pubkey":
            continue

        yield pkg


def list_installed_rpms(root=None, keys=fleure.globals.RPM_KEYS,
                        resolv=False):
    """
    List installed RPMs :: [dict]

    :param root: Root dir of RPM DBs.
    :param keys: RPM Package dict keys
    :param resolv: Resolve dependencies also if True

    :return: A list of packages :: [dict]

    >>> list_installed_rpms()  # doctest: +ELLIPSIS
    [{...}, ...]
    """
    if not resolv:
        return rpm_search(root, keys=keys)

    return list(list_installed_rpms_itr(root=root))


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
    rts = rpm_transactionset(root)
    rpmver = [h for h in rts.dbMatch()][0][rpm.RPMTAG_RPMVERSION]
    del rts

    irpmver = int(''.join(rpmver.decode('utf-8').split('.')[:4])[:4])

    if irpmver in (433, 432, 431):
        osver = 4
    elif irpmver == 442:
        osver = 5
    elif 470 <= irpmver < 4110:
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
