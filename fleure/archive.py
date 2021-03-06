#
# -*- coding: utf-8 -*-
# Copyright (C) 2015 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato@redhat.com>
#
# This software is licensed to you under the GNU General Public License,
# version 3 (GPLv3). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. You should have received a copy of GPLv3 along with this
# software; if not, see http://www.gnu.org/licenses/gpl.html
#
"""
Utility functions to extract input data archives safely.
"""
from __future__ import absolute_import

import logging
import os.path
import os
import tempfile
import uuid
import zipfile

import fleure.globals
import fleure.utils

from fleure.globals import _


LOG = logging.getLogger(__name__)


def _is_link(filepath):
    """
    :param filepath: Path to a file to check
    :return: True if `filepath` is a symlink or hardlink
    """
    if os.path.islink(filepath) or os.lstat(filepath).st_nlink > 1:
        return True

    return False


def _is_bad_path(filepath, prefix=None):
    """
    Is `filepath` a bad path, that is, contains '..', starting with '/', etc?

    :param filepath: File path
    :param prefix: Prefix of file path expected to check more strictly

    >>> _is_bad_path("")
    True
    >>> _is_bad_path("var/lib/rpm/../../../etc/passwd", "var/lib/rpm")
    True
    >>> _is_bad_path("/var/lib/rpm/Packages")
    True
    >>> _is_bad_path("var/lib/rpm/Packages")
    False
    >>> _is_bad_path("var/lib/rpm/Packages", "var/lib/rpm/")
    False
    >>> _is_bad_path("/var/lib/rpm/Packages", "/var/lib/rpm")
    False
    >>> _is_bad_path("lib/rpm/Packages", "var/lib/rpm/")
    True
    """
    if not filepath:
        return True

    filepath = os.path.normpath(filepath)
    if prefix is None:
        return filepath.startswith('/')

    return not filepath.startswith(prefix)


def _remove_if_bad_file(filepath, prefix=None):
    """
    :param filepath: Absolute path to the file may be removed
    :param prefix: Expected prefix of file path
    :return: Error message or None (no need to remove it)
    """
    if not os.path.isfile(filepath):
        return None

    if _is_bad_path(filepath, prefix) or _is_link(filepath):
        os.remove(filepath)
        return "Removed as a link or refering unexpected path: " + filepath

    return None


def safe_untar(arcfile, destdir, files=None):
    """
    Extract tar archive file safely, with avoiding dir traversal attack
    attempts, for example.

    .. note::
       :mod:`tarfile` cannot be used here as it does not support tar+xz files.

    :param arcfile: Tar file path
    :param destdir: Destination dir to extract files from `arcfile` to
    :param files:
        A list of files to extract. All files looks safe will be extracted if
        it's None.

    :return: A list of error messages if something goes wrong or []
    """
    cmd_s = "tar --list -f " + arcfile
    (rcode, out, err) = fleure.utils.subproc_call(cmd_s, timeout=30)
    if rcode != 0:
        return [err or "Failed to list files in tar: %s" % arcfile]

    if files is None:
        files = [f for f in out.decode('utf-8').splitlines()
                 if not _is_bad_path(f)]

    errors = []
    for filepath in files:
        cmd_s = "tar --get -C {}/ -f {} {}".format(destdir, arcfile, filepath)
        (rcode, out, err) = fleure.utils.subproc_call(cmd_s, timeout=60)
        if rcode != 0:
            err = err or "Failed to extract from " + arcfile
            errors.append(err + ": " + filepath)
            continue

        path = os.path.join(destdir, filepath)
        err = _remove_if_bad_file(path, destdir)
        if err:
            errors.append(err)

    return errors


def safe_unzip(arcfile, destdir, files=None):
    """
    Extract zip file safely similar to :func:`safe_untar`.

    .. note::
       zipfile.extract in python 2.7+ can process untrusted zip files safely:
       https://docs.python.org/2/library/zipfile.html#zipfile.ZipFile.extract

    :param arcfile: Zip file path
    :param destdir: Destination dir to extract files from `tarfile` to
    :param files:
        A list of files to extract. All files looks safe will be extracted if
        it's None.

    :return: A list of error messages if something goes wrong or []
    """
    if files is None:
        files = []

    errors = []
    with zipfile.ZipFile(arcfile) as zipf:
        for filepath in zipf.namelist():
            if files and filepath not in files:
                LOG.info(_("Skip %s as not in the list"), filepath)
                continue

            if _is_bad_path(filepath):
                errors.append("Skip as bad path: {}".format(filepath))
                continue

            zipf.extract(filepath, path=destdir)

            path = os.path.join(destdir, filepath)
            err = _remove_if_bad_file(path, destdir)
            if err:
                errors.append(err)

    return errors


def _exract_fnc(maybe_arc_path):
    """
    :param arc_path: Archive file path or something
    :return: function to extract the archive, e.g. :func:`safe_untar`
    """
    if maybe_arc_path.endswith(".zip"):
        return safe_unzip

    # TBD: re.match(r".tar.(?:gz|bz2|xz)$", maybe_arc_path):
    return safe_untar


def extract_rpmdb_archive(arc_path, root=None):
    """Try to extract given RPM DB files archive `arc_path`.

    :param arc_path: Archive file path
    :param root:
        Path to dir to extract RPM DB files. These files will be put into
        `root`/var/lib/rpm.

    :return:
       A tuple of (root, err) where root is an absolute path of root of RPM DB
       files extracted or None, indicates extraction failed, and err is an
       error message tells what's the problem of exraction failure.
    """
    if not os.path.exists(arc_path):
        return (None, "Not found an archive: " + arc_path)

    if not os.path.isfile(arc_path):
        return (None, "Not a file: " + arc_path)

    if root is None:
        root = tempfile.mkdtemp(dir="/tmp", prefix="%s-" % __name__)
        LOG.info(_("Created a root dir of RPM DBs: %s"), root)
    else:
        root = os.path.abspath(root)  # Ensure it's an absolute path.

    rpmdbdir = os.path.join(root, fleure.globals.RPMDB_SUBDIR)
    if not os.path.exists(rpmdbdir):
        os.makedirs(rpmdbdir)

    prefix = fleure.globals.RPMDB_SUBDIR
    files = [os.path.join(prefix, fn) for fn in fleure.globals.RPMDB_FILENAMES]

    return (root, _exract_fnc(arc_path)(arc_path, root, files))


def archive_report(resultsdir, output=None,
                   filenames=fleure.globals.REPORT_FILES):
    """
    Archive analysis results (.xls files).

    :param resultsdir: Dir in which results are
    :param output: Archive filename
    :param filenames: Name of files will be archived into the output file
    """
    if output is None:
        output = "report-%s.zip" % str(uuid.uuid4())

    output = os.path.join(resultsdir, output)
    topdir = os.path.basename(resultsdir)

    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for filename in filenames:
            zipf.write(os.path.join(resultsdir, filename),
                       arcname=os.path.join(topdir, filename))

    return output

# vim:sw=4:ts=4:et:
