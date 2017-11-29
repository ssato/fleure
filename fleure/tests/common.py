#
# Copyright (C) 2011 - 2017 Satoru SATOH <ssato at redhat.com>
#
# pylint: disable=missing-docstring
from __future__ import absolute_import

import os.path
import os
import shutil
import sys
import tempfile
import unittest

import fleure.globals


IS_PYTHON_3 = sys.version_info[0] == 3
CNF_0 = dict(name="a", a=1, b=dict(b=[1, 2], c="C"))
SCM_0 = {"type": "object",
         "properties": {
             "name": {"type": "string"},
             "a": {"type": "integer"},
             "b": {"type": "object",
                   "properties": {
                       "b": {"type": "array",
                             "items": {"type": "integer"}}}}}}


def selfdir():
    """
    >>> os.path.exists(selfdir())
    True
    """
    return os.path.dirname(__file__)


def setup_workdir():
    """
    >>> workdir = setup_workdir()
    >>> assert workdir != '.'
    >>> assert workdir != '/'
    >>> os.path.exists(workdir)
    True
    >>> os.rmdir(workdir)
    """
    return tempfile.mkdtemp(dir="/tmp", prefix="python-fleure-tests-")


def cleanup_workdir(workdir):
    """
    FIXME: Danger!

    >>> workdir = setup_workdir()
    >>> os.path.exists(workdir)
    True
    >>> open(os.path.join(workdir, "workdir.stamp"), 'w').write("OK!\n")
    >>> cleanup_workdir(workdir)
    >>> os.path.exists(workdir)
    False
    """
    assert workdir != '/'
    assert workdir != '.'

    os.system("rm -rf " + workdir)


def skip_if_not(pred=True):
    """A decorator to skip test if `pred` is False.
    """
    def wrapper(fnc):
        """Skip test; see nose.tools.nontrivial.nottest.
        """
        fnc.__test__ = pred
        return fnc
    return wrapper


def copy_rpmdb_files(workdir):
    """Copy some RPM DB files into workdir for tests.
    """
    rpmdbdir = os.path.join(workdir, fleure.globals.RPMDB_SUBDIR)
    os.makedirs(rpmdbdir)

    for dbn in fleure.globals.RPMDB_FILENAMES:
        src = os.path.join('/', fleure.globals.RPMDB_SUBDIR, dbn)
        if os.path.exists(src):
            shutil.copy(src, rpmdbdir)


def dicts_equal(lhs, rhs):
    """
    >>> dicts_equal({}, {})
    True
    >>> dicts_equal({}, {'a': 1})
    False
    >>> d0 = {'a': 1}; dicts_equal(d0, d0)
    True
    >>> d1 = {'a': [1, 2, 3]}; dicts_equal(d1, d1)
    True
    >>> dicts_equal(d0, d1)
    False
    """
    if len(lhs.keys()) != len(rhs.keys()):
        return False

    for key, val in rhs.items():
        val_ref = lhs.get(key, None)
        if val != val_ref:
            return False

    return True


def to_bytes(astr):
    """
    Convert a string to bytes. Do nothing in python 2.6.
    """
    return bytes(astr, 'utf-8') if IS_PYTHON_3 else astr


def is_rhel_or_fedora(relfile="/etc/redhat-release"):
    return os.path.exists(relfile)


class Chdir(object):

    def __init__(self, chdir=None):
        self.orgdir = os.path.abspath(os.curdir)
        self.chdir = self.orgdir if chdir is None else chdir
        self.need_chdir = self.orgdir != self.chdir

    def __enter__(self, *args):
        if self.need_chdir:
            os.chdir(self.chdir)

    def __exit__(self, *args):
        if self.need_chdir:
            os.chdir(self.orgdir)


class TestsWithWorkdir(unittest.TestCase):

    def setUp(self):
        self.workdir = setup_workdir()

    def tearDown(self):
        cleanup_workdir(self.workdir)


class TestsWithRpmDB(TestsWithWorkdir):

    def setUp(self):
        super(TestsWithRpmDB, self).setUp()
        copy_rpmdb_files(self.workdir)

# vim:sw=4:ts=4:et:
