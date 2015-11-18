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
import os.path
import os
import subprocess

# from fleure.decorators import async  # TBD


LOG = logging.getLogger(__name__)


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


def longest_common_suffix(*args):
    """
    Like `longest_common_prefix` compute the common suffix of given strings.

    >>> longest_common_suffix("abc.tar.xz", "bcd.tar.xz", "def.tar.xz")
    '.tar.xz'
    >>> longest_common_suffix("cab", "ab", "cdab")
    'ab'
    >>> longest_common_suffix("cab", "cba")
    ''
    """
    rsfx = longest_common_prefix(*(list(reversed(x)) for x in args))
    return ''.join(reversed(rsfx))


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
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                **kwargs)
        rcode = proc.wait()
        (out, err) = proc.communicate()
        return (rcode, out, err)

    except subprocess.CalledProcessError as exc:
        return (rcode, None, str(exc))

# vim:sw=4:ts=4:et:
