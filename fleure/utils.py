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
import anyconfig.utils

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


def chaincalls(obj, *callables):
    """
    Apply `callables` to `obj` one by one.

    :param obj: Object to apply callables
    :param callables:
        callables, functions or callable classes, to apply to obj in this order

    >>> chaincalls(0, str, int, [lambda x: x + 1], None)
    1
    >>> chaincalls(0, *([lambda a: a + 1, lambda b: b + 2]))
    3
    >>> chaincalls(0)
    0
    >>> chaincalls(0, "aaa")
    Traceback (most recent call last):
    ValueError: Not callable: "'aaa'"
    """
    for fun in callables:
        if fun is None:  # Just ignore it.
            continue

        if anyconfig.utils.is_iterable(fun):
            obj = chaincalls(obj, *fun)
        else:
            if not callable(fun):
                raise ValueError("Not callable: %r" % repr(fun))
            obj = fun(obj)

    return obj


def uniq(vals, sort=True, key=None, reverse=False, callables=None):
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
    :param callables:
        callables, functions or callable classes, to apply to obj in this order

    >>> uniq([])
    []
    >>> uniq([0, 3, 1, 2, 1, 0, 4, 5])
    [0, 1, 2, 3, 4, 5]
    >>> uniq([0, 3, 1, 2, 1, 0, 4, 5], callables=(str, int))
    [0, 1, 2, 3, 4, 5]
    >>> uniq([0, 3, 1, 2, 1, 0, 4, 5], reverse=True)
    [5, 4, 3, 2, 1, 0]
    >>> uniq([0, 3, 1, 2, 1, 0, 4, 5], sort=False)
    [0, 3, 1, 2, 4, 5]
    >>> uniq((0, 3, 1, 2, 1, 0, 4, 5), sort=False)
    [0, 3, 1, 2, 4, 5]
    """
    # TBD:
    # if use_set and not callables:
    #    return sorted(set(vals), key=key, reverse=reverse)

    acc = []
    if not callable(key):
        key = None

    if key is not None:
        keyed_acc = []

    for val in vals:
        if callables:
            val = chaincalls(val, *callables)

        if key is None:
            if val in acc:
                continue
        else:
            if key(val) in keyed_acc:
                continue
            else:
                keyed_acc.append(key(val))

        acc.append(val)

    return sorted(acc, key=key, reverse=reverse) if sort else acc


def uconcat(xss, **uniq_options):
    """uniq + concat
    """
    return uniq(concat(xss), **uniq_options)


def sgroupby(items, kfn, kfn2=None):
    """
    :param items: Iterable object, e.g. a list, a tuple, etc.
    :param kfn: Key function to sort `items` and group it
    :param kfn2: Key function to sort each group in result

    :return: A generator to yield items in `items` grouped by `kf`

    >>> from operator import itemgetter
    >>> items = [(1, 2, 10), (3, 4, 2), (3, 2, 1), (1, 10, 5)]
    >>> list(sgroupby(items, itemgetter(0)))
    [[(1, 2, 10), (1, 10, 5)], [(3, 4, 2), (3, 2, 1)]]
    >>> list(sgroupby(items, itemgetter(0), itemgetter(2)))
    [[(1, 10, 5), (1, 2, 10)], [(3, 2, 1), (3, 4, 2)]]
    """
    return (list(g) if kfn2 is None else sorted(g, key=kfn2) for _k, g
            in itertools.groupby(sorted(items, key=kfn), kfn))


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
