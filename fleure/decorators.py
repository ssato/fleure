#
# Copyright (C) 2015 Satoru SATOH <ssato@redhat.com>
# License: GPLv3+
#
"""Misc decorators
"""
from __future__ import absolute_import

import functools
import inspect
import multiprocessing


def _make_ref_to_original(fnc):
    """
    Make up a reference to original function `fnc` to decorate, in its module.

    :param fnc: Function to decorate
    """
    assert callable(fnc), "Given object is not callable!: " + repr(fnc)
    setattr(inspect.getmodule(fnc), fnc.__name__ + "_original", fnc)


def noop(fnc):
    """A decorator does nothing (no-operation).
    """
    _make_ref_to_original(fnc)

    @functools.wraps(fnc)
    def decorated(*args, **kwargs):
        """Decorated one"""
        return fnc(*args, **kwargs)

    return decorated


def memoize(fnc):
    """memoization decorator.
    """
    _make_ref_to_original(fnc)
    cache = {}

    @functools.wraps(fnc)
    def decorated(*args, **kwargs):
        """Decorated one"""
        key = repr(args) + repr(kwargs)
        if key not in cache:
            cache[key] = fnc(*args, **kwargs)

        return cache[key]

    return decorated


def async(fnc):
    """
    A decorator to run :func:`fnc` asynchronously with help of multiprocessing
    module, originally from http://bit.ly/1KKBJZ2 .

    .. note::
       async.pool must be initialized to multiprocessing.pool.Pool object by
       call the function :func:`multiprocessing.Pool`.

    :param fnc: Target function to run asynchronously
    """
    _make_ref_to_original(fnc)

    # pylint: disable=no-member
    @functools.wraps(fnc)
    def decorated(*args, **kwargs):
        """Decorated one"""
        assert isinstance(async.pool, multiprocessing.pool.Pool)
        return async.pool.apply_async(fnc, args, kwargs)

    return decorated

# vim:sw=4:ts=4:et:
