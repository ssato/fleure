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


def ref_to_original(fnc):
    """
    Reference to original function :func:`fnc`.
    """
    return fnc.__name__ + "_original"


def _make_ref_to_original(fnc):
    """
    Make up a reference to original function `fnc` to decorate, in its module.

    :param fnc: Function to decorate
    """
    if not callable(fnc):
        raise ValueError("Given object is not callable!: %r" % fnc)

    setattr(inspect.getmodule(fnc), ref_to_original(fnc), fnc)


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
        if not isinstance(async.pool, multiprocessing.pool.Pool):
            raise ValueError("async.pool is not initialized yet!")

        return async.pool.apply_async(fnc, args, kwargs)

    return decorated

# vim:sw=4:ts=4:et:
