#
# Copyright (C) 2015 Satoru SATOH <ssato@redhat.com>
# License: GPLv3+
#
"""Misc decorators
"""
from __future__ import absolute_import

import functools
import inspect


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

# vim:sw=4:ts=4:et:
