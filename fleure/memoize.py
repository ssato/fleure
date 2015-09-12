#
# Copyright (C) 2012 - 2015 Satoru SATOH <satoru.satoh@gmail.com>
# License: GPLv3+
#
"""Memoize module
"""


def memoize(fnc):
    """memoization decorator.
    """
    assert callable(fnc), "Given object is not callable!: " + repr(fnc)
    cache = {}

    def wrapped(*args, **kwargs):
        """Wrapper function.
        """
        key = repr(args) + repr(kwargs)
        if key not in cache:
            cache[key] = fnc(*args, **kwargs)

        return cache[key]

    wrapped.__doc__ = fnc.__doc__
    return wrapped

# vim:sw=4:ts=4:et:
