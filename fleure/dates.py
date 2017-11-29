#
# Copyright (C) 2013 Satoru SATOH <ssato@redhat.com>
# Copyright (C) 2013 - 2015 Red Hat, Inc.
# License: GPLv3+
#
"""Functions to process dates (periods).
"""
from __future__ import absolute_import

import calendar
import logging
import re

import fleure.globals


LOG = logging.getLogger(__name__)


def _round_ymd(year, mon, day, roundout=False):
    """
    :param roundout: Round out given date to next year, month, day if this
        parameter is True

    >>> _round_ymd(2014, None, None, True)
    (2015, 1, 1)
    >>> _round_ymd(2014, 11, None, True)
    (2014, 12, 1)
    >>> _round_ymd(2014, 12, 24, True)
    (2014, 12, 25)
    >>> _round_ymd(2014, 12, 31, True)
    (2015, 1, 1)
    >>> _round_ymd(2014, None, None)
    (2014, 1, 1)
    >>> _round_ymd(2014, 11, None)
    (2014, 11, 1)
    >>> _round_ymd(2014, 12, 24)
    (2014, 12, 24)
    """
    if mon is None:
        return (year + 1 if roundout else year, 1, 1)

    if day is None:
        if roundout:
            return (year + 1, 1, 1) if mon == 12 else (year, mon + 1, 1)

        return (year, mon, 1)
    else:
        if roundout:
            last_day = calendar.monthrange(year, mon)[1]
            if day == last_day:
                return (year + 1, 1, 1) if mon == 12 else (year, mon + 1, 1)

            return (year, mon, day + 1)

    return (year, mon, day)


def _d2i(dtpl):
    """
    Convert date tuple (YYYY, MM, DD) to an int for later comparison.

    >>> _d2i((2014, 10, 1))
    20141001
    """
    return dtpl[0] * 10000 + dtpl[1] * 100 + dtpl[2]


def _ymd_to_date(ymd, roundout=False):
    """
    :param ymd: Date string in YYYY[-MM[-DD]]
    :param roundout: Round out to next year, month if True and day was not
        given; ex. '2014' -> (2015, 1, 1), '2014-11' -> (2014, 12, 1)
        '2014-12-24' -> (2014, 12, 25), '2014-12-31' -> (2015, 1, 1) if True
        and '2014' -> (2014, 1, 1), '2014-11' -> (2014, 11, 1) if False.
    :param datereg: Date string regex

    :return: A tuple of (year, month, day) :: (int, int, int)

    >>> _ymd_to_date('2014-12-24')
    (2014, 12, 24)
    >>> _ymd_to_date('2014-12')
    (2014, 12, 1)
    >>> _ymd_to_date('2014')
    (2014, 1, 1)
    >>> _ymd_to_date('2014-12-24', True)
    (2014, 12, 25)
    >>> _ymd_to_date('2014-12-31', True)
    (2015, 1, 1)
    >>> _ymd_to_date('2014-12', True)
    (2015, 1, 1)
    >>> _ymd_to_date('2014', True)
    (2015, 1, 1)
    """
    match = re.match(r"^(\d{4})(?:.(\d{2})(?:.(\d{2}))?)?$", ymd)
    if not match:
        LOG.error("Invalid input for normalize_date(): %s", ymd)

    dic = match.groups()
    int_ = lambda x: x if x is None else int(x)
    return _round_ymd(int(dic[0]), int_(dic[1]), int_(dic[2]), roundout)


def _to_date(date_s):
    """
    .. note::
       Errata issue_date and update_date format: month/day/year, e.g. 12/16/10.

    >>> _to_date("12/16/10")
    (2010, 12, 16)
    >>> _to_date("2014-10-14 00:00:00")
    (2014, 10, 14)
    """
    if '-' in date_s:
        return tuple(int(x) for x in date_s.split()[0].split('-'))

    (month, day, year) = date_s.split('/')
    return (int("20" + year), int(month), int(day))


def period_to_dates(start_date, end_date=fleure.globals.TODAY):
    """
    :param period: Period of errata in format of YYYY[-MM[-DD]],
        ex. ("2014-10-01", "2014-11-01")

    >>> today = _d2i(_ymd_to_date(fleure.globals.TODAY, True))
    >>> (20141001, today) == period_to_dates("2014-10-01")
    True
    >>> period_to_dates("2014-10-01", "2014-12-31")
    (20141001, 20150101)
    """
    return (_d2i(_ymd_to_date(start_date)), _d2i(_ymd_to_date(end_date, True)))


def in_period(date_s, start_date, end_date):
    """
    :param date_s: date string such as "12/16/10", "2014-10-14 00:00:00"
    :param start_date, end_date: Start and end date of period, YYYYMMDD

    :return: True if given date (:: str) in the period (start_date .. end_date)

    >>> in_period("12/16/10", 20101010, 20110101)
    True
    >>> in_period("2014-10-14 00:00:00", 20101010, 20140201)
    False
    """
    date_i = _d2i(_to_date(date_s))
    return start_date <= date_i and date_i < end_date

# vim:sw=4:ts=4:et:
