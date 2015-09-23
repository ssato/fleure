#
# Copyright (C) 2012 - 2015 Red Hat, Inc.
# Red Hat Author(s): Satoru SATOH <ssato redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""Globals.
"""
from __future__ import absolute_import

import datetime
import gettext
import logging
import os.path


PACKAGE = "fleure"

FLEURE_SYSCONFDIR = "/etc/%s" % PACKAGE
FLEURE_DATADIR = "/usr/share/%s" % PACKAGE
FLEURE_TEMPLATE_PATHS = [os.path.join(FLEURE_DATADIR, "templates/2/%s") % lang
                         for lang in ("ja", "en")]

RPM_VENDOR = "redhat"
RPM_KEYS = ("name", "epoch", "version", "release", "arch")
ERRATA_KEYWORDS = ("crash", "panic", "hang", "SEGV", "segmentation fault",
                   "data corruption")
CORE_RPMS = ("kernel", "glibc", "bash", "openssl", "zlib")
DEFAULT_CVSS_SCORE = 4.0

TODAY = datetime.datetime.now().strftime("%F")

LOGGING_FORMAT = "%(asctime)s %(name)s: [%(levelname)s] %(message)s"


def get_logger(name=PACKAGE, fmt=LOGGING_FORMAT, level=logging.WARN):
    """
    Initialize custom logger.
    """
    logging.basicConfig(level=level, format=fmt)
    logger = logging.getLogger(name)

    hdlr = logging.StreamHandler()
    hdlr.setLevel(level)
    hdlr.setFormatter(logging.Formatter(format))
    logger.addHandler(hdlr)

    return logger


LOGGER = get_logger()

_ = gettext.translation(domain=PACKAGE,
                        localedir=os.path.join(os.path.dirname(__file__),
                                               "locale"),
                        fallback=True).ugettext


def rpm_list_path(workdir, filename="packages.json"):
    """
    :param workdir: Working dir to dump the result
    :param filename: Output file basename
    """
    return os.path.join(workdir, filename)


def errata_list_path(workdir, filename="errata.json"):
    """
    :param workdir: Working dir to dump the result
    :param filename: Output file basename
    """
    return os.path.join(workdir, filename)


def updates_list_path(workdir, filename="updates.json"):
    """
    :param workdir: Working dir to dump the result
    """
    return os.path.join(workdir, filename)

# vim:sw=4:ts=4:et:
