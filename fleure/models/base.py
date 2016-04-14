#
# Copyright (C) 2016 Satoru SATOH <ssato redhat.com>
# License: GPLv3+
#
"""Models' base.
"""
from __future__ import absolute_import
import sqlalchemy.ext.declarative


Base = sqlalchemy.ext.declarative.declarative_base()

# vim:sw=4:ts=4:et:
