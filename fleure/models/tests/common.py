#
# Copyright (C) 2016 Satoru SATOH <ssato at redhat.com>
# License: MIT
#
# pylint: disable=missing-docstring,invalid-name,no-member
from __future__ import absolute_import

import sqlalchemy
import unittest

from sqlalchemy.orm import scoped_session, sessionmaker
from .. import base as TT


class TestsWithSession(unittest.TestCase):

    def setUp(self):
        # For further debug:
        # self.engine = sqlalchemy.create_engine("sqlite:////tmp/test.db")
        self.engine = sqlalchemy.create_engine("sqlite:///:memory:")
        self.session = scoped_session(sessionmaker(bind=self.engine))

        TT.Base.query = self.session.query_property()
        TT.Base.metadata.create_all(bind=self.engine)

    def tearDown(self):
        self.session.remove()

# vim:sw=4:ts=4:et:
