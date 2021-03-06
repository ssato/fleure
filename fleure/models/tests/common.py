#
# Copyright (C) 2016, 2017 Satoru SATOH <ssato at redhat.com>
# License: MIT
#
# pylint: disable=missing-docstring,invalid-name,no-member
from __future__ import absolute_import

import unittest
import sqlalchemy

from sqlalchemy.orm import scoped_session, sessionmaker
from .. import base as TT


class TestsWithSession(unittest.TestCase):

    def setUp(self):
        # For further debug:
        # self.engine = sqlalchemy.create_engine("sqlite:////tmp/test.db")
        self.engine = sqlalchemy.create_engine("sqlite://")
        self.session = scoped_session(sessionmaker(bind=self.engine))

        TT.Base.query = self.session.query_property()
        TT.Base.metadata.create_all(bind=self.engine)

    def tearDown(self):
        TT.Base.metadata.drop_all(bind=self.engine)
        self.session.remove()
        self.session.close()

# vim:sw=4:ts=4:et:
