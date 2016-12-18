'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		test_basics.py
  > Created Time:	2016-12-15 Thu 09:22
'''''''''''''''''''''''''''''''''''''''''''''''''''

import unittest
import flask
from app import create_app, db

class BasicTest(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
    def tearDown(self):
        db.session.remove()     # call session.close() and release resource
        db.drop_all()
        self.app_context.pop()
    def test_app_exists(self):
        self.assertTrue(flask.current_app is not None)
    def test_app_is_testing(self):
        self.assertTrue(flask.current_app.config['TESTING'])
