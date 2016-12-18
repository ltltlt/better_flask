'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		test_models.py
  > Created Time:	2016-12-15 Thu 17:15
'''''''''''''''''''''''''''''''''''''''''''''''''''

import unittest
from app.models import User

class ModelTest(unittest.TestCase):
    def test_password_setter(self):
        u = User(password='cat')
        self.assertTrue(u.password_hash is not None)
    def test_no_password_getter(self):
        with self.assertRaises(AttributeError):
            u = User(password='cat')
            u.password
    def test_password_verification(self):
        u = User(password='cat')
        self.assertTrue(u.verify_password('cat'))
        self.assertFalse(u.verify_password('dog'))
    def test_password_salts_are_random(self):
        u = User(password='cat')
        d = User(password='cat')
        self.assertNotEqual(u.password_hash, d.password_hash)
