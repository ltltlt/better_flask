'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		test_user_model.py
  > Created Time:	2016-12-18 Sun 12:57
'''''''''''''''''''''''''''''''''''''''''''''''''''

import unittest
from app.models import User, Permission, AnonymousUser

class UserModelTestCase(unittest.TestCase):
    def test_roles_and_permissions(self):
        u = User(email='196789@qq.com')
        self.assertTrue(u.can(Permission.COMMIT))
        self.assertTrue(u.can(Permission.FOLLOW))
        self.assertTrue(u.can(Permission.WRITE_ARTICLES))
        self.assertFalse(u.can(Permission.ADMINISTER))
        self.assertFalse(u.can(Permission.MODERATE_COMMENTS))
    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.COMMIT))
        self.assertFalse(u.can(Permission.FOLLOW))
        self.assertFalse(u.can(Permission.WRITE_ARTICLES))
        self.assertFalse(u.can(Permission.ADMINISTER))
        self.assertFalse(u.can(Permission.MODERATE_COMMENTS))
