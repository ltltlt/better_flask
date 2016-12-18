'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		test_generate_confirmation.py
  > Created Time:	2016-12-16 Fri 10:06
'''''''''''''''''''''''''''''''''''''''''''''''''''

import unittest
from app.models import User
import time

class Generate_Confirm(unittest.TestCase):
    def test_g(self):
        u = User(id=12345)
        s = u.generate_confirmation_token(5)
        self.assertTrue(u.confirm(s))
        
        time.sleep(5.5)
        self.assertFalse(u.confirm(s))
