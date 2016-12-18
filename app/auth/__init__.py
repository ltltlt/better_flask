'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		__init__.py
  > Created Time:	2016-12-15 Thu 17:35
'''''''''''''''''''''''''''''''''''''''''''''''''''

import flask

auth = flask.Blueprint('auth', __name__)

from . import views
