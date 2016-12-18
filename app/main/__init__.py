'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		__init__.py
  > Created Time:	2016-12-14 Wed 09:51
'''''''''''''''''''''''''''''''''''''''''''''''''''

import flask

main = flask.Blueprint('main', __name__)

from . import views, errors
