'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		errors.py
  > Created Time:	2016-12-14 Wed 09:52
'''''''''''''''''''''''''''''''''''''''''''''''''''

import flask
from . import main as main_blueprint

# note: shouldn't use errorhandler, 因为其只会注册蓝本的错误处理程序，
# 不会作用在app上，所以要用app_errorhandler
@main_blueprint.app_errorhandler(404)
def page_not_found(error):
    return flask.render_template('404.html'), 404
@main_blueprint.app_errorhandler(500)
def internal_error(error):
    return flask.render_template('500.html'), 500
