'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		decorators.py
  > Created Time:	2016-12-18 Sun 12:17
'''''''''''''''''''''''''''''''''''''''''''''''''''

import functools
from .models import Permission
import flask_login
import flask

def permission_required(permission):
    def decorator(f):
        @functools.wraps(f)
        def decorated_func(*args, **kwargs):
            if not flask_login.current_user.can(permission):
                flask.abort(403)
            return f(*args, **kwargs)
        return decorated_func
    return decorator

admin_required = permission_required(Permission.ADMINISTER)
moderate_required = permission_required(Permission.MODERATE_COMMENTS)
