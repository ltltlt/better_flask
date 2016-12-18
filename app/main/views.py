'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		views.py
  > Created Time:	2016-12-14 Wed 09:52
'''''''''''''''''''''''''''''''''''''''''''''''''''

from . import main
from .. import db
from . import forms
from ..models import Permission
# import forms      # i don't know why, but it's mistake
import flask
from ..models import User

@main.route('/', methods=['GET', 'POST'])
def index():
    form = forms.LoginForm()
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        password = form.password.data
        users = User.query.filter_by(username=name).all()
        if users:
            flask.session['known'] = True
        else:
            flask.session['known'] = False
            user = User(username=name, password=password)
            db.session.add(user)
        flask.session['name'] = name

        return flask.redirect(flask.url_for('.index'))
    return flask.render_template('index.html',
            form = form, name=flask.session.get('name'),
            known=flask.session.get('known'))
@main.route('/test/<tt>')
def test(tt):
    return tt

@main.app_context_processor
def inject_permissions():
    return { 'Permission':  Permission }        # let Permission can be used in template
