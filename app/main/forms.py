'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		forms.py
  > Created Time:	2016-12-14 Wed 21:00
'''''''''''''''''''''''''''''''''''''''''''''''''''

import flask_wtf
import wtforms
from wtforms import validators

class LoginForm(flask_wtf.FlaskForm):
    name = wtforms.StringField('Input your name',
            validators=[validators.Required()])
    password = wtforms.PasswordField('Input your password',
            validators=[validators.Required()])
    submit = wtforms.SubmitField('Submit')
