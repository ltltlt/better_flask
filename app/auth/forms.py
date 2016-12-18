'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		forms.py
  > Created Time:	2016-12-15 Thu 19:33
'''''''''''''''''''''''''''''''''''''''''''''''''''

import flask_wtf
import wtforms
from wtforms import validators
from .. import models
import flask_login

class LoginForm(flask_wtf.FlaskForm):
    email = wtforms.StringField('Email', 
            validators=[validators.Required(), validators.Email(),
                validators.Length(1, 64)])
    password = wtforms.PasswordField('Password', 
            validators=[validators.Required()])
    remember_me = wtforms.BooleanField('Keep me logged in')
    submit = wtforms.SubmitField('Submit')

class RegisterationForm(flask_wtf.FlaskForm):
    email = wtforms.StringField('Email',
            validators=[validators.Required(), validators.Email(),
                validators.Length(1, 64)])
    username = wtforms.StringField('Username',
            validators=[validators.Required(), validators.Length(1, 64),
                validators.Regexp(r'^[a-zA-Z][a-zA-Z\-_0-9]*$', 
                    message='Usernames must have only a-zA-Z0-9_-')])
    password = wtforms.PasswordField('Password', 
            validators=[validators.Required(), 
                validators.EqualTo('password2', 
                    message='Password must match.')])
    password2 = wtforms.PasswordField('Confirm Password',
            validators=[validators.Required()])
    submit = wtforms.SubmitField('Register')
    def validate_email(self, field):
        if models.User.query.filter_by(email=field.data).all():
            raise wtforms.ValidationError('Email already registered.')
    def validate_username(self, field):
        if models.User.query.filter_by(username=field.data).all():
            raise wtforms.ValidationError('Username already in use.')

class PasswordUpdateForm(flask_wtf.FlaskForm):
    old_password = wtforms.PasswordField('Old Password',
            validators=[validators.Required()])
    password = wtforms.PasswordField('New Password',
            validators=[validators.Required(), 
                validators.EqualTo('password2',
                    message='Password must match.')])
    password2 = wtforms.PasswordField('Confirm Password',
            validators=[validators.Required()])
    submit = wtforms.SubmitField('Update Password')
    def validate_old_password(self, field):
        if not flask_login.current_user.verify_password(field.data):
            raise wtforms.ValidationError('Password uncorrect!')

class PasswordResetRequestForm(flask_wtf.FlaskForm):
    email = wtforms.StringField('Email',
            validators=[validators.Required(), validators.Email(),
                validators.Length(1, 64)])
    send_me_email = wtforms.SubmitField('Send Me A Email')
    def validate_email(self, field):
        if not models.User.query.filter_by(email=field.data).all():
            raise wtforms.ValidationError('Not a user email.')
class PasswordResetForm(flask_wtf.FlaskForm):
    password = wtforms.PasswordField('New Password',
            validators=[validators.Required(), 
                validators.EqualTo('password2',
                    message='Password must match.')])
    password2 = wtforms.PasswordField('Confirm Password',
            validators=[validators.Required()])
    submit = wtforms.SubmitField('Reset Password')
    def validate_email(self, field):
        if not models.User.query.filter_by(email=field.data).all():
            raise wtforms.ValidationError('Not a user email.')

class EmailUpdateForm(flask_wtf.FlaskForm):
    email = wtforms.StringField('New Email',
            validators=[validators.Required(), validators.Email(),
                validators.Length(1, 64)])
    password = wtforms.PasswordField('Password',
            validators=[validators.Required()])
    submit = wtforms.SubmitField('Reset Email')
    def validate_email(self, field):
        if models.User.query.filter_by(email=field.data).all():
            raise wtforms.ValidationError('Email already been registered.')
    def validate_password(self, field):
        if not flask_login.current_user.verify_password(field.data):
            raise wtforms.ValidationError('Password Error')
