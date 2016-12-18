'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		views.py
  > Created Time:	2016-12-15 Thu 17:36
'''''''''''''''''''''''''''''''''''''''''''''''''''

import flask
from . import auth
from . import forms
from .. import models
from ..email import send_mail
from .. import db
import flask_login

@auth.route('/login', methods=['POST', 'GET'])
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        user = models.User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            flask_login.login_user(user, remember=form.remember_me.data)
            # if remember is False, when browser close,messages are gone
            # elseif server will give browser a cookie

            return flask.redirect(flask.request.args.get('next') or \
                    flask.url_for('main.index'))
            # 当用户访问未授权的URL(使用login_required修饰符)会显示登录表单
            # 此时，flask_login会把原地址保存在查询字符串的next字段，
            # 其可从requests.args字典读取
        else:
            flask.flash('Invalid username or password.')
    return flask.render_template('auth/login.html', form=form)

@auth.route('/logout')
@flask_login.login_required
def logout():
    flask_login.logout_user()
    flask.flash('You have been logged out.')
    return flask.redirect(flask.url_for('main.index'))

@auth.route('/register', methods=['POST', 'GET'])
def register():
    form = forms.RegisterationForm()
    if form.validate_on_submit():
        user = models.User(username=form.username.data, 
                password=form.password.data, 
                email=form.email.data)
        models.db.session.add(user)
        models.db.session.commit()

        token = user.generate_confirmation_token()
        send_mail(user.email, 'Confirm Your Account',
                'auth/email/confirm', user=user, token=token)
        flask.flash('A confirmation email have been sent to you by email.')
        return flask.redirect(flask.url_for('auth.login'))
    return flask.render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@flask_login.login_required
def confirm(token):
    if flask_login.current_user.confirmed:
        return flask.redirect(flask.url_for('main.index'))
    if flask_login.current_user.confirm(token):
        flask.flash('You have confirmed your account. Thanks!')
    else:
        flask.flash('The confirmation link is invalid or has expired.')
    return flask.redirect(flask.url_for('main.index'))

@auth.route('/confirm')
@flask_login.login_required
def resend_confirmation():
    token = flask_login.current_user.generate_confirmation_token()
    send_mail(flask_login.current_user.email, 
            "Confirm {}'s Account".format(flask_login.current_user.username),
            'auth/email/confirm', user=flask_login.current_user, 
            token = token)
    flask.flash('A new confirmation email has been sent to your by email.')
    return flask.redirect(flask.url_for('main.index'))

@auth.before_app_request
def before_request():
    if flask_login.current_user.is_authenticated \
            and not flask_login.current_user.confirmed \
            and flask.request.endpoint[:5] != 'auth.' \
            and flask.request.endpoint != 'static':
        return flask.redirect(flask.url_for('auth.unconfirmed'))
            # 当请求main.index时，request就在main命名空间，
            # 使用.unconfirmed就会在main.unconfirmed中查找，会出错，所以使用绝对命名空间

@auth.route('/unconfirmed')
def unconfirmed():
    if flask_login.current_user.is_anonymous \
            or flask_login.current_user.confirmed:
        return flask.redirect(flask.url_for('main.index'))
    return flask.render_template('auth/unconfirmed.html')

@auth.route('/update_password', methods=['GET', 'POST'])
@flask_login.login_required
def password_update():
    form = forms.PasswordUpdateForm()
    if form.validate_on_submit():
        flask_login.current_user.password=form.password.data
        db.session.add(flask_login.current_user)
        flask.flash('Password update success.')
        return flask.redirect(flask.url_for('main.index'))
    return flask.render_template('auth/update_password.html', form=form)

@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not flask_login.current_user.is_anonymous:
        return flask.redirect(flask.url_for('main.index'))
    form = forms.PasswordResetRequestForm()
    if form.validate_on_submit():
        flask.session['email'] = form.email.data
        user = models.User.query.filter_by(email=flask.session['email']).first()
        token = user.generate_reset_token()
        send_mail(flask.session['email'], "Reset your password",
                'auth/email/reset_password', user=user, token=token)
        flask.flash('A reset email has been sent to your by email.')
        return flask.redirect(flask.url_for('.login'))
    return flask.render_template('auth/reset_password.html', form=form)
@auth.route('/reset/<token>', 
        methods=['GET', 'POST'])
def password_reset(token):
    if not flask_login.current_user.is_anonymous:
        flask.redirect(flask.url_for('main.index'))
    form = forms.PasswordResetForm()
    if form.validate_on_submit():
        user = models.User.query.filter_by(email=flask.session['email']).first()
        if user and user.reset_password(token, form.password.data):
            flask.flash('Your password has been updated.')
            return flask.redirect(flask.url_for('auth.login'))
        else:
            flask.flash("Invalid operation. Maybe the token is expired "\
                    "or it's not your email.")
            return flask.redirect(flask.url_for('main.index'))
    return flask.render_template('auth/reset_password.html', form=form)

@auth.route('/change-email', methods=['GET', 'POST'])
@flask_login.login_required
def change_email_request():
    form = forms.EmailUpdateForm()
    if form.validate_on_submit():
        new_email = form.email.data
        token = flask_login.current_user.generate_email_change_token(new_email)
        send_mail(new_email, 'Reset your email',
                'auth/email/reset_email', user=flask_login.current_user, token=token)
        flask.flash('A reset email has been sent to your by email.')
        return flask.redirect(flask.url_for('main.index'))
    return flask.render_template('auth/reset_email.html', form=form)


@auth.route('/change-email/<token>')
@flask_login.login_required
def change_email(token):
    if flask_login.current_user.change_email(token):
        flask.flash('You email address have been changed.')
    else:
        flask.flash("Invalid request.")
    return flask.redirect(flask.url_for('main.index'))
