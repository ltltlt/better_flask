'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		models.py
  > Created Time:	2016-12-14 Wed 21:13
'''''''''''''''''''''''''''''''''''''''''''''''''''

import flask
from . import db
import werkzeug
import flask_login
from . import login_manager
import itsdangerous

class User(flask_login.UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is gone')
    @password.setter
    def password(self, password):
        self.password_hash = \
                werkzeug.security.generate_password_hash(password)
    def verify_password(self, password):
        return werkzeug.security.check_password_hash(self.password_hash, password)

    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    confirmed = db.Column(db.Boolean, default=False)

    def generate_confirmation_token(self, expiration=3600):
        s = itsdangerous.TimedJSONWebSignatureSerializer(\
                flask.current_app.config['SECRET_KEY'],
                expires_in=expiration)
        return s.dumps({ 'confirm': self.id })

    def confirm(self, token):
        s = itsdangerous.TimedJSONWebSignatureSerializer(\
                flask.current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)        # update model
        return True

    def generate_reset_token(self, expiration=3600):
        s = itsdangerous.TimedJSONWebSignatureSerializer(\
                flask.current_app.config['SECRET_KEY'],
                expires_in=expiration)
        return s.dumps({ 'reset': self.id })

    def reset_password(self, token, password):
        s = itsdangerous.TimedJSONWebSignatureSerializer(\
                flask.current_app.config['SECRET_KEY'])
        try:
            d = s.loads(token)
        except:
            return False
        if d.get('reset') != self.id:
            return False
        self.password = password
        db.session.add(self)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = itsdangerous.TimedJSONWebSignatureSerializer(\
                flask.current_app.config['SECRET_KEY'],
                expires_in=expiration)
        return s.dumps({ 'reset_email': { 'id': self.id, 'new_email': new_email } })
    def change_email(self, token):
        s = itsdangerous.TimedJSONWebSignatureSerializer(\
                flask.current_app.config['SECRET_KEY'])
        try:
            d = s.loads(token)
            id_email = d['reset_email']
        except:
            return False
        if id_email['id'] != self.id:
            return False
        self.email = id_email['new_email']
        db.session.add(self)
        return True

    def __repr__(self):
        return '<user {}>'.format(self.username)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.role is None:
            if self.email == flask.current_app.config['FLASKY_ADMIN_MAIL']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            else:
                self.role = Role.query.filter_by(default=True).first()
        self.role_id = self.role.id

    def can(self, permissions):
        return self.role is not None and \
                (self.role.permissions&permissions == permissions)
    def is_administrator(self):
        return self.can(Permission.ADMINISTER)
class AnonymousUser(flask_login.AnonymousUserMixin):
    def can(self, permissions):
        return False
    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser

class Permission:
    FOLLOW = 0x01
    COMMIT = 0X02
    WRITE_ARTICLES = 0X04
    MODERATE_COMMENTS = 0X08
    ADMINISTER = 0X80
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer, unique=True)

    users = db.relationship('User', backref='role')

    @staticmethod
    def insert_roles():
        roles = {
                'User': (Permission.FOLLOW |
                    Permission.COMMIT | Permission.WRITE_ARTICLES,
                    True),
                'Moderator': (Permission.FOLLOW |
                    Permission.COMMIT | Permission.WRITE_ARTICLES |
                    Permission.MODERATE_COMMENTS, False),
                'Administrator': (0xff, False)
                }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<role {}>'.format(self.name)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
