'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		__init__.py
  > Created Time:	2016-12-14 Wed 08:36
'''''''''''''''''''''''''''''''''''''''''''''''''''

import flask_moment
import os, sys
import flask_bootstrap
import flask_mail
import flask_sqlalchemy
import flask
import flask_login

moment = flask_moment.Moment()
db = flask_sqlalchemy.SQLAlchemy()
mail = flask_mail.Mail()
bootstrap = flask_bootstrap.Bootstrap()
login_manager = flask_login.LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'

def create_app(config_name):
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    import config

    app = flask.Flask(__name__)
    app.config.from_object(config.config[config_name])
    config.config[config_name].init_app(app)

    moment.init_app(app)
    db.init_app(app)
    mail.init_app(app)
    bootstrap.init_app(app)
    login_manager.init_app(app)

    # some blueprint

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    # url_prefix: add prefix for all route in this blueprint
    # /login -> /auth/login
    
    return app
