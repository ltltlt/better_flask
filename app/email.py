'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		email.py
  > Created Time:	2016-12-16 Fri 21:08
'''''''''''''''''''''''''''''''''''''''''''''''''''

import flask_mail
from . import mail
import flask
import threading

def async_send(app, msg):
    with app.app_context():
        mail.send(msg)

def send_mail(to, subject, template_file, **kwargs):
    msg = flask_mail.Message(subject=\
            flask.current_app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
            sender=flask.current_app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = flask.render_template(template_file+'.txt', **kwargs)
    msg.html = flask.render_template(template_file+'.html', **kwargs)

    app = flask.current_app._get_current_object()   # get the real object
    thread = threading.Thread(target=async_send, args=(app, msg))
    thread.daemon = True
    thread.start()
