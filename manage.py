#!/usr/bin/python 
'''''''''''''''''''''''''''''''''''''''''''''''''''
  > System:		Archlinux
  > Author:		ty-l6
  > Mail:		liuty196888@gmail.com
  > File Name:		manage.py
  > Created Time:	2016-12-14 Wed 21:25
'''''''''''''''''''''''''''''''''''''''''''''''''''

from app import create_app
from app import db
from app import models
import flask_migrate
import flask_script
import os

app = create_app(os.getenv('FLASK_CONFIG', 'default'))
manage = flask_script.Manager(app)
migrate = flask_migrate.Migrate(app, db)

manage.add_command('db', flask_migrate.MigrateCommand)

def make_shell_context():
    return dict(app=app, db=db, Role=models.Role, User=models.User)

manage.add_command('shell', 
        flask_script.Shell(make_context=make_shell_context))
@manage.command
def test():
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)

if __name__ == '__main__':
    manage.run()
