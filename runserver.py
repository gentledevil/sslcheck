#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import ConfigParser
import argparse
from flask import Flask, redirect
from flask.ext.admin import Admin
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.admin.contrib.sqla import ModelView

app = Flask(__name__)
config = ConfigParser.ConfigParser()
config.read('sslcheck.conf')
db = config.get('Database', 'Path')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///%s' % db
db = SQLAlchemy(app)

@app.route('/')
def index():
    return redirect('/admin')

class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255))
    dns_valid = db.Column(db.Boolean)
    cert_valid = db.Column(db.Boolean)
    certname_match = db.Column(db.Boolean)
    expire_days = db.Column(db.Integer)
    expiration_date = db.Column(db.DateTime)
    last_check_date = db.Column(db.DateTime)
    ignore = db.Column(db.Boolean)
    protocol_id = db.Column(db.Integer, db.ForeignKey('protocol.id'))
    protocol = db.relationship('Protocol',
        backref=db.backref('hosts', lazy='dynamic'))

class Protocol(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True)
    port = db.Column(db.Integer, unique=True)

    def __init__(self, name, port):
        self.name = name
        self.port = port

    def __repr__(self):
        return '%s (%d)' % (self.name, self.port)

admin = Admin(app, name='SSLCheck')
admin.add_view(ModelView(Host, db.session))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="address to listen on", type=str,
                        default="localhost")
    parser.add_argument("--port", help="port to listen on", type=int,
                        default="8000")
    parser.add_argument("--init-db", help="initialize database tables",
                        action="store_true")
    parser.add_argument("--debug", help="enable debug mode",
                        action="store_true")
    args = parser.parse_args()
    if args.init_db:
        try:
            db.create_all()
            db.session.add(Protocol('https', 443))
            db.session.add(Protocol('ftps', 990))
            db.session.add(Protocol('pop3s', 995))
            db.session.commit()
        except:
            pass
    app.run(args.host, args.port, args.debug)
