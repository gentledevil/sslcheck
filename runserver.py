#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import ConfigParser
import argparse
from flask import Flask, redirect
from flask.ext.admin import Admin, BaseView, expose
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.admin.contrib.sqla import ModelView
import pygal
from pygal.style import DefaultStyle

app = Flask(__name__)
config = ConfigParser.ConfigParser()
config.read('sslcheck.conf')
app.secret_key = config.get('Flask', 'SecretKey')
app.config['DEBUG'] = config.get('Flask', 'Debug')
db_uri = config.get('Database', 'URI')
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
db = SQLAlchemy(app)
MyStyle = DefaultStyle
MyStyle.background = '#555555'
MyStyle.plot_background = '#333333'


class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255))
    commonname = db.Column(db.String(255))
    dns_valid = db.Column(db.Boolean)
    net_ok = db.Column(db.Boolean)
    cert_valid = db.Column(db.Boolean)
    certname_match = db.Column(db.Boolean)
    expire_days = db.Column(db.Integer)
    expiration_date = db.Column(db.DateTime)
    revoked = db.Column(db.Boolean)
    heartbleed = db.Column(db.Boolean)
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

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dns_valid_percent = db.Column(db.Integer)
    net_ok_percent = db.Column(db.Integer)
    cert_valid_percent = db.Column(db.Integer)
    certname_match_percent = db.Column(db.Integer)
    expire_days_average = db.Column(db.Integer)
    revoked_percent = db.Column(db.Integer)
    heartbleed_percent = db.Column(db.Integer)
    date = db.Column(db.DateTime)

class ChartsView(BaseView):
    @expose('/')
    def index(self):
        return self.render('charts.html')

@app.route('/')
def index():
    return redirect('/admin')

@app.route('/certs.png')
def plot_certs():
    cert_valid = Host.query.filter_by(cert_valid = True).count()
    cert_invalid = Host.query.filter_by(cert_valid = False).count()

    pie_chart = pygal.Pie(style=MyStyle, human_readable=True, \
                          x_title='Certificates (in %)')
    pie_chart.add('Valid', cert_valid)
    pie_chart.add('Invalid', cert_invalid)
    pie_chart.render()
    pie_chart.render_to_png('tmp/certs.png')

    header = {'Content-type': 'image/png'}
    f = open('tmp/certs.png')
    f.seek(0)
    data = f.read()

    return data, 200, header

@app.route('/errors.png')
def plot_errors():
    dns_invalid = Host.query.filter_by(dns_valid = False).count()
    net_nok = Host.query.filter_by(net_ok = False).count()
    expired = Host.query.filter(Host.expire_days <= 0).count()
    wrong_cn = Host.query.filter_by(certname_match = False).count()

    bar_chart = pygal.Bar(style=MyStyle, human_readable=True, rounded_bars=20, \
                          x_title='Errors', y_title='Certificates')
    bar_chart.add('DNS', dns_invalid)
    bar_chart.add('Network', net_nok)
    bar_chart.add('Expired', expired)
    bar_chart.add('Wrong CN', wrong_cn)
    bar_chart.render()
    bar_chart.render_to_png('tmp/errors.png')

    header = {'Content-type': 'image/png'}
    f = open('tmp/errors.png')
    f.seek(0)
    data = f.read()

    return data, 200, header

@app.route('/vulnerabilities.png')
def plot_vulnerabilities():
    revoked = Host.query.filter_by(revoked = True).count()
    heartbleed = Host.query.filter_by(heartbleed = True).count()

    bar_chart = pygal.Bar(style=MyStyle, human_readable=True, rounded_bars=20, \
                          x_title='Vulnerabilities', y_title='Certificates')
    bar_chart.add('Revoked', revoked)
    bar_chart.add('Heartbleed', heartbleed)
    bar_chart.render()
    bar_chart.render_to_png('tmp/vulnerabilities.png')

    header = {'Content-type': 'image/png'}
    f = open('tmp/vulnerabilities.png')
    f.seek(0)
    data = f.read()

    return data, 200, header

@app.route('/expiration.png')
def plot_expiration():
    expired = Host.query.filter(Host.expire_days <= 0).count()
    expires_1m = Host.query.filter(Host.expire_days >= 0).filter(Host.expire_days <= 30).count()
    expires_3m = Host.query.filter(Host.expire_days > 30).filter(Host.expire_days <= 90).count()
    expires_6m = Host.query.filter(Host.expire_days > 90).filter(Host.expire_days <= 180).count()
    expires_1y = Host.query.filter(Host.expire_days > 180).filter(Host.expire_days <= 365).count()
    expires_2y = Host.query.filter(Host.expire_days > 365).filter(Host.expire_days <= 730).count()
    expires_10y = Host.query.filter(Host.expire_days > 730).filter(Host.expire_days <= 3650).count()
    expires_later = Host.query.filter(Host.expire_days > 3650).count()

    bar_chart = pygal.Bar(style=MyStyle, human_readable=True, rounded_bars=20, \
                          x_title='Expiration time (in days)', y_title='Certificates')
    bar_chart.add('Expired', expired)
    bar_chart.add('1 month', expires_1m)
    bar_chart.add('3 months', expires_6m)
    bar_chart.add('6 months', expires_6m)
    bar_chart.add('1 year', expires_1y)
    bar_chart.add('2 years', expires_2y)
    bar_chart.add('10 years', expires_10y)
    bar_chart.add('Later', expires_later)
    bar_chart.render()
    bar_chart.render_to_png('tmp/expiration.png')

    header = {'Content-type': 'image/png'}
    f = open('tmp/expiration.png')
    f.seek(0)
    data = f.read()

    return data, 200, header

@app.route('/history.png')
def plot_history():
    date = []
    dns_valid_percent = []
    net_ok_percent = []
    cert_valid_percent = []
    certname_match_percent = []
    revoked_percent = []
    heartbleed_percent = []
    for row in History.query.limit(52):
        date.append(row.date.strftime('%V-%Y'))
        dns_valid_percent.append(row.dns_valid_percent)
        net_ok_percent.append(row.net_ok_percent)
        cert_valid_percent.append(row.cert_valid_percent)
        certname_match_percent.append(row.certname_match_percent)
        revoked_percent.append(row.certname_match_percent)
        heartbleed_percent.append(row.certname_match_percent)

    line_chart = pygal.Line(style=MyStyle, human_readable=True, fill=True, \
                            x_title='Week', y_title='Certificates (in %)')
    line_chart.x_labels = date
    line_chart.add('DNS valid', dns_valid_percent)
    line_chart.add('Network OK', net_ok_percent)
    line_chart.add('Valid', cert_valid_percent)
    line_chart.add('CN match', certname_match_percent)
    line_chart.add('Revoked', certname_match_percent)
    line_chart.add('Heartbleed', certname_match_percent)

    line_chart.render()
    line_chart.render_to_png('tmp/history.png')

    header = {'Content-type': 'image/png'}
    f = open('tmp/history.png')
    f.seek(0)
    data = f.read()

    return data, 200, header

admin = Admin(app, name='SSLCheck')
admin.add_view(ModelView(Host, db.session))
admin.add_view(ChartsView(name='Charts'))

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
