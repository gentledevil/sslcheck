#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import socket
import re
import ConfigParser
from datetime import datetime
from sqlalchemy import Table, schema, select, text
from sqlalchemy.engine import create_engine
try:
    from OpenSSL import SSL
    PYOPENSSL = True
except ImportError:
    print 'You need pyOpenSSL for this script to work'
    exit(1)

class Certificate:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.x509 = None
        self.expiration_date = None
        self.expire_days = None
        self.cert_valid = None
        self.certname_match = None
        self.dns_valid = None

    def check_callback(self, connection, x509, errnum, errdepth, ok):
        self.check_expiration(x509.get_notAfter())
        if not ok:
            return False
        return ok


    def check_expiration(self, asn1):
        self.expiration_date = datetime.strptime(asn1, "%Y%m%d%H%M%SZ")

        expire_in = self.expiration_date - datetime.now()
        self.expire_days = expire_in.days
        if 0 < self.expire_days < 30:
            print 'Warning: Certificate for %s expires in %d days.' % (self.host, self.expire_days)
        if self.expire_days < 0:
            print 'Certificate for %s has expired %d days ago.' % (self.host, -self.expire_days)

    def check_dns(self):
        # Check the DNS name
        try:
            socket.getaddrinfo(self.host, self.port)[0][4][0]
        except socket.gaierror as err:
            print 'DNS problem on %s: %s.' % (self.host, err)
            self.dns_valid = False
            return
        self.dns_valid = True

    def check_ssl(self):
        # Connect to the host and get the certificate
        if self.dns_valid == False:
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
        except socket.error as err:
            print 'Unable to reach server %s: %s.' % (self.host, err)
            self.cert_valid = False

        try:
            ctx = SSL.Context(SSL.TLSv1_METHOD)
            ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           self.check_callback)
            ctx.load_verify_locations(CA_CERTS)
            ssl_sock = SSL.Connection(ctx, sock)
            ssl_sock.set_connect_state()
            ssl_sock.set_tlsext_host_name(self.host)
            ssl_sock.do_handshake()
            self.x509 = ssl_sock.get_peer_certificate()
            ssl_sock.shutdown()
        except SSL.Error:
            print 'Certificate validation failed on %s.' % self.host
            self.cert_valid = False

        if self.cert_valid != False:
            self.cert_valid = True

        sock.close()

    def check_certname(self):
        if not self.x509:
            return
        x509name = self.x509.get_subject()
        cn = x509name.commonName
        split_cn = re.match(r'^([^.]+)\.(.*)$', cn)
        cn_domain = split_cn.group(2)
        cn_subdomain = split_cn.group(1)
        host_domain = re.match(r'^[^.]+\.(.*)$', self.host).group(1)
        if cn != self.host and not (cn_subdomain == '*' and cn_domain == host_domain):
            print 'Hostname %s does not match certificate cn %s.' \
            % (self.host, x509name.commonName)
            self.certname_match = False
        else:
            self.certname_match = True

if __name__ == "__main__":
    config = ConfigParser.ConfigParser()
    config.read('sslcheck.conf')
    db_uri = config.get('Database', 'URI')
    CA_CERTS = config.get('SSL', 'CACerts')

    engine = create_engine(db_uri)
    connection = engine.connect()
    metadata = schema.MetaData(engine)
    thost = Table("host", metadata, autoload=True)
    tprotocol = Table("protocol", metadata, autoload=True)

    select = select([thost, tprotocol]).where(thost.c.protocol_id == tprotocol.c.id)
    for host in connection.execute(select):
        host_id = host[0]
        hostname = str(host['hostname'])
        port = int(host['port'])
        cert = Certificate(hostname, port)
        cert.check_dns()
        cert.check_ssl()
        cert.check_certname()
        update = text('UPDATE host \
                     SET expire_days=:ed, cert_valid=:cv, certname_match=:cm, \
                     dns_valid=:dv, expiration_date=:edt, last_check_date=:lcd \
                     WHERE id=:id')
        connection.execute(update, ed=cert.expire_days, cv=cert.cert_valid,
                      cm=cert.certname_match, dv=cert.dns_valid,
                      edt=cert.expiration_date, lcd=datetime.now(), id=host_id)

    connection.close()
