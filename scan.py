#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import argparse
import socket
import re
import ConfigParser
from datetime import datetime
import time
import sqlite3
try:
    from OpenSSL import SSL
    PYOPENSSL = True
except ImportError:
    print 'You need pyOpenSSL for this script to work'
    exit(1)

class Certificate:
    def __init__(self):
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
        try:
            self.expiration_date = datetime.strptime(asn1, "%Y%m%d%H%M%SZ")
        except:
            return

        expire_in = self.expiration_date - datetime.now()
        self.expire_days = expire_in.days
        if 0 < self.expire_days < 30:
            print 'Warning: Certificate for %s expires in %d days.' % (HOST, self.expire_days)
        if self.expire_days < 0:
            print 'Certificate for %s has expired %d days ago.' % (HOST, -self.expire_days)

    def check_dns(self):
        # Check the DNS name
        try:
            socket.getaddrinfo(HOST, PORT)[0][4][0]
        except socket.gaierror as e:
            print 'DNS problem on %s: %s.' % (HOST, e)
            self.dns_valid = False
            return
        self.dns_valid = True

    def check_ssl(self):
        # Connect to the host and get the certificate
        if self.dns_valid == False:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))

        try:
            ctx = SSL.Context(SSL.TLSv1_METHOD)
            ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           self.check_callback)
            ctx.load_verify_locations(CA_CERTS)
            ssl_sock = SSL.Connection(ctx, sock)
            ssl_sock.set_connect_state()
            ssl_sock.set_tlsext_host_name(HOST)
            ssl_sock.do_handshake()
            self.x509 = ssl_sock.get_peer_certificate()
            ssl_sock.shutdown()
        except SSL.Error as e:
            print 'Certificate validation failed on %s.' % HOST
            self.cert_valid = False

        if self.cert_valid != False:
            self.cert_valid = True

        sock.close()

    def check_certname(self):
        if not self.x509:
            return
        x509name = self.x509.get_subject()
        CN = x509name.commonName
        splitCN = re.match(r'^([^.]+)\.(.*)$', CN)
        CNdomain = splitCN.group(2)
        CNsubdomain = splitCN.group(1)
        HOSTdomain = re.match(r'^[^.]+\.(.*)$', HOST).group(1)
        if CN != HOST and not (CNsubdomain == '*' and CNdomain == HOSTdomain):
            print 'Hostname %s does not match certificate CN %s.' \
            % (HOST, x509name.commonName)
            self.certname_match = False
        else:
            self.certname_match = True

if __name__ == "__main__":
    config = ConfigParser.ConfigParser()
    config.read('sslcheck.conf')
    db = config.get('Database', 'Path')
    CA_CERTS = config.get('SSL', 'CACerts')
    con = None
    try:
        con = sqlite3.connect(db)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
    except sqlite3.Error, e:
        print "Error: %s" % e.args[0]
        exit(1)

    cur.execute('SELECT host.id, host.hostname, protocol.port \
                FROM host, protocol \
                WHERE host.protocol_id = protocol.id \
                AND host.ignore != 1')
    global HOST, PORT
    for host in cur.fetchall():
        host_id = host['id']
        HOST = str(host['hostname'])
        PORT = int(host['port'])
        cert = Certificate()
        cert.check_dns()
        cert.check_ssl()
        cert.check_certname()
        cur.execute('UPDATE host \
                    SET expire_days=?, cert_valid=?, certname_match=?, \
                    dns_valid=?, expiration_date=?, last_check_date=? \
                    WHERE id=?',
                    (cert.expire_days, cert.cert_valid, cert.certname_match,
                    cert.dns_valid, cert.expiration_date, datetime.now(), host_id))
        con.commit()
    if con:
        con.close()
