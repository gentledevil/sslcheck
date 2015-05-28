## Description ##
SSLCheck is a tool to check and report on SSL certificates validity. Give it a list of hosts and ports through the Web UI and it will produce alerts, charts and logs about which certificates are not properly setup, vulnerables or expire soon.

It comes in two parts :
 - `scan.py` is the script that scan the certificates and populates the DB
 - `runserver.py` provides the Web UI

## Features ##

It currently reports on :
 - network/DNS error while trying to reach hosts
 - Common Names which do not match hostnames
 - invalid/incomplete certificate chain
 - vulnerability to Heartbleed (probably not useful anymore)
 - soon to expire or expired certificates
 - revoked certificates
 - evolution over time of the number of certificates that are valid/invalid

 ![One does not simply forget to renew the certificate](static/img/one-does-not-simply.jpg)

## Installation ##

Install dependencies using pip :

    pip install -r requirements.txt

then edit `sslcheck.conf` with the connection string to your DB and the path to your certificates CA store.

See [SQLAlchemy documentation][2] for the DB connection string syntax and available backends.
If not using SQLite you may need to install appropriate modules for your database.

Then run :

    ./runserver.py --init-db

> **NOTE:** See `./runserver --help` for other options.

to create the database tables. The Web UI should now be accessible on `http://localhost:8000`.

Once everything works, use a WSGI Web server such as [Gunicorn][1] to serve the application :

    gunicorn runserver:app -b localhost:80

## Usage ##

Connect to the Web interface, define some servers you would like to check the certificates on.

Once you have setup some hosts to check from the interface, run the scan :

    ./scan.py

You may want to put this script in a cron for regular check, and setup the logging to get mails when a certificate error is detected.

## Configuration ##

Main configuration is done in `sslcheck.conf`. See [SQLAlchemy documentation][2] for the DB connection string syntax and available backends.

Log configuration is done in `logging.conf`. See Python documentation for [configuration file format][3] and [available handlers][4].

## Troubleshooting ##

In case of problems, the Web UI can be run in debug mode :

    ./runserver.py --debug

> **NOTE:** This is highly insecure.


  [1]: http://gunicorn.org/
  [2]: http://docs.sqlalchemy.org/en/rel_0_9/core/engines.html
  [3]: https://docs.python.org/2/library/logging.config.html#configuration-file-format
  [4]: https://docs.python.org/2/library/logging.handlers.html#module-logging.handlers
