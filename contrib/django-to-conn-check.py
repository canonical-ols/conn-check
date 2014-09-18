#!/usr/bin/env python

import argparse
import os
import sys
import yaml

from django.conf import settings as django_settings


class SettingsDict(dict):
    """Wrapper for Django settings object that allows access as a dict"""

    def __init__(self, settings):
        self.settings = settings

    def __getitem__(self, name):
        return getattr(self.settings, name, None)

    def get(self, name, default):
        return getattr(self.settings, name, default)


def get_settings():
    if 'DJANGO_SETTINGS_MODULE' not in os.environ:
        os.environ['DJANGO_SETTINGS_MODULE'] = 'django_project.settings'
        # Make sure we can import django_project even if this script is called
        # directly
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    return SettingsDict(django_settings)


def make_postgres_checks(settings, options):
    checks = []
    for name, db in settings.get('DATABASES', {}).items():
        if db.get('ENGINE') == 'django.db.backends.postgresql_psycopg2':
            checks.append({
                'type': 'postgres',
                'database': 'pkgme-service-app',
                'host': db['HOST'],
                'port': int(db['PORT']),
                'username': db['USER'],
                'password': db['PASSWORD'],
            })
    return checks


def make_oops_checks(settings, options):
    # Skipped for now as we don't have oops in our testing env
    # Needs to create an amqp check for any amqp publisher
    # in settings.OOPSES

    return []


def make_celery_checks(settings, options):
    checks = []
    host = settings['BROKER_HOST']
    backend = settings['BROKER_BACKEND']
    if ((not backend and host) or backend == 'amqp'):
        checks.append({
            'type': 'amqp',
            'host': host,
            'port': int(settings['BROKER_PORT']),
            'username': settings['BROKER_USER'],
            'password': settings['BROKER_PASSWORD'],
            'vhost': settings['BROKER_VHOST'],
        })
    return checks


def make_myapps_checks(settings, options):
    checks = []
    url = settings['myapps_base_url']
    if url:
        checks.append({
            'type': 'http',
            'url': url,
            'expected_code': 302,
        })
    return checks


def make_click_updown_checks(settings, options):
    checks = []
    if options.click_updown_url:
        checks.append({
            'type': 'http',
            'url': options.click_updown_url,
            'expected_code': 302,
        })
    return checks


def gather_checks(options):
    settings = get_settings()
    checks = []
    checks.extend(make_postgres_checks(settings, options))
    checks.extend(make_oops_checks(settings, options))
    checks.extend(make_celery_checks(settings, options))
    checks.extend(make_click_updown_checks(settings, options))
    checks.extend(make_myapps_checks(settings, options))
    return checks


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('output_file')
    parser.add_argument('--click-updown-url',
                        dest="click_updown_url",
                        action="store")
    opts = parser.parse_args(args)
    checks = gather_checks(opts)
    with open(opts.output_file, 'w') as f:
        yaml.dump(checks, f, default_flow_style=False)


def run():
    sys.exit(main(sys.argv[1:]))


if __name__ == '__main__':
    run()
