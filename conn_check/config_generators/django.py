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


def get_settings(settings_module, settings_module_path):
    if settings_module:
        os.environ['DJANGO_SETTINGS_MODULE'] = settings_module
    if settings_module_path:
        sys.path.insert(0, os.path.abspath(settings_module_path))

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
    # XXX: skipped, on account of OOPS settings being untested, but should just
    # be AMQP checks
    return []


def make_celery_checks(settings, options):
    checks = []
    host = settings['BROKER_HOST']
    backend = settings['BROKER_BACKEND']
    if ((not backend and host) or backend in ('amqp', 'redis')):
        check = {
            'type': backend,
            'host': host,
            'port': int(settings['BROKER_PORT']),
            'username': settings['BROKER_USER'],
            'password': settings['BROKER_PASSWORD'],
        }
        if settings['BROKER_VHOST']:
            check['vhost'] = settings['BROKER_VHOST']
        checks.append(check)
    return checks


def gather_checks(options):
    settings = get_settings(options.settings_module,
                            options.settings_module_path)
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
    parser.add_argument('-m', '--settings-module',
                        dest="settings_module",
                        action="store")
    parser.add_argument('-p', '--module-path',
                        dest="settings_module_path",
                        action="store")
    opts = parser.parse_args(args)

    checks = gather_checks(opts)

    with open(opts.output_file, 'w') as f:
        yaml.dump(checks, f, default_flow_style=False)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
