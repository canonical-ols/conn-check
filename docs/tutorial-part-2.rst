Tutorial Part 2: Auto-generating conn-check config for a Django app
===================================================================

Hello World (again)
-------------------

Let's assume that you've actually created the ``Hello World`` service from
:doc:`part 1 </tutorial-part-1>` as a
`Django app <https://www.djangoproject.com/>`_, and you think to yourself:

*"Hang on, aren't all these connections I want conn-check to check for me
already defined in my Django settings module?"*

conn-check-configs
------------------

Yes, yes they are, and with the handy-dandy
`conn-check-configs <https://pypi.python.org/pypi/conn-check-configs>`_
package you can automatically generate conn-check config YAML from a range of
standard Django settings values (in theory from other environments
too, such as `Juju <https://jujucharms.com/>`_, but for now just Django).

exempli gratia
--------------

Given the following ``settings.py`` in our *HWaaS* app:

.. code-block:: python

    INSTALLED_APPS = [
        'hwaas'
    ]
    DATABASES = {
        'default': {
                'ENGINE': 'django.db.backends.postgresql_psycopg2',
                'HOST': 'gibson.hwass.internal',
                'NAME': 'hwaas_production',
                'PASSWORD': '123456asdf',
                'PORT': 11211,
                'USER': 'hwaas',
    }
    CACHES = {
        'default': {
            'LOCATION': 'freeside.hwaas.internal:11211',
            'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
        },
    }
    PROXY_HOST = 'countzero.hwaas.internal'
    PROXY_PORT = 8080
    TRANSLATE_API_KEY = 'BLAH'

We can create a ``settings-to-conn-check.py`` script with the least possible
effort like so:

.. code-block:: python

    #!/usr/bin/env python
    from conn_check_configs.django import *

    if __name__ == '__main__':
        run()

This will output *postgresql* and *memcached* checks to similar our 
hand-written config:

.. code-block:: sh

    $ chmod +x settings-to-conn-check.py
    $ ./settings-to-conn-check.py -f cc-config.yaml -m hwaas.settings
    $ cat cc-config.yaml

.. code-block:: yaml

    - type: postgresql
      database: hwaas_production
      host: gibson.hwaas.internal
      port: 5432
      username: hwaas
      password: 123456asdf
    - type: memcached
      host: freeside.hwaas.internal
      port: 11211

Customising generated checks
----------------------------

In order to generate the checks we need for Squid / Google Translate API, we
can add some custom callbacks:

.. code-block:: python

    #!/usr/bin/env python
    from conn_check_configs.django import *


    def make_proxied_translate_check(settings, options):
        checks = []
        if settings['PROXY_HOST']:
            checks.append({
                'type': 'http',
                'url': 'https://www.googleapis.com/language/translate/v2?q='
                       'Hello%20World&target=de&source=en&key={}'.format(
                           settings['TRANSLATE_API_KEY']),
                'proxy_host': settings['PROXY_HOST'],
                'proxy_port': int(settings.get('PROXY_PORT', 8080)),
                'expected_code': 200,
            })
        return checks

    EXTRA_CHECK_MAKERS.append(make_proxied_translate_check)


    if __name__ == '__main__':
        run()


In the above we define a callable which takes 2 params, ``settings`` which
is a wrapper around the Django settings module, and ``options`` which is
an object containing the command line arguments that were passed to the script.

The ``settings`` module is not the direct settings module but a dict-like
wrapper so that you can access the settings just a like a dict (using indices,
``.get`` method, etc.)

To ensure ``make_proxied_translate_check`` is collected and called by the main
``run`` function we add it to the ``EXTRA_CHECK_MAKERS`` list.

The above generates our required HTTP check:

.. code-block:: yaml

    - type: http
      url: https://www.googleapis.com/language/translate/v2?q=Hello%20World&target=de&source=en&key=BLAH
      proxy_host: countzero.hwaas.internal
      proxy_port: 8080
      expected_code: 200

A note on statstd checks
------------------------

Getting more operational visibility on how *HWaaS* runs would be great,
wouldn't it?

So let's add some metrics collection using
`StatsD <https://github.com/etsy/statsd>`_, and as luck would have it we can
get a lot for *nearly free* with the
`django-statsd <https://django-statsd.readthedocs.org/>`_, after adding it to
our dependencies we update our ``settings.py`` to include:

.. code-block:: python

    INSTALLED_APPS = [
        'hwaas'
        'django_statsd',
    ]
    MIDDLEWARE_CLASSES = [
        'django_statsd.middleware.GraphiteMiddleware',
    ]
    STATSD_CLIENT = 'django_statsd.clients.normal'
    STATSD_HOST = 'bigend.hwaas.internal'
    STATSD_PORT = 10021

**Note**: You don't actually need the django-statsd app to have
conn-check-configs generate statsd checks, only the use of ``STATSD_HOST``
and ``STATSD_PORT`` in your settings module matters.

Another run of our ``settings-to-conn-check.py`` script will result in the
extra statsd check:

.. code-block:: yaml

    - type: udp
      host: bigend.hwaas.internal
      port: 10021
      send: conncheck.test:1|c
      expect: 

As you can see this is just a generic UDP check that attempts to send an
incremental counter metric to the statsd host.

Unfortunately the fire-and-forget nature of this use of statsd/UDP will not
error in a number of common situations (the simplest being that statsd is not
running on the target host, or even a routing issue along the way).

It will catch simple problems such as not being able to open up the local UDP
port to send from, but that's usually not enough.

If you use a third-party implementation of statsd, such as 
`txStatsD <https://launchpad.net/txstatsd>`_ then you might have the ability
to define a pair of health check strings, for example by changing the send
and expect values in the ``STATSD_CHECK`` dict we can send and expect different
strings:

.. code-block:: python

    #!/usr/bin/env python
    from conn_check_configs.django import *

    STATSD_CHECK['send'] = 'Hakuna'
    STATSD_CHECK['expect'] = 'Matata'

    if __name__ == '__main__':
        run()

Which generates this check:

.. code-block:: yaml

    - type: udp
      host: bigend.hwaas.internal
      port: 10021
      send: Hakuna
      expect: Matata

In the above we would configure our txStatD (for example) instance to respond
to the string ``Hakuna`` with the string ``Matata``, which would catch pretty
much all the possible issues with contacting our metrics service.
