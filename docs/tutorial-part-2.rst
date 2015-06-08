Tutorial Part 2: Auto-generating conn-check config for a Django app
===================================================================

Hello World (again)
-------------------

Let's assume that you've actually created the ``Hello World`` service from
:doc:`part 1 </tutorial-part-1>` as a
`Django app <https://www.djangoproject.com/>`_, and you think to yourself:

`"Hang on, aren't all these connections I want conn-check to check for me
already defined in my Django settings module?"`

conn-check-configs
------------------

Yes, yes they are, and with the handy-dandy
`conn-check-configs <https://pypi.python.org/pypi/conn-check-configs>`_
package you can automatically generate conn-check config YAML from a range of
different standard Django settings values (in theory from other environments
too, such as `Juju <https://jujucharms.com/>`_, but for now just Django).

exempli gratia
--------------

Given the following ``settings.py`` in our `HWaaS` service:

.. code-block:: python

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

We can create a ``settings-to-conn-check.py`` script with the least possible
effort like so:

.. code-block:: python

    from conn_check_configs.django import *

    if __name__ == '__main__':
        run()

This will output `postgresql` and `memcached` checks to similar our 
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



A note on statstd checks
------------------------


