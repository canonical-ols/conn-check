Tutorial Part 1: Checking connections for a basic web app
=========================================================

Hello World
-----------

Suppose you have the basic webapp *HWaaS* (Hello World as a Service, naturally).

It returns a different translation of "Hello World" on every request, and
accepts new translations via ``POST`` requests.

 * The translations are stored in a *PostgreSQL* database.
 * *memcached* is used to keep a cache of pre-rendered "Hello World"
   HTML pages.
 * Optionally requests are sent to the
   `Google Translate API <https://cloud.google.com/translate/>`_ to get an
   automatically translated version of the page in the user's language
   if they push a certain button and a translation in their language isn't
   available in the *PostgreSQL* DB.
 * The *Squid* HTTP proxy is sat between it and the Translate API to cache requests
   (varied by language), to avoid hitting Google's rate limiting.


Why use conn-check?
-------------------

Our *HWaaS* example service depends on not only 3 internal services, but also
a completely external service (the Google Translate API), and any number of
issues from network routing, firewall configuration and bad service
configuration to external outages could cause issues after a new deployment
(or at any time really, but we'll address that later in :ref:`nagios`).

*conn-check* can verify connections to these dependencies using not just basic
TCP/UDP connects, but also service specific ones, with authentication where
needed, timeouts, and even permissions (e.g. can *user A* access
*DB schema B*).

Yet another YAML file
---------------------

conn-check is configured using a `YAML <http://yaml.org/>`_ file containing
a list of checks to perform in parallel (by default, but this too is
configurable with a CLI option).

Here's an example file (it could be called ``hwaas-cc.yaml``):

.. code-block:: yaml

    - type: postgresql
      host: gibson.hwaas.internal
      port: 5432
      username: hwaas
      password: 123456asdf
      database: hwaas_production
    - type: memcached
      host: freeside.hwaas.internal
      port: 11211
    - type: http
      url: https://www.googleapis.com/language/translate/v2?q=Hello%20World&target=de&source=en&key=BLAH
      proxy_host: countzero.hwaas.internal
      proxy_port: 8080
      expected_code: 200

Let's examine those checks..
----------------------------

PostgreSQL
``````````

.. code-block:: yaml

    - type: postgresql
      host: gibson.hwaas.internal
      port: 5432
      username: hwaas
      password: 123456asdf
      database: hwaas_production

*type*: This one doesn't require much explanation, except the fact that you
can use either "postgresql" or "postgres" (many checks have aliases).

*host*, *port*: The host to connect to is always, understandably, required,
but if not supplied the default psql port of ``5432`` will be used.

*username*, *password*: Auth detailed are required and important when used with ...

... *database*: This is the psql schema to attempt to switch to use, and
*username* has permission to access.

memcached
`````````

.. code-block:: yaml

    - type: memcached
      host: freeside.hwaas.internal
      port: 11211

*type*: The alias "memcache" will also work.

*host*, *port*: If port isn't supplied the memcached default ``11211`` is used
instead.

HTTP
````

.. code-block:: yaml

    - type: http
      url: https://www.googleapis.com/language/translate/v2?q=Hello%20World&target=de&source=en&key=BLAH
      proxy_host: countzero.hwaas.internal
      proxy_port: 8080
      expected_code: 200

*type*: The alias "https" will also work.

*url*: As we're doing a simple GET to the Translate API I've included the
``key`` in the querystring, but you could also include auth defailts as HTTP
headers using the ``headers`` check option.

*proxy_host*, *proxy_port*: We supply the host/port to our Squid proxy here,
we could also use the ``proxy_url`` check option instead to define the proxy
as a standard HTTP URL (makes it possible to define a HTTPS proxy).

*expected_code*: This is the `status code <http://en.wikipedia.org/wiki/List_of_HTTP_status_codes>`_
we expect to get back from the service if the request was successful, anything
other than ``200`` in this case will cause the check to fail.

.. _nagios:

Using conn-check with Nagios
----------------------------

conn-check output tries to stay as close as possible to the
`Nagios plugin guidelines <https://nagios-plugins.org/doc/guidelines.html#PLUGOUTPUT>`_
so that it can be used as a regular `Nagios <https://www.nagios.org/>`_ check
for more constant monitoring of your service deployment (not just ad-hoc at
deploy time).

Example NRPE config files, assuming ``conn-check`` is system installed::

    # /etc/nagios/nrpe.d/check_conn_check.cfg
    command[conn_check]=/usr/bin/conn-check --max-timeout=10  --exclude-tags=no-nagios /var/conn-check/hwaas-cc.yaml
    
    
    # /var/lib/nagios/export/service__hwaas_conn_check.cfg
    define service {
        use                             active-service
        host_name                       hwaas-web1.internal
        service_description             connection checks with conn-check
        check_command                   check_nrpe!conn_check
        servicegroups                   web,hwaas
    }

A few arguments to note:

``--max-timeout=10``: This sets the global timeout to 10 seconds, which means
it will error if the total time for all checks combined goes above 10s, which
is the default max time allowed by Nagios for a plugin to run.

This way we still get all the individual check results back even if one of them
went above the threshold.


``--exclude-tags=no-nagios``: Although optional, this allows you to exclude
any check tagged with ``no-nagios``, which is especially handy for checks to
external/third-party services that you don't want to be hit constantly
by Nagios.

For example if we didn't want Nagios to hit Google every few minutes:

.. code-block:: yaml

    - type: http
      url: https://www.googleapis.com/language/translate/v2?q=Hello%20World&target=de&source=en&key=BLAH
      proxy_host: countzero.hwaas.internal
      proxy_port: 8080
      expected_code: 200
      tags: [no-nagios]
