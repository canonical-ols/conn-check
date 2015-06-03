Tutorial Part 1: Checking connections for a basic web app
=========================================================

Hello World
-----------

Suppose you have the basic webapp `HWaaS` (Hello World as a Service, naturally).

It returns a different translation of "Hello World" on every request, and
accepts new translations via ``POST`` requests.

 * The translations are stored in a `PostgreSQL` database.
 * `memcached` is used to keep a cache of pre-rendered "Hello World"
   HTML pages.
 * Optionally requests are sent to the
   `Google Translate API <https://cloud.google.com/translate/>`_ to get an
   automatically translated version of the page in the user's language
   if they push a certain button and a translation in their language isn't
   available in the `PostgreSQL` DB.
 * The `Squid` HTTP proxy is sat between it and the Translate API to cache requests
   (varied by language), to avoid hitting Google's rate limiting.


Why use conn-check?
-------------------

Our `HWaaS` example service depends on not only 3 internal services, but also
a completely external service (the Google Translate API), and any number of
issues from network routing, firewall configuration and bad service
configuration to external outages could cause issues after a new deployment
(or at any time really, but we'll address that later in :ref:`nagios`).

`conn-check` can verify connections to these dependencies using not just basic
TCP/UDP connects, but also service specific ones, with authentication where
needed, timeouts, and even permissions (e.g. can `user A` access
`DB schema B`).

Yet another YAML file
---------------------

`conn-check` is configured using a `YAML <http://yaml.org/>`_ file containing
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

memcached
`````````

HTTP
````


.. _nagios:

Using conn-check with Nagios
----------------------------
