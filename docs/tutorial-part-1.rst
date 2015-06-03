Tutorial Part 1: Checking connections for a basic web app
=========================================================

Hello World
-----------

Suppose you have the basic webapp `HWaaS` (Hello World as a Service, naturally).
It returns a different translation of "Hello World" on every request, and
accepts new translations via ``POST`` requests.

It stores these translations in a `PostgreSQL` database, uses `memcached` to
keep a cache of pre-rendered "Hello World" HTML pages, and optionally sends
request to the `Google Translate API <https://cloud.google.com/translate/>`_
to get an automatically translated version of the page in the user's language
if they push a certain button and a translation in their language isn't
available in the `PostgreSQL` DB.

Because Google have rate limiting on their API, and because translations
for a certain language are unlikely to change (unless it was incorrect on
Google's end and they've fixed it), `HWaaS` has the `Squid` HTTP proxy sat
between it and the Translate API to cache requests (varied by language).
