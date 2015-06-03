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
