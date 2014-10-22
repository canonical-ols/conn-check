conn-check
==========

conn-check allows for checking connectivity with external services.

You can write a config file that defines services that you need to
have access to, and conn-check will check connectivity with each.

It supports various types of services, all of which allow for
basic network checks, but some allow for confirming credentials
work also.

Configuration
-------------

The configuration is done via a yaml file. The file defines a list
of checks to do::

    - type: tcp
      host: localhost
      port: 80
    - type: ssl
      host: localhost
      port: 443
      verify: true

Each check defines a type, and then options as appropriate for that type.

Check Types
-----------

tcp
```

A simple tcp connectivity check.

host
    The host.

port
    The port.


ssl
```

A check that uses SSL.

host
    The host.

port
    The port.

verify
    Optional flag whether to also verify the SSL certificate. Default: true.


udp
```

Check that sending a specific UDP packet gets a specific response.

host
    The host.

port
    The port.

send
    The string to send.

expect
    The string to expect in the response.


http
````

Check that a HTTP/HTTPS request succeeds.

url
    The URL to fetch.

method
    Optional HTTP method to use. Default: "GET".

expected_code
    Optional status code that defines success. Default: 200.

proxy_host
    Optional HTTP proxy to connect via.

proxy_port
    Optional port to use with ``proxy_host``. Default: 8000.

https_proxy_host
    Optional HTTPS proxy to connect via, if not set uses ``proxy_host``.

https_proxy_port
    Optional port to use with ``https_proxy_host``. Default: 8000.

headers:
    Optional headers to send, as a dict of key-values. Multiple values can be
    given as a list under the same key.

body:
    Optional raw request body string to send.

disable_ssl_verification:
    Optional flag to disable verification of SSL certs and handshake. Default:
    false.


amqp
````

Check that an AMQP server can be authenticated against.

host
    The host.

port
    The port.

username
    The username to authenticate with.

password
    The password to authenticate with.

use_ssl
    Optional flag whether to connect with ssl. Default: true.

vhost
    Optional vhost name to connect to. Default '/'.


postgres
````````

Check that a postgres db can be authenticated against.

host
    The host.

port
    The port.

username
    The username to authenticate with.

password
    The password to authenticate with.

database
    The database to connect to.


redis
`````

Check that a redis server is present, optionally checking authentication.

host
    The host.

port
    The port.

password
    Optional password to authenticatie with.


memcached
`````````

Check that a memcached server is present (`memcache` also works).

host
    The host.

port
    The port.


Building wheels
---------------

To allow for easier/more portable distribution of this tool you can build
conn-check and all it's dependencies as `Python wheels <http://legacy.python.org/dev/peps/pep-0427/>`_::

    make clean-wheels
    make build-wheels
    make build-wheels-extra EXTRA=amqp
    make build-wheels-extra EXTRA=redis

The `build-wheels` make target will build conn-check and it's base
dependencies, but to include the optional extra dependencies for other
checks such as amqp, redis or postgres you need to use the
`build-wheels-extra` target with the `EXTRA` env value.

By default all the wheels will be placed in `./wheels`.


Automatically generating conn-check YAML configurations
-------------------------------------------------------

The `conn-check-configs <https://pypi.python.org/pypi/conn-check-configs>`_ package contains utilities/libraries
for generating checks from existing application configurations and environments, e.g. from Django settings modules
and Juju environments.
