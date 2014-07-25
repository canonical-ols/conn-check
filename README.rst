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
    Whether to also verify the SSL certificate. Optional. Default: true.


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

Check that a HTTP request succeeds.

url
    The URL to fetch.

method
    The method to use. Optional. Default: "GET".

expected_code
    The status code that defines success. Optional. Default: 200.


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
    Whether to connect with ssl. Optional. Default: true.

vhost
    The vhost to connect to. Optional. Default '/'.


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
    The password to authenticatie with. Optional.


memcached
`````````

Check that a memcached server is present (`memcache` also works).

host
    The host.

port
    The port.
