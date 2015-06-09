Tutorial Part 3: Adding conn-check to Juju deployed services
============================================================

Juju
----

`Juju <https://www.jujucharms.com/>`_ is an open source service orientated
framework and deployment toolset from Canonical, given conn-check is also by
Canonical you might expect there is an easy yet flexible way to add conn-check
to your Juju environment.

You'd be right..

Adding conn-check charm support to your apps charm
--------------------------------------------------

The `conn-check charm <https://jujucharms.com/u/ubuntuone-hackers/conn-check/trusty>`_
is a subordinate charm that can be added alongside your applications charm,
and will install/configure conn-check on your application units.

To enable support for the conn-check subordinate in your applications charm
you just need to implement the ``conn-check-relation-changed`` hook, e.g.:

.. code-block:: bash

    #!/bin/bash
    set -e
    CONFIG_PATH=/var/conn-check.yaml

    juju-log "Writing conn-check config to ${CONFIG_PATH}"
    /path/to/hwaas/settings-to-conn-check.py -f $CONFIG_PATH -m hwaas.settings
    
    relation-set config-path="${CONFIG_PATH}"


Nagios
------


Actions
-------


