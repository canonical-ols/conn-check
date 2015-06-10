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
you need to implement the ``conn-check-relation-changed`` hook, e.g.:

.. code-block:: bash

    #!/bin/bash
    set -e
    CONFIG_PATH=/var/conn-check.yaml

    juju-log "Writing conn-check config to ${CONFIG_PATH}"
    /path/to/hwaas/settings-to-conn-check.py -f ${CONFIG_PATH} -m hwaas.settings

    # Ensure conn-check and nagios can both access the config file
    chown conn-check:nagios ${CONFIG_PATH}
    chmod 0660 ${CONFIG_PATH}
    
    # Set the config path, we could also tell the conn-check charm
    # to write the config file for us by setting the "config" option
    # but this is deprecated in favour of writing the file ourselves
    # and setting "config_path"
    relation-set config_path="${CONFIG_PATH}"

You may note that we set the user to ``conn-check`` and the group to ``nagios``,
you can actually get away with just setting the group to ``nagios`` as this
will give both conn-check and nagios access to the config file, but you might
as well set the user anyway otherwise it's likely to be ``root``.

You'll also need to tell Juju your charm provides the ``conn-check`` relation
in your ``metadata.yaml``:

.. code-block:: yaml

    provides:
        conn-check:
            interface: conn-check
            scope: container

When deploying conn-check with your service you then deploy the subordinate,
relate it to your service, and optionally set it as a :ref:`nagios` provider.


.. _nagios:

Nagios
------


Actions
-------


