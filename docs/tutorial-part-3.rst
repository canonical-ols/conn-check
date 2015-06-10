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
relate it to your service (you can aslo optionally set it as a :ref:`nagios`
provider):

.. code-block:: sh

    $ juju deploy cs:~ubuntuone-hackers/trusty/conn-check-31 my-service-conn-check
    $ juju set my-service-conn-check revision=108 # pin to the rev of conn-check you want to use
    $ juju add-relation my-service my-service-conn-check


.. _nagios:

Nagios
------

The conn-check charm provides the ``nrpe-external-master`` relation which
means it can act as a Nagios plugin executor, meaning if you have a Nagios
master in your environment for monitoring then conn-check can be regularly
run along with your other monitoring checks to ensure your environments
connections are as you expect them to be.

To set this up you need to relate the deployed subordinate to your servie nrpe:

.. code-block:: sh

    $ # assuming something like:
    $ # juju deploy nagios nagios-master
    $ # juju deploy nrpe my-service-nrpe
    $ # juju add-relation my-service:monitors my-service-nrpe:monitors
    $ juju add-relation my-service-conn-check my-service-nrpe

For more details on Juju and Nagios you can see
`this handy blog post <https://maas.ubuntu.com/2012/08/07/juju-and-nagios-sittin-in-a-tree-part-1>`_.

Actions
-------

To manually run conn-check on all units, or a single unit, you can use the
supplied ``run-check`` and ``run-nagios-check`` actions:

.. code-block:: sh

    $ # all checks on all units
    $ juju run --service my-service-conn-check 'actions/run-check'
    $ # all checks on just unit 0
    $ juju run --service my-service-conn-check/0 'actions/run-check'
    $ # nagios (not including no-nagios) checks on all units
    $ juju run --service my-service-conn-check 'actions/run-nagios-check'
    $ # nagios (not including no-nagios) checks on just unit 0
    $ juju run --service my-service-conn-check/0 'actions/run-nagios-check'

**Note**: before Juju 1.21 there is a
`bug <https://bugs.launchpad.net/juju-core/+bug/1286613>`_ which prevents
juju-run from working with subordinate charms, you can work around this with
juju-ssh:

.. code-block:: sh

    $ # all checks on just unit 0
    $ juju ssh my-service-conn-check/0 'juju-run my-service-conn-check/0 actions/run-check'
