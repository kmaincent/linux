.. SPDX-License-Identifier: GPL-2.0

============
Devlink Conf
============

The ``devlink-conf`` API allows saving the device configuration as
permanent writing it to a non-volatile memory.

Drivers are expected to implement ``devlink-conf`` functionality through
``conf_save`` and ``conf_reset`` devlink operations.

example usage
-------------

.. code:: shell

    $ devlink dev conf help
    $ devlink dev conf DEV [ save | reset ]

    # Run conf command for saving configuration to non-volatile memory:
    $ devlink dev conf i2c/1-003c save
