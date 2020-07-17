
.. _porting_2.11_guide:

**************************
Ansible 2.11 Porting Guide
**************************

This section discusses the behavioral changes between Ansible 2.10 and Ansible 2.11.

It is intended to assist in updating your playbooks, plugins and other parts of your Ansible infrastructure so they will work with this version of Ansible.

We suggest you read this page along with `Ansible Changelog for 2.11 <https://github.com/ansible/ansible/blob/devel/changelogs/CHANGELOG-v2.11.rst>`_ to understand what updates you may need to make.

This document is part of a collection on porting. The complete list of porting guides can be found at :ref:`porting guides <porting_guides>`.

.. contents:: Topics


Playbook
========

No notable changes


Command Line
============

No notable changes


Deprecated
==========

No notable changes


Modules
=======

Change to default file permissions
----------------------------------

To address `CVE-2020-1736<https://access.redhat.com/security/cve/cve-2020-1736>`_, the default permissions for files created by Ansible using ``atomic_move()`` changed from ``0o666`` to ``0o600``.

The old behavior applied ``0o666`` permissions to temporary files before they were moved into place. If a file existed when the new temporary file was moved into place, Ansible used the permissions of the existing file. If there was no existing file, Ansible retained the default file permissions, combined with the system ``umask``, of the temporary file. If the module that called ``atomic_move()`` also called ``set_fs_attributes_if_different()`` or ``set_mode_if_different()``, Ansible set the permissions of the file to the mode specified in the task.

To make you aware of the new default permissions, Ansible 2.11 warns: ``File <filename> created with default permissions <permissions>. The previous default was '666'. Specify 'mode' to avoid this warning.`` when all of the following conditions are true:

    - The file at the final destination (not the temporary file) does not exist
    - A module supports setting ``mode`` but you did not specify it for the task
    - The module calls ``atomic_move()`` without later calling ``set_fs_attributes_if_different()`` or ``set_mode_if_different()``

If a module calls ``atomic_move()`` without later calling ``set_fs_attributes_if_different()``  or ``set_mode_if_different()``, but does not support setting ``mode``, Ansible does not display the warning, because you cannot set ``mode`` to remove the warning. For files these modules create, the default permissions have changed. These modules are:

    - M(ansible.builtin.known_hosts)
    - M(ansible.builtin.service)
    - Collections modules
      - M(ansible.posix.authorized_key)
      - M(community.general.interfaces_file)
      - M(community.general.pam_limits)
      - M(community.general.pamd)
      - M(community.general.redhat_subscription)
      - M(ansible.posix.selinux)
      - M(ansible.posix.sysctl)

Review each module below to understand what permissions it applies, both to temporary files and when those files are moved into place.

known_hosts
^^^^^^^^^^^

The M(ansible.builtin.known_hosts) module uses ``atomic_move()`` to operate on the ``known_hosts`` file specified by the ``path`` parameter in the module. It uses ``tempfile.NamedTemporaryFile()`` to create a temporary file that is readable and writable only by the creating user ID.

service
^^^^^^^

The M(ansible.builtin.service) module uses ``atomic_move()`` to operate on the default rc file, which is the first found of ``/etc/rc.conf``,  ``/etc/rc.conf.local``, and ``/usr/local/etc/rc.conf``. These files almost always exist on the target system, so the module uses the permissions of the existing file.

**The following modules were included in Ansible <= 2.9. They have moved to collections but are documented here for completeness.**

authorized_key
^^^^^^^^^^^^^^

The M(ansible.posix.authorized_key) module uses ``atomic_move()`` to operate on the the ``authorized_key`` file. It uses ``tempfile.mkstemp()`` to create a temporary file that is readable and writable only by the creating user ID. The module manages the permissions of the the ``.ssh`` directory and ``authorized_keys`` files if ``managed_dirs`` is set to ``True``, which is the default. The module sets the ``ssh`` directory owner and group to the ``uid`` and ``gid`` of the user specified in the ``user`` parameter and directory permissions to ``700``. The module sets the ``authorized_key`` file owner and group to the ``uid`` and ``gid`` of the user specified in the ``user`` parameter and file permissions to ``600``. These values cannot be controlled by module parameters.

interfaces_file
^^^^^^^^^^^^^^^
The M(community.general.interfaces_file) module uses ``atomic_move()`` to operate on ``/etc/network/serivces`` or the ``dest`` specified by the module. It uses ``tempfile.mkstemp()`` to create a temporary file that is readable and writable only by the creating user ID. If the file specified by ``path`` does not exist, the module retains the permissions of the temporary file when it moves the file into place.

pam_limits
^^^^^^^^^^

The M(community.general.pam_limits) module uses ``atomic_move()`` to operate on ``/etc/security/limits.conf`` or the value of ``dest``. It uses ``tempfile.NamedTemporaryFile()`` to create a temporary file that is readable and writable only by the creating user ID. If the file specified by ``dest`` does not exist, the module retains the permissions of the temporary file when it moves the file into place.

pamd
^^^^

The M(community.general.pamd) module uses ``atomic_move()`` to operate on a file in ``/etc/pam.d``. The path and the file can be specified by setting the ``path`` and ``name`` parameters. It uses ``tempfile.NamedTemporaryFile()`` to create a temporary file that is only readable and writable by the creating user ID. If the file specified by ``[dest]/[name]`` does not exist, the module retains the permissions of the temporary file when it moves the file into place.

redhat_subscription
^^^^^^^^^^^^^^^^^^^

The M(community.general.redhat_subscription) module uses ``atomic_move()`` to operate on ``/etc/yum/pluginconf.d/rhnplugin.conf`` and ``/etc/yum/pluginconf.d/subscription-manager.conf``. It uses ``tempfile.mkstemp()`` to create a temporary file that is readable and writable only by the creating user ID. The temporary file inherits the permissions of the existing file when it is moved in to place.

selinux
^^^^^^^

The M(ansible.posix.selinux) module uses ``atomic_move()`` to operate on ``/etc/selinux/config`` on the value specified by ``configfile``. The module will fail if ``configfile`` does not exist before any temporary data is written to disk. It uses ``tempfile.mkstemp()`` to create a temporary file that is readable and writable only by the creating user ID. Since the file specified by ``configfile`` must exist, the temporary file inherits the permissions of that file when it is moved in to place.

sysctl
^^^^^^

The M(ansible.posix.sysctl) module uses ``atomic_move()`` to operate on ``/etc/sysctl.conf`` or the value specified by ``sysctl_file``. The module will fail if ``sysctl_file`` does not exist before any temporary data is written to disk. It uses ``tempfile.mkstemp()`` to create a temporary file that is readable and writable only by the creating user ID. Since the file specified by ``sysctl_file`` must exist, the temporary file will inherit the permissions of that file once it is moved in to place.


* The ``apt_key`` module has explicitly defined ``file`` as mutually exclusive with ``data``, ``keyserver`` and ``url``. They cannot be used together anymore.

Modules removed
---------------

The following modules no longer exist:

* No notable changes


Deprecation notices
-------------------

No notable changes


Noteworthy module changes
-------------------------

* facts - ``ansible_virtualization_type`` now tries to report a more accurate result than ``xen`` when virtualized and not running on Xen.


Plugins
=======

No notable changes


Porting custom scripts
======================

No notable changes


Networking
==========

No notable changes
