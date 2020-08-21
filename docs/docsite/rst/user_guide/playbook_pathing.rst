:orphan:

***********************
Search paths in Ansible
***********************

You can control the paths Ansible searches to find resources on your control node (including configuration, modules, roles, ssh keys, and more) as well as resources on the remote nodes you are managing. Use absolute paths to tell Ansible where to find resources whenever you can. However, absolute paths are not always practical. This page covers how Ansible interprets relative search paths. Understanding search paths will help you troubleshoot problems like:

  - your playbook fails because Ansible cannot find a file, task, or role
  - you get an unexpected result because Ansible does not load the variable you wanted
  - changes to your configuration file do not seem to have any effect

.. contents::
   :local:

Config paths
============

If you set a relative path in an ``ansible.cfg`` file, for most configuration options Ansible uses the location of the config file as the base for the relative path. For example, if the configuration file in ``/etc/ansible/ansible.cfg`` sets ``collections_paths = ../my_collections``, Ansible searches for collections in ``/etc/my_collections/``. If a configuration setting is not working as expected, remember that Ansible searches for :ref:`configuration files <ansible_configuration_settings_locations>` in certain locations in a set order. Ansible may be loading a different configuration file from the one you are editing.

If a configuration option sets paths relative to the current working directory or to the playbook directory, the behavior is documented in :ref:`ansible_configuration_settings`. For example, Ansible uses the current working directory as the base for relative paths to ssh keys, because that behavior mirrors how the underlying tools work.

Task paths
==========

If you set a relative path in a task, Ansible uses it in two different scopes: task evaluation and task execution. For task evaluation, all paths are local, like in lookups. For task execution, which usually happens on the remote nodes, local paths do not usually apply. However, if a task uses an action plugin, it uses a local path. The template and copy modules are examples of modules that use action plugins, and therefore use local paths.

Paths for loading resources
===========================

On the control node, Ansible searches multiple paths to load the roles, files, and variables that your plays or playbooks need. Lookup and action plugins use this 'search magic', starting with the directory that contains the playbook itself, then searching the directories that contain roles and other :ref:`re-usable files <playbooks_reuse>` referred to in the playbook.

Using this magic, relative paths get attempted first with a 'files|templates|vars' appended (if not already present), depending on action being taken, 'files' is the default. (i.e include_vars will use vars/).  The paths will be searched from most specific to most general (i.e role before play).
dependent roles WILL be traversed (i.e task is in role2, role2 is a dependency of role1, role2 will be looked at first, then role1, then play).
i.e ::

    role search path is rolename/{files|vars|templates}/, rolename/tasks/.
    play search path is playdir/{files|vars|templates}/, playdir/.

By default, Ansible does not search the current working directory unless it happens to coincide with one of the paths above. If you `include` a task file from a role, it  will NOT trigger role behavior, this only happens when running as a role, `include_role` will work. A new variable `ansible_search_path` var will have the search path used, in order (but without the appended subdirs). Using 5 "v"s (`-vvvvv`) should show the detail of the search as it happens.

As for includes, they try the path of the included file first and fall back to the play/role that includes them.

.. note:  The current working directory (CWD) on remote hosts might vary, depending on which connection plugin you are using and whether the action is local or remote. For remote actions the CWD is normally the directory on which the login shell puts the user. For local actions the CWD is either the directory you executed Ansible from, or the playbook directory.
