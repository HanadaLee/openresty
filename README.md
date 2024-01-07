Name
====

OpenResty - Turning Nginx into a Full-Fledged Scriptable Web Platform

Table of Contents
=================

- [Name](#name)
- [Table of Contents](#table-of-contents)
- [Description](#description)
  - [For Users](#for-users)
  - [For Bundle Maintainers](#for-bundle-maintainers)
- [Additional Features](#additional-features)
  - [resolv.conf parsing](#resolvconf-parsing)
- [Mailing List](#mailing-list)
- [Report Bugs](#report-bugs)
- [Copyright \& License](#copyright--license)

Description
===========

OpenResty is a full-fledged web application server by bundling the standard nginx core,
lots of 3rd-party nginx modules, as well as most of their external dependencies.

This bundle is maintained by Yichun Zhang (agentzh).

Because most of the nginx modules are developed by the bundle maintainers, it can ensure
that all these modules are played well together.

The bundled software components are copyrighted by the respective copyright holders.

The homepage for this project is on [openresty.org](https://openresty.org/).

For Users
---------

Visit the [download page](https://openresty.org/en/download.html) on the `openresty.org` web site
to download the latest bundle tarball, and
follow the installation instructions in the [installation page](https://openresty.org/en/installation.html).

For Bundle Maintainers
----------------------

The bundle's source is at the following git repository:

https://github.com/openresty/openresty

To reproduce the bundle tarball, just do

```bash
make
```

at the top of the bundle source tree.

Please note that you may need to install some extra dependencies, like `perl`, `dos2unix`, and `mercurial`.
On Fedora 22, for example, installing the dependencies
is as simple as running the following commands:

```bash
sudo dnf install perl dos2unix mercurial
```

[Back to TOC](#table-of-contents)

Additional Features
===================

In additional to the standard nginx core features, this bundle also supports the following:

[Back to TOC](#table-of-contents)

resolv.conf parsing
--------------------

**syntax:** *resolver address ... [valid=time] [ipv6=on|off] [local=on|off|path]*

**default:** *-*

**context:** *http, stream, server, location*

Similar to the [`resolver` directive](https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver)
in standard nginx core with additional support for parsing additional resolvers from the `resolv.conf` file
format.

When `local=on`, the standard path of `/etc/resolv.conf` will be used. You may also specify arbitrary
path to be used for parsing, for example: `local=/tmp/test.conf`.

When `local=off`, parsing will be disabled (this is the default).

This feature is not available on Windows platforms.

[Back to TOC](#table-of-contents)

Mailing List
============

You're very welcome to join the English OpenResty mailing list hosted on Google Groups:

https://groups.google.com/group/openresty-en

The Chinese mailing list is here:

https://groups.google.com/group/openresty

[Back to TOC](#table-of-contents)

Report Bugs
===========

You're very welcome to report issues on GitHub:

https://github.com/openresty/openresty/issues

[Back to TOC](#table-of-contents)

