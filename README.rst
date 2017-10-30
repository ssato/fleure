=========
fleure
=========

.. image:: https://img.shields.io/travis/ssato/fleure.svg
   :target: https://travis-ci.org/ssato/fleure
   :alt: Test status

.. .. image:: https://img.shields.io/coveralls/ssato/fleure.svg
   :target: https://coveralls.io/r/ssato/fleure
   :alt: [Coverage Status]

.. image:: https://landscape.io/github/ssato/fleure/master/landscape.png
   :target: https://landscape.io/github/ssato/fleure/master
   :alt: [Code Health]

.. image:: https://scrutinizer-ci.com/g/ssato/fleure/badges/quality-score.png?b=master
   :target: https://scrutinizer-ci.com/g/ssato/fleure
   :alt: [Code Quality]

fleure (フルーア) [#]_ , a successor of rk-updateinfo (rpmkit.updateinfo cli),
is a package level static analysis tool for systems running RPM-based linux
distributions such like RHEL (primary target) and Fedora.

fleure loads RPM database files of target hosts, tries to fetch updateinfo data
from yum repos and do some analysis based on these data.

- Home: https://github.com/ssato/fleure
- Author: Satoru SATOH <ssato at redhat.com>
- License: AGPLv3+ and GPLv3+

.. [#] The name 'fleure' is borrowed from the name of a track by my most favorite music duo, Authechre.


Build & Install
==================

Requirements
--------------

- python-anyconfig: https://github.com/ssato/python-anyconfig
- python-anytemplate: https://github.com/ssato/python-anytemplate

::

  ## Example session in Fedora 25+
  # sudo dnf copr enable ssato/python-anyconfig -y
  # sudo dnf install -y python-{anytemplate,anyconfig}

Build
------

Run `python setup.py srpm` and mock dist/SRPMS/<built-srpm>, or
run `python setup.py rpm`.

Install
-----------

- build srpm, rpm w/ mock and install it

.. vim:sw=2:ts=2:et:
