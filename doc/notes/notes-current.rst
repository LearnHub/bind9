.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

Notes for BIND 9.18.5
---------------------

Security Fixes
~~~~~~~~~~~~~~

- None.

Known Issues
~~~~~~~~~~~~

- None.

New Features
~~~~~~~~~~~~

- None.

Removed Features
~~~~~~~~~~~~~~~~

- None.

Feature Changes
~~~~~~~~~~~~~~~

- The :option:`dnssec-signzone -H` default value has been changed to 0 additional
  NSEC3 iterations. This change aligns the :iscman:`dnssec-signzone` default with
  the default used by the :ref:`dnssec-policy <dnssec_policy_grammar>` feature.
  At the same time, documentation about NSEC3 has been aligned with
  `Best Current Practice
  <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-nsec3-guidance-10>`__.
  :gl:`#3395`

Bug Fixes
~~~~~~~~~

- It was possible for a catalog zone consumer to process a catalog zone member
  zone when there was a configured pre-existing forward-only forward zone with
  the same name. This has been fixed. :gl:`#2506`.

- Fix the assertion failure caused by TCP connection closing between the
  connect (or accept) and the read from the socket. :gl:`#3400`
