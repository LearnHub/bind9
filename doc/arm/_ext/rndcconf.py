############################################################################
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
############################################################################

"""
Sphinx domain "rndcconf". See iscconf.py for details.
"""

from docutils import nodes

import iscconf


class ToBeReplacedStatementList(nodes.General, nodes.Element):
    """
    Placeholder, does nothing, but must be picklable
    (= cannot be in a generated class).
    """


def setup(app):
    return iscconf.setup(app, "rndcconf", "rndc.conf", ToBeReplacedStatementList)
