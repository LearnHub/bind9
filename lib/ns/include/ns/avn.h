/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/netmgr.h>
#include <isc/quota.h>
#include <isc/stdtime.h>

#include <dns/db.h>
#include <dns/ecs.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/types.h>

#include <ns/query.h>
#include <ns/types.h>

isc_result_t avn_verify_response(ns_client_t *client, isc_region_t *region);

