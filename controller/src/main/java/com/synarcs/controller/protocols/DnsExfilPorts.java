/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package com.synarcs.controller.protocols;

public class DnsExfilPorts {
    public static final Integer DNS_EGRESS_PORT = 53;
    public static final Integer DOT_EGRESS_PORT = 853;
    public static final Integer DNS_EGRESS_MULTICAST_PORT = 5353;
    public static final Integer LLMNR_EGRESS_LOCAL_MULTICAST_PORT = 5355;
    public static final Integer NETBIOS_EGRESS_MULTICAST_PORT = 137;
}
