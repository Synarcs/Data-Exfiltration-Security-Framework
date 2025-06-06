/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package com.synarcs.controller.protocols;

public interface IFeatureNetworkProtocol {
    public String GetProtocolName();
    public Integer GetProtocolCustomExfiltratedL3Ip();
    public Object GetDnsFeatures();
}
