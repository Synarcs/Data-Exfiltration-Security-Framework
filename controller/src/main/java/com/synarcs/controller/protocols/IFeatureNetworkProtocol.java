/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package com.synarcs.controller.protocols;

public interface IFeatureNetworkProtocol {
    public String GetProtocolName();
    public Integer GetProtocolCustomExfiltratedL3Ip();
    public Object GetDnsFeatures();
}
