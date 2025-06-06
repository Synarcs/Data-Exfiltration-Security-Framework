/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package com.synarcs.controller.protocols;

public interface IFeatureTransportProtocol {
    public String GetExfilProtocolBaseType();
    public Integer GetProtocolDefaultPort();
    public Integer GetProtocolCustomExfiltratedPort();
    public Object GetDnsFeatures();
}