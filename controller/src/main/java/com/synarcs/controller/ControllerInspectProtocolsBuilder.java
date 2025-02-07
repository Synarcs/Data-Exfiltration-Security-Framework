package com.synarcs.controller;

import com.synarcs.controller.protocols.DnsProtocol;
import com.synarcs.controller.protocols.IFeatureTransportProtocol;
import com.synarcs.controller.streamserdes.DnsFeatures;

public class ControllerInspectProtocolsBuilder {

    public ControllerInspectProtocolsBuilder() {
        super();
    }

    // use for l4 protocol family builder for all protocols in it 
    public IFeatureTransportProtocol GetProtocolFeatures(String protocol, Integer port) {
        switch (protocol) {
            case "DNS": 
                return new DnsProtocol(port, new DnsFeatures());
        }
        throw new IllegalArgumentException("Invalid protocol"); 
    }
}
