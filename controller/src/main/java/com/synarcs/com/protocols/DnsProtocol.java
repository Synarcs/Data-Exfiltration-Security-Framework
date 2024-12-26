package com.synarcs.com.protocols;

import java.io.Serializable;


public class DnsProtocol implements Serializable, IFeatureTransportProtocol {
    private Integer ExfilPort = 53;
    private final String ProtocolName = "DNS"; 
    private DnsFeatures features;

    public DnsProtocol(int customPort, DnsFeatures features) {
        this.ExfilPort = customPort;
        this.features = features; 
    }

    public String GetProtocolName(){
        return ProtocolName;
    }
    
    public Integer GetProtocolDefaultPort() {
        return ExfilPort;
    }

    public DnsFeatures getDnsFeatures() {
        return features;
    }
    
    public Integer GetProtocolCustomExfiltratedPort() {
        return ExfilPort;
    }
}
