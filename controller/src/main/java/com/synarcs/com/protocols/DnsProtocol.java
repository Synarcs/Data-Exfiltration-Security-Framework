package com.synarcs.com.protocols;

import java.io.Serializable;


public class DnsProtocol implements Serializable, IFeatureTransportProtocol {
    private final Integer DNS_EGRESS_PORT = 53;
    private final Integer DOT_EGRESS_PORT = 853;
    private final Integer DNS_EGRESS_MULTICAST_PORT = 5353;
    private final Integer LLMNR_EGRESS_LOCAL_MULTICAST_PORT = 5355;
    private final Integer NETBIOS_EGRESS_MULTICAST_PORT = 137;
    // 179 for multicast transport over BGP using TCP as transport port 

    private Integer ExfilPort = 53;
    private final String ProtocolName = "DNS"; 
    private DnsFeatures features;

    public DnsProtocol(int customPort, DnsFeatures features) {
        this.ExfilPort = customPort;
        this.features = features; 
    }

    public DnsProtocol(DnsFeatures features) {
        // use the default port for UDP transport if not specified any custom protocol port 
        this.ExfilPort = DNS_EGRESS_PORT;
    }

    public DnsProtocol(DnsFeatures features, ProtocolEnums enums) {
        switch (enums) {
            case DOT_EGRESS: 
                this.ExfilPort = DOT_EGRESS_PORT;
                break;
            case DNS_EGRESS_MULTICAST:
                this.ExfilPort = DNS_EGRESS_MULTICAST_PORT;
                break;
            case DNS_LLMNR_EGRESS:
                this.ExfilPort = LLMNR_EGRESS_LOCAL_MULTICAST_PORT;
                break;
            case DNS_NETBIOS_EGRESS:
                this.ExfilPort = NETBIOS_EGRESS_MULTICAST_PORT;
                break;
            default:
                throw new Error("Error Please provide a supported protocol for controller to stream analytics over threat events ...");
        }
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
