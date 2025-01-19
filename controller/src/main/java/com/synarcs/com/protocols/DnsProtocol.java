package com.synarcs.com.protocols;

import java.io.Serializable;
import java.util.TreeSet;


public class DnsProtocol implements Serializable, IFeatureTransportProtocol {

    // 179 for multicast transport over BGP using TCP as transport port 

    private Integer ExfilPort = 53;
    private final String ExfilProtocolRootType = "DNS"; 
    private DnsFeatures features;
    private ProtocolEnums ExfilProtocolInternalType;

    public DnsProtocol(int customPort, DnsFeatures features) {
        this.ExfilPort = customPort;
        this.features = features; 
    }

    /*
     * The base proptocol in the feature resemble the root protocol the framework is build on 
     *  For example, DNS, ICMP etc with each of them having more nested types of exfiltration detected from kernel and ebPF node agent
     *  Configure the base exfil type followed witht the internal type as an extension used to exnfiltrate data from base type  
     *      For example, DNS exfiltration is base type LLMNR, MDNS, DNS, NETBIOS etc as other nested types of exfil
     */
    public DnsProtocol(DnsFeatures features) {
        switch (features.ExfilPort) {
            case 53: 
                this.ExfilPort = DnsExfilPorts.DOT_EGRESS_PORT;
                this.ExfilProtocolInternalType = ProtocolEnums.DNS_EGRESS;
                break;
            case 5353:
                this.ExfilPort = DnsExfilPorts.DNS_EGRESS_MULTICAST_PORT;
                this.ExfilProtocolInternalType = ProtocolEnums.DNS_MULTICAST_EGRESS;
                break;
            case 5355:
                this.ExfilPort = DnsExfilPorts.LLMNR_EGRESS_LOCAL_MULTICAST_PORT;
                this.ExfilProtocolInternalType = ProtocolEnums.DNS_MULTICAST_EGRESS;
                break;
            case 137:
                this.ExfilPort = DnsExfilPorts.NETBIOS_EGRESS_MULTICAST_PORT;
                this.ExfilProtocolInternalType = ProtocolEnums.DNS_NETBIOS_EGRESS;
                break;
            default:
                this.ExfilPort = features.ExfilPort;
                this.ExfilProtocolInternalType = ProtocolEnums.DNS_OVERLAY_ENCAP_EGRESS;
                break;
        }
        this.features = features;
    }

    public String GetExfilProtocolBaseType(){
        return ExfilProtocolRootType;
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

    @SuppressWarnings("unused")
    public void test() {
    }
}
