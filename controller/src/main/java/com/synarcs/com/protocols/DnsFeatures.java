package com.synarcs.com.protocols;

import com.fasterxml.jackson.annotation.JsonProperty;

public class DnsFeatures {

    @JsonProperty
    public String AuthZoneSoaservers;

    @JsonProperty
    public Integer AverageLabelLength;
    
    @JsonProperty
    public Double Entropy;

    @JsonProperty
    public Integer ExfilPort;

    @JsonProperty
    public String Fqdn;

    @JsonProperty
    public Boolean IsEgress;

    @JsonProperty
    public Integer LongestLabelDomain;

    @JsonProperty
    public Integer NumberCount;

    @JsonProperty
    public Integer Periods;

    @JsonProperty
    public Integer PeriodsInSubDomain;

    @JsonProperty
    public String PhysicalNodeIpv4;

    @JsonProperty
    public String PhysicalNodeIpv6;

    @JsonProperty
    public String Protocol;

    @JsonProperty
    public String RecordType;

    @JsonProperty
    public String Subdomain;

    @JsonProperty
    public String Tld;

    @JsonProperty
    public Integer TotalChars;

    @JsonProperty
    public Integer TotalCharsInSubdomain;

    @JsonProperty
    public Integer UCaseCount;

    @Override
    public String toString() {
        return "DnsFeatures{" +
                "AuthZoneSoaservers='" + AuthZoneSoaservers + '\'' +
                ", AverageLabelLength=" + AverageLabelLength +
                ", Entropy=" + Entropy +
                ", ExfilPort=" + ExfilPort +
                ", Fqdn='" + Fqdn + '\'' +
                ", IsEgress=" + IsEgress +
                ", LongestLabelDomain=" + LongestLabelDomain +
                ", NumberCount=" + NumberCount +
                ", Periods=" + Periods +
                ", PeriodsInSubDomain=" + PeriodsInSubDomain +
                ", PhysicalNodeIpv4='" + PhysicalNodeIpv4 + '\'' +
                ", PhysicalNodeIpv6='" + PhysicalNodeIpv6 + '\'' +
                ", Protocol='" + Protocol + '\'' +
                ", RecordType='" + RecordType + '\'' +
                ", Subdomain='" + Subdomain + '\'' +
                ", Tld='" + Tld + '\'' +
                ", TotalChars=" + TotalChars +
                ", TotalCharsInSubdomain=" + TotalCharsInSubdomain +
                ", UCaseCount=" + UCaseCount +
                '}';
    }
}