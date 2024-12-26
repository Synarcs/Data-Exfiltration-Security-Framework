package com.synarcs.com.protocols;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class DnsFeatures {

    private String AuthZoneSoaservers;
    private Integer AverageLabelLength;
    private Double Entropy;
    private Integer ExfilPort;
    private String Fqdn;
    private Boolean IsEgress;
    private Integer LongestLabelDomain;
}
