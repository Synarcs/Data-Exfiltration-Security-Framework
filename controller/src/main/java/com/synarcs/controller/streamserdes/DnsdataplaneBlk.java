package com.synarcs.controller.streamserdes;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/*
 * Global blacklist stream serdes used to instrcy al the nodes in the data plane to blacklist and hydrate their local malicious blacklist cache ingress / ingress
 * Ensure kernel eBPF deep scan packets in user space post kernel tc are dropped as these domains are globally hydrated and meant to be blacklisted over the entire data plane.
*/


@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class DnsdataplaneBlk implements Serializable  {

    private String fqdn;
    private String tld;
    private String recordType;
    private boolean isForcedUnBlocked;
    private String detectedThreadNodeIpv4;
    private String detectedThreadNodeIpv6;
}
