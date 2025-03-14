package com.synarcs.controller.netpols.cni;


// relies on l3 netpool for filter over iptables or ipvs based on cni support

public class LegacyNetworkPolicy implements FilterPolicies {
    
    public void addL7FilterPolicies() {
        // add legacy l7 filter policies
    }

    public void addL3FilterPolicies() {
        // add legacy l3 filter policies
    }
}
