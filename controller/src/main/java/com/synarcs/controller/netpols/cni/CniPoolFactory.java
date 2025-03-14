package com.synarcs.controller.netpols.cni;


public class CniPoolFactory {
    
    public static FilterPolicies GenerateL3Netpool(String cniName) {
        // catch when cni pool generation invoked from service 
        switch (cniName) {
            case "cilium":
                return new CiliumNetworkPolicy();
            case "calico":
                return new CalicoNetworkPolicy();
            default:
                return new LegacyNetworkPolicy();
        }
    }


    public static FilterPolicies GenerateL7Netpool(String cniName) {
        // catch when cni pool generation invoked from service 
        switch (cniName) {
            case "cilium":
                return new CiliumNetworkPolicy();
            case "calico":
                return new CalicoNetworkPolicy();
            default:
                return new LegacyNetworkPolicy();
        }
    }
}
