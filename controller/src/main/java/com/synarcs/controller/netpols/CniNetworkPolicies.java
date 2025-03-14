package com.synarcs.controller.netpols;

import java.io.Serializable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;

import com.synarcs.controller.config.yaml.Config;
import com.synarcs.controller.netpols.cni.CniPoolFactory;
import com.synarcs.controller.netpols.cni.FilterPolicies;

public class CniNetworkPolicies implements Serializable{
 
    private Config controllerConfig;
    private Logger logger = LoggerFactory.getLogger(CniNetworkPolicies.class);
    
    @Autowired
    public CniNetworkPolicies(Config config) {
        this.controllerConfig = config;
    }

    @Bean
    public void generalteL3Pools() {
        if (controllerConfig.getK8s().isEnabled()) {
            FilterPolicies l3Nwpolicy = CniPoolFactory.GenerateL3Netpool(controllerConfig.getK8s().getCni().getName());
            try {
                l3Nwpolicy.addL3FilterPolicies();
                logger.info("created network policy over k8s for cni to filter malicious l3 traffic to c2 servers");
            }catch (Exception exception) {
                logger.error("Error creating l3 netpool for CNI " + controllerConfig.getK8s().getCni().getName() +
                        " over controller host " + controllerConfig.getK8s().getK8sAdvertisedHostServiceAddress(), exception);
            }
        }else {
            logger.info("please reboot controller, make sure controller is booted with CNI dynamic netpool configuration");
        }
    }


    @Bean
    public void generalteL7Pools() {
        if (controllerConfig.getK8s().isEnabled()) {
            FilterPolicies l3Nwpolicy = CniPoolFactory.GenerateL3Netpool(controllerConfig.getK8s().getCni().getName());
            try {
                l3Nwpolicy.addL7FilterPolicies();
                logger.info("created network policy over k8s for cni to filter malicious l7 traffic to c2 servers");
            }catch (Exception exception) {
                logger.error("Error creating l7 netpool for CNI " + controllerConfig.getK8s().getCni().getName() +
                        " over controller host " + controllerConfig.getK8s().getK8sAdvertisedHostServiceAddress(), exception);
            }
        }else {
            logger.info("please reboot controller, make sure controller is booted with CNI dynamic netpool configuration");
        }
    }

}
