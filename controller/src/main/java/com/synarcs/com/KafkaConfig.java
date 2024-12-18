package com.synarcs.com;

import java.io.Serializable;

public class KafkaConfig implements Serializable {

    private String BrokerUrlIpv4;

    private int BrokerPort;

    private String KafkaTOpic;


    public String getBrokerUrl() { return BrokerUrlIpv4; }

    public int getBrokerPort() { return BrokerPort; } 

    public String getKafkaTopic() { return KafkaTOpic; } 
}
