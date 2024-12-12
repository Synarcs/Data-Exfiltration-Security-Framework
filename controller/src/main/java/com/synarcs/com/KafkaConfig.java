package com.synarcs.com;

public class KafkaConfig {

    private String BrokerUrlIpv4;

    private int BrokerPort;

    private String KafkaTOpic;


    public String getBrokerUrl() { return BrokerUrlIpv4; }

    public int getBrokerPort() { return BrokerPort; } 

    public String getKafkaTopic() { return KafkaTOpic; } 
}
