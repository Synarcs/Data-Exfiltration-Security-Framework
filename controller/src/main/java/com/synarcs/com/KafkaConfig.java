package com.synarcs.com;

import java.io.Serializable;

public class KafkaConfig implements Serializable {

    private final String BrokerUrlIpv4 = "10.158.82.6";

    private final int BrokerPort =  9092; 
    private final int SchemaRegistryPort = 8081;

    private final String STREAM_THREAT_TOPIC = "exfil-sec";

    private final String STREAM_THREAT_TOPIC_INFER_STATE = "exfil-sec-infer-controller";

    public int getSchemaRegistryPort() { return this.SchemaRegistryPort; }
    
    public String getBrokerUrl() { return BrokerUrlIpv4; }

    public int getBrokerPort() { return BrokerPort; } 

    public String getKafkaInputStreamTopic() { return STREAM_THREAT_TOPIC; } 

    public String getKafkaInputStreamInferTopic() { return STREAM_THREAT_TOPIC_INFER_STATE; } 
}
