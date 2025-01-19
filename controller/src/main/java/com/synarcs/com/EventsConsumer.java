package com.synarcs.com;

import java.io.Serializable;
import java.util.Properties;

public class EventsConsumer implements Serializable {
    private KafkaConfig config;
    private ControllerInspectProtocolsBuilder protocolsBuilder;

    public EventsConsumer (KafkaConfig config) {
        this.config = config;
    }
    
    public void initKafkaConsumer() {
        Properties props = new Properties();
    }

}