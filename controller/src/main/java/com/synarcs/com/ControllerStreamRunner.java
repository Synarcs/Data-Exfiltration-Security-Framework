package com.synarcs.com;

import java.io.Serializable;
import java.util.Properties;
import org.apache.kafka.streams.kstream.*;
import org.apache.kafka.common.serialization.StringDeserializer;


public class ControllerStreamRunner implements Serializable, IController, Runnable {
    private KafkaConfig config;
    private ControllerInspectProtocolsBuilder protocolsBuilder;

    public ControllerStreamRunner() {
        super();
        this.protocolsBuilder = new ControllerInspectProtocolsBuilder(); 
        this.config = new KafkaConfig(); 
    }


    public void initKafkaConnection() {
        Properties props = new Properties();
        props.put("bootstrap.servers", "broker1:9092,broker2:9092");
    }

    public ControllerStreamRunner(KafkaConfig config) {
        super();
        this.config = config;
    }

    public Properties ConfigureBroker() {
        Properties props = new Properties();
        props.put("bootstrap.servers", this.config.getBrokerUrl()+":"+this.config.getBrokerPort());
        props.put("key.deserializer", StringDeserializer.class.getName());
        props.put("value.deserializer", StringDeserializer.class.getName());
        return props;
    }

    @Override 
    public void run() {
        ProcessStreamAnalyticsDSl();
    }
    /**
     * Configure the remote kafka broker for stream analytics over the trheat events streamed by each node agent 
     */
    public void ConfigureKafkaBroker(String brokerUrl, int BrokerPort){
    }

    /**
     * Defines the complete Kafka streams DSL to process Kstream and Ktable for threat stream analytics.
     */
    public void ProcessStreamAnalyticsDSl(){
        Thread current = Thread.currentThread();
        System.out.println("processing the broker stream analytics for the thread " + current.getId() + 
                        current.getName());
    }
}
