package com.synarcs.com;

import java.io.IOException;
import java.io.Serializable;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;

import org.apache.kafka.streams.KafkaStreams;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.StreamsConfig;
import org.apache.kafka.streams.kstream.*;
import org.apache.kafka.common.serialization.Serdes;

import com.synarcs.com.protocols.DnsFeatures;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import com.fasterxml.jackson.databind.ObjectMapper;


public class ControllerStreamRunner implements Serializable, IController, Runnable {
    private KafkaConfig config;
    private ControllerInspectProtocolsBuilder protocolsBuilder;

    public ControllerStreamRunner(KafkaConfig config) {
        super();
        this.config = config;
    }

    public ControllerStreamRunner() {
        this(new KafkaConfig());
        this.protocolsBuilder = new ControllerInspectProtocolsBuilder(); 
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
        final Properties props = new Properties();
        props.put(StreamsConfig.APPLICATION_ID_CONFIG, "dns_exfil-security");
        props.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, this.config.getBrokerUrl()+":"+this.config.getBrokerPort());
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(StreamsConfig.COMMIT_INTERVAL_MS_CONFIG, 10000);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true);
        props.put(StreamsConfig.TOPOLOGY_OPTIMIZATION_CONFIG, StreamsConfig.OPTIMIZE);
        props.put(StreamsConfig.REPLICATION_FACTOR_CONFIG, 1);
        props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, 300000);
        props.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 600000);
        props.put(StreamsConfig.consumerPrefix(ConsumerConfig.METADATA_MAX_AGE_CONFIG), "1000");


        props.put(StreamsConfig.CLIENT_ID_CONFIG, "dns_exfil-security");
        StreamsBuilder builder = new StreamsBuilder();
        ObjectMapper objectMapper = new ObjectMapper();

        builder.stream(config.getKafkaInputStreamTopic(), 
            Consumed.with(Serdes.String(), Serdes.ByteArray()))
            .<DnsFeatures>mapValues(bytes -> {
                try {
                    return objectMapper.readValue(bytes, DnsFeatures.class);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            })
        .foreach((key, value) -> {
            System.out.println("DNS Features: " + value);
        });

        KafkaStreams streams = new KafkaStreams(builder.build(), props);

        streams.setStateListener((newState, oldState) -> {
            System.out.println("Stream state changed from " + oldState + " to " + newState);
        });

        streams.start();
        System.out.println("Connected to topic: " + config.getKafkaInputStreamTopic());
        System.out.println("Connected to broker: " + config.getBrokerUrl() + ":" + config.getBrokerPort());
        
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            streams.cleanUp();
        }
    }
}
