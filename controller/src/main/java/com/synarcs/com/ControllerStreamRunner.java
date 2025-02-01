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

import com.synarcs.com.config.ControllerConfigLoader;
import com.synarcs.com.config.KafkaConfig;
import com.synarcs.com.config.yaml.Config;
import com.synarcs.com.protocols.DnsFeatures;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import com.fasterxml.jackson.databind.ObjectMapper;


public class ControllerStreamRunner implements Serializable, IController, Runnable {
    private KafkaConfig config;
    private Config controllerConfig;
    private ControllerInspectProtocolsBuilder protocolsBuilder;

    public ControllerStreamRunner(KafkaConfig config) {
        super();
        this.config = config;
    }

    public ControllerStreamRunner() {
        try {
            this.controllerConfig = new ControllerConfigLoader().loadControllerConfig();
            this.config = KafkaConfig.builder()
                    .BrokerPort(this.controllerConfig.getStreamConfig().getBrokerPort())
                    .BrokerUrlIpv4(this.controllerConfig.getStreamConfig().getHost())
                    .SchemaRegistryPort(this.controllerConfig.getStreamConfig().getSchemaRegistry().getPort())
                    .STREAM_THREAT_TOPIC(this.controllerConfig.getStreamConfig().getStreamThreatTopic())
                    .STREAM_THREAT_TOPIC_INFER_STATE(this.controllerConfig.getStreamConfig().getStreamThreatTopicInferState())
                    .consumerGroupName(this.controllerConfig.getStreamConfig().getConsumerGroupName())
                    .build();
            this.protocolsBuilder = new ControllerInspectProtocolsBuilder(); 
        }catch (IOException exception) {
            exception.printStackTrace();
        }
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
        props.put(StreamsConfig.APPLICATION_ID_CONFIG, this.config.getConsumerGroupName()); // use app ID same as consumer config  or group name 
        props.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, this.config.getBrokerUrlIpv4()+":"+this.config.getBrokerPort());
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(StreamsConfig.COMMIT_INTERVAL_MS_CONFIG, 10000);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, true);
        props.put(StreamsConfig.TOPOLOGY_OPTIMIZATION_CONFIG, StreamsConfig.OPTIMIZE);
        props.put(StreamsConfig.REPLICATION_FACTOR_CONFIG, 1);
        props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, 300000);
        props.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 600000);
        props.put(StreamsConfig.consumerPrefix(ConsumerConfig.METADATA_MAX_AGE_CONFIG), "1000");


        props.put(StreamsConfig.CLIENT_ID_CONFIG, this.config.getConsumerGroupName());
        StreamsBuilder builder = new StreamsBuilder();
        ObjectMapper objectMapper = new ObjectMapper();

        builder.stream(config.getSTREAM_THREAT_TOPIC(), 
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
        System.out.println("Connected to topic: " + config.getSTREAM_THREAT_TOPIC());
        System.out.println("Connected to broker: " + config.getBrokerUrlIpv4() + ":" + config.getBrokerPort());
        
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            streams.cleanUp();
        }
    }
}
