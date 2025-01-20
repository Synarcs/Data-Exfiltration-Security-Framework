package com.synarcs.com;

import java.io.Serializable;
import java.time.Duration;
import java.util.Arrays;
import java.util.Properties;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.synarcs.com.cache.NodeCache;
import com.synarcs.com.protocols.DnsFeatures;
import com.synarcs.com.protocols.DnsProtocol;
import com.synarcs.com.protocols.ProtocolEnums;

import io.confluent.kafka.serializers.KafkaJsonDeserializer;
import io.confluent.kafka.serializers.KafkaJsonDeserializerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class EventsConsumer implements Serializable, Runnable {
    private KafkaConfig config;
    private ControllerInspectProtocolsBuilder protocolsBuilder;
    private Logger log = LoggerFactory.getLogger(EventsConsumer.class);
    private final String threat_event_topic = "exfil-sec";

    public EventsConsumer(KafkaConfig config) {
        super();
        this.config = config;
    }

    @Override
    public void run() {
        this.threadConsumer();
    }

    public EventsConsumer() {
        this(new KafkaConfig());
        this.protocolsBuilder = new ControllerInspectProtocolsBuilder(); 
    }

    
    public Properties initKafkaConsumer() {
        Properties props = new Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, this.config.getBrokerUrl() + ":" + this.config.getBrokerPort());
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG,
            StringDeserializer.class);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "exfil_dns_sec");
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, 
                KafkaJsonDeserializer.class);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put("schema.registry.url", "http://"+this.config.getBrokerUrl() + ":" + this.config.getSchemaRegistryPort());
        props.put(KafkaJsonDeserializerConfig.JSON_VALUE_TYPE, DnsFeatures.class.getName());

        return props;
    }

    /*
     *  Convert the raw features into a java object for represeting the protocol 
     */
    public DnsProtocol getEncapDnsProtocol(DnsFeatures features) {
        return new DnsProtocol(features);
    }

    public void threadConsumer() {
        log.info("Starting the Thread for consuming Threat events from kafka topic " + Thread.currentThread().getName() + " " + threat_event_topic);

        // convert this to LRU cache for faster lookup and eviction from local cache in memory 
        NodeCache<String> cache = new NodeCache<>();
        final KafkaConsumer<String, JsonNode> consumer = new KafkaConsumer<String, JsonNode>(this.initKafkaConsumer());
        consumer.subscribe(Arrays.asList(
            threat_event_topic
        ));
        ObjectMapper mapper = new ObjectMapper(); 
        try {
            while (true) {
                ConsumerRecords<String, JsonNode> records = consumer.poll(Duration.ofMillis(1000));
                for (var record : records) {
                    DnsFeatures dnsFeature= mapper.convertValue(record.value(), new TypeReference<DnsFeatures>(){});
                    getEncapDnsProtocol(dnsFeature);
                    cache.addRecordInCache(
                        dnsFeature.Tld);
                    cache.addExfilProtocolCountPerNode(ProtocolEnums.DNS_EGRESS, dnsFeature.PhysicalNodeIpv4);
                    cache.addSldCountPerNode(dnsFeature.Tld, dnsFeature.PhysicalNodeIpv4);
                    cache.readRecords();
                }
            }
        }finally {
            consumer.close();
        }
    }
}